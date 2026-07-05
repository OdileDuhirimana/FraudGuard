import secrets
from datetime import datetime
from typing import Any, Optional

import networkx as nx
from fastapi import APIRouter, BackgroundTasks, Depends, Query
from networkx.readwrite import json_graph
from sqlalchemy.orm import Session

from .. import models
from ..auth import get_current_user, require_role
from ..database import get_db, get_session_factory
from ..errors import BadRequestError, ForbiddenError, NotFoundError
from ..logging_config import get_logger
from ..ml.ensemble import ensemble_features
from ..models import TRANSACTION_DECISIONS
from ..pagination import Page, PageParams
from ..repositories import (
    AlertRepository,
    GraphJobRepository,
    OTPChallengeRepository,
    TransactionRepository,
    get_alert_repository,
    get_graph_job_repository,
    get_otp_challenge_repository,
    get_transaction_repository,
)
from ..risk import compute_risk_score
from ..schemas import (
    AlertOut,
    BehaviorEventIn,
    DeviceIn,
    FeedbackIn,
    OTPInitIn,
    OTPVerifyIn,
    ScoreOut,
    TransactionIn,
)
from ..security import encrypt_json
from ..services.analytics import count_user_tx_last_minutes
from ..services.audit import record as record_audit
from ..services.darkweb import is_exposed

router = APIRouter()
logger = get_logger("fraudguard.fraud")

# Hard ceiling on how many transactions the *synchronous* GET /graph will
# ever consider per page. Now backed by PageParams (see API-05 fix below),
# so this is a defensive upper bound on top of PageParams.MAX_PAGE_SIZE,
# not the primary control.
GRAPH_MAX_TRANSACTIONS = 5_000

# Ceiling for the *background job* graph computation (POST /graph/jobs).
# Allowed to scan much further back than the synchronous endpoint
# specifically because it runs off the request/response cycle — see
# SCALE-02 fix / _run_graph_job below.
GRAPH_JOB_MAX_TRANSACTIONS = 50_000


def _require_user_id(user: models.User) -> int:
    if user is None or user.id is None:
        raise ForbiddenError("unresolved_user", "Could not resolve authenticated user")
    return user.id


def _require_transaction_ownership(tx: models.Transaction, user: models.User) -> None:
    """
    Single source of truth for "may this user act on this transaction?".

    Extracted because the same two-line check (owner OR admin) was
    previously duplicated across otp_init and otp_verify, and had silently
    gone missing from a third, newer endpoint (/fraud/feedback) — the
    ownership-check gap the code review flagged. Centralizing it means a
    future endpoint that needs the same rule calls this instead of
    re-deriving it (and risking re-deriving it incorrectly, or forgetting
    it entirely).
    """
    if tx.user_id != user.id and user.role != "admin":
        raise ForbiddenError("not_authorized_for_transaction", "Not authorized for this transaction")


def _build_relationship_graph(transactions: list[models.Transaction]) -> nx.Graph:
    """
    Shared graph-construction logic for both the synchronous, paginated
    GET /graph endpoint and the asynchronous POST /graph/jobs background
    job — kept as one function so the two code paths cannot silently drift
    into building the graph differently.
    """
    graph = nx.Graph()
    for tx in transactions:
        if tx.user_id is None:
            continue
        user_node = f"user:{tx.user_id}"
        graph.add_node(user_node, type="user", id=tx.user_id)

        if tx.device_id:
            device_node = f"device:{tx.device_id}"
            graph.add_node(device_node, type="device", id=tx.device_id)
            graph.add_edge(user_node, device_node, kind="seen_on")

        if tx.ip:
            ip_node = f"ip:{tx.ip}"
            graph.add_node(ip_node, type="ip", id=tx.ip)
            graph.add_edge(user_node, ip_node, kind="used_from")
    return graph


def _run_graph_job(job_id: int, limit: int, session_factory) -> None:
    """
    Executed via FastAPI `BackgroundTasks` — i.e. after the response for
    POST /graph/jobs has already been sent to the client (SCALE-02 fix:
    moves the potentially-expensive full graph scan off the request/
    response cycle instead of blocking a worker on it synchronously).

    Deliberately opens its own DB session from `session_factory()` instead
    of reusing the request-scoped session from `Depends(get_db)`: that
    session's lifecycle is tied to the request/response cycle via
    `database.py::get_db`'s generator teardown, which is not a dependable
    handle to keep using once the response has already gone out.
    `session_factory` is threaded through as a plain argument (rather than
    importing `database.SessionLocal` directly) specifically so tests can
    override `get_session_factory` the same way they override `get_db` —
    see database.py::get_session_factory's docstring. Every state
    transition is committed independently so an interrupted process leaves
    the job row in a legible `status` rather than silently hanging forever
    as "pending".
    """
    db = session_factory()
    repo = GraphJobRepository(db)
    try:
        repo.mark_running(job_id)
        transactions = (
            db.query(models.Transaction).order_by(models.Transaction.timestamp.desc()).limit(limit).all()
        )
        graph = _build_relationship_graph(transactions)
        repo.mark_done(
            job_id,
            transactions_considered=len(transactions),
            truncated=len(transactions) == limit,
            result=json_graph.node_link_data(graph),
        )
        logger.info("graph_job_completed", extra={"job_id": job_id, "transactions": len(transactions)})
    except Exception as exc:  # pragma: no cover - defensive; exercised via test_graph_jobs failure-path test
        db.rollback()
        repo.mark_failed(job_id, error=str(exc))
        logger.exception("graph_job_failed", extra={"job_id": job_id})
    finally:
        db.close()


@router.post("/score", response_model=ScoreOut)
def score_transaction(
    payload: TransactionIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
    tx_repo: TransactionRepository = Depends(get_transaction_repository),
    alert_repo: AlertRepository = Depends(get_alert_repository),
):
    uid = _require_user_id(user)
    tx_data = payload.model_dump()
    tx_data["velocity_1min"] = count_user_tx_last_minutes(db, uid, 1)
    if tx_data.get("card_hash"):
        tx_data["darkweb_hit"] = is_exposed(tx_data["card_hash"])

    features = ensemble_features(tx_data)
    score, decision, reason = compute_risk_score(features)

    tx = tx_repo.create(
        user_id=uid,
        amount=payload.amount,
        currency=payload.currency,
        merchant=payload.merchant,
        mcc=payload.mcc,
        ip=payload.ip,
        gps_lat=payload.gps_lat,
        gps_lon=payload.gps_lon,
        device_id=payload.device_id,
        features=encrypt_json(features),
        score=score,
        decision=decision,
    )
    db.flush()

    if decision in ("block", "challenge"):
        alert_repo.create(transaction_id=tx.id, risk_score=score, decision=decision, reason=reason)

    db.commit()
    db.refresh(tx)

    logger.info(
        "transaction_scored",
        extra={"user_id": uid, "transaction_id": tx.id, "score": score, "decision": decision},
    )
    return ScoreOut(score=score, decision=decision, reason=reason, transaction_id=tx.id)


@router.post("/behavior", status_code=201)
def track_behavior(
    event: BehaviorEventIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    behavior_event = models.BehaviorEvent(
        user_id=_require_user_id(user),
        event_type=event.event_type,
        data=encrypt_json(event.data),
    )
    db.add(behavior_event)
    db.commit()
    return {"status": "ok"}


@router.post("/device", status_code=201)
def register_device(
    device: DeviceIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    device_record = models.Device(
        user_id=_require_user_id(user),
        device_id=device.device_id,
        fingerprint=encrypt_json(device.fingerprint),
        compromised=False,
    )
    db.add(device_record)
    db.commit()
    return {"status": "ok"}


@router.get("/alerts", response_model=Page[AlertOut])
def alerts_feed(
    repo: AlertRepository = Depends(get_alert_repository),
    user: models.User = Depends(require_role("admin", "analyst")),
    params: PageParams = Depends(),
    decision: Optional[str] = Query(
        default=None, description=f"Filter by decision. One of: {list(TRANSACTION_DECISIONS)}"
    ),
    sort: str = Query(
        default="-created_at",
        description="Sort field, prefix with '-' for descending. One of: created_at, -created_at, risk_score, -risk_score",
    ),
):
    if decision and decision not in TRANSACTION_DECISIONS:
        raise BadRequestError(
            "invalid_filter_value", f"decision must be one of {list(TRANSACTION_DECISIONS)}"
        )
    items, meta = repo.list_paginated(params, decision=decision, sort=sort)
    return Page(items=items, meta=meta)


@router.post("/feedback", status_code=201)
def submit_feedback(
    feedback: FeedbackIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
    tx_repo: TransactionRepository = Depends(get_transaction_repository),
):
    # NOTE: this only records investigator feedback as an audit trail entry.
    # It does not feed any retraining loop — there is no trained model to
    # retrain (see README "What's Mocked vs. Real"). This is an honest
    # no-op beyond audit logging, not a stubbed promise of ML retraining.
    tx = tx_repo.get_by_id(feedback.transaction_id)
    if not tx:
        raise NotFoundError("transaction_not_found", f"No transaction with id {feedback.transaction_id}")

    # SECURITY FIX: this endpoint previously checked only that the
    # transaction existed, not ownership — the same bug class as the
    # otp_verify gap this project's remediation was originally aimed at,
    # and precisely the "does every endpoint that checks ownership have a
    # sibling that doesn't?" lesson documented in README "Challenges
    # faced". Uses the same shared ownership rule as otp_init/otp_verify
    # (see _require_transaction_ownership below) instead of re-deriving it
    # inline a third time.
    _require_transaction_ownership(tx, user)

    record_audit(
        db,
        actor_user_id=user.id,
        action="feedback_submitted",
        target=f"transaction:{feedback.transaction_id}",
        details=f"label={'fraud' if feedback.label else 'legit'}",
    )
    db.commit()
    return {"status": "recorded"}


@router.get("/graph")
def fraud_graph(
    repo: TransactionRepository = Depends(get_transaction_repository),
    user: models.User = Depends(require_role("admin")),
    params: PageParams = Depends(),
):
    """
    Builds a user/device/IP relationship graph for investigator tooling
    from one page of recent transactions.

    API-05 FIX: previously used a hardcoded `.limit(GRAPH_MAX_TRANSACTIONS)`
    instead of this API's shared pagination contract. Now accepts the same
    `page`/`page_size` query parameters as every other list endpoint
    (`/fraud/alerts`, `/admin/audit`, `/admin/users`) via `PageParams`, and
    a client pages through transactions (most-recent-first) instead of
    always receiving one fixed top-N slice.

    This remains a synchronous, request-time computation, intentionally
    scoped to one bounded page for fast interactive use. For the *full*
    graph across up to GRAPH_JOB_MAX_TRANSACTIONS transactions, use
    `POST /graph/jobs` instead (SCALE-02 background-job path) — see that
    endpoint's docstring.
    """
    items, meta = repo.list_recent_page(params)
    graph = _build_relationship_graph(items)

    return {
        "truncated": meta.page < meta.total_pages,
        "transactions_considered": len(items),
        "graph": json_graph.node_link_data(graph),
        "meta": meta,
    }


@router.post("/graph/jobs", status_code=202)
def create_graph_job(
    background_tasks: BackgroundTasks,
    job_repo: GraphJobRepository = Depends(get_graph_job_repository),
    user: models.User = Depends(require_role("admin")),
    session_factory=Depends(get_session_factory),
):
    """
    SCALE-02 FIX: computing the *full* fraud-ring graph (as opposed to one
    paginated page — see GET /graph above) can mean scanning up to
    GRAPH_JOB_MAX_TRANSACTIONS rows and building a networkx graph from all
    of them, which is exactly the kind of work that should not block a
    request/response cycle or an API worker. This kicks the computation off
    via FastAPI's `BackgroundTasks` (chosen over Celery+Redis: this project
    is not otherwise running a message broker, and BackgroundTasks is
    explicitly the right-sized tool for "run this after the response, in
    the same process" without introducing new infrastructure) and returns
    immediately with a job id; poll `GET /graph/jobs/{job_id}` for status
    and, once done, the result.
    """
    job = job_repo.create(requested_by_user_id=user.id)
    background_tasks.add_task(_run_graph_job, job.id, GRAPH_JOB_MAX_TRANSACTIONS, session_factory)
    logger.info("graph_job_queued", extra={"job_id": job.id, "user_id": user.id})
    return {"job_id": job.id, "status": job.status}


@router.get("/graph/jobs/{job_id}")
def get_graph_job(
    job_id: int,
    job_repo: GraphJobRepository = Depends(get_graph_job_repository),
    user: models.User = Depends(require_role("admin")),
):
    job = job_repo.get_by_id(job_id)
    if not job:
        raise NotFoundError("graph_job_not_found", f"No graph job with id {job_id}")

    response: dict[str, Any] = {
        "job_id": job.id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "transactions_considered": job.transactions_considered,
        "truncated": job.truncated,
    }
    if job.status == "done":
        response["graph"] = job.result
    elif job.status == "failed":
        response["error"] = job.error
    return response


@router.post("/otp/init")
def otp_init(
    payload: OTPInitIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
    tx_repo: TransactionRepository = Depends(get_transaction_repository),
    otp_repo: OTPChallengeRepository = Depends(get_otp_challenge_repository),
):
    tx = tx_repo.get_by_id(payload.transaction_id)
    if not tx:
        raise NotFoundError("transaction_not_found", f"No transaction with id {payload.transaction_id}")
    _require_transaction_ownership(tx, user)

    code = f"{secrets.randbelow(1_000_000):06d}"
    otp_repo.create(transaction_id=tx.id, user_id=user.id, code=code)
    record_audit(
        db,
        actor_user_id=user.id,
        action="otp_initiated",
        target=f"transaction:{tx.id}",
    )
    db.commit()
    logger.info("otp_initiated", extra={"user_id": user.id, "transaction_id": tx.id})
    return {"status": "sent", "transaction_id": tx.id}


@router.post("/otp/verify")
def otp_verify(
    payload: OTPVerifyIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
    tx_repo: TransactionRepository = Depends(get_transaction_repository),
    otp_repo: OTPChallengeRepository = Depends(get_otp_challenge_repository),
):
    """
    SECURITY FIX (previously a broken-access-control bug): this endpoint
    now enforces the exact same ownership check as otp_init — the
    requesting user must own the transaction (or be an admin) before any
    OTP-verification attempt is even considered. Previously, any
    authenticated user who knew or guessed a transaction_id could attempt
    to verify OTP codes against another user's transaction, relying solely
    on the 6-digit code's randomness rather than authorization as the
    security boundary.
    """
    tx = tx_repo.get_by_id(payload.transaction_id)
    if not tx:
        raise NotFoundError("transaction_not_found", f"No transaction with id {payload.transaction_id}")
    _require_transaction_ownership(tx, user)

    challenge = otp_repo.get_latest_for_transaction(payload.transaction_id)
    if not challenge:
        raise NotFoundError("challenge_not_found", "No OTP challenge exists for this transaction")

    if challenge.verified:
        return {"status": "already_verified"}

    if datetime.utcnow() > challenge.expires_at:
        record_audit(
            db,
            actor_user_id=user.id,
            action="otp_verify_expired",
            target=f"transaction:{tx.id}",
        )
        db.commit()
        logger.warning("otp_verify_expired", extra={"user_id": user.id, "transaction_id": tx.id})
        raise BadRequestError("code_expired", "This OTP code has expired; request a new one")

    if challenge.code != payload.code:
        record_audit(
            db,
            actor_user_id=user.id,
            action="otp_verify_failed",
            target=f"transaction:{tx.id}",
        )
        db.commit()
        logger.warning("otp_verify_failed", extra={"user_id": user.id, "transaction_id": tx.id})
        raise BadRequestError("invalid_code", "The provided OTP code is incorrect")

    challenge.verified = True
    db.add(challenge)
    if tx.decision == "challenge":
        tx.decision = "allow"
        db.add(tx)

    record_audit(
        db,
        actor_user_id=user.id,
        action="otp_verify_succeeded",
        target=f"transaction:{tx.id}",
    )
    db.commit()
    logger.info("otp_verify_succeeded", extra={"user_id": user.id, "transaction_id": tx.id})
    return {"status": "verified"}
