from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
from ..schemas import TransactionIn, ScoreOut, BehaviorEventIn, DeviceIn, FeedbackIn, OTPInitIn, OTPVerifyIn
from ..ml.ensemble import ensemble_features
from ..risk import risk_score
from ..auth import get_current_user
from ..services.analytics import count_user_tx_last_minutes
from ..services.darkweb import is_exposed
from ..security import encrypt_json
from networkx.readwrite import json_graph
import networkx as nx
import random

router = APIRouter()


@router.post("/score", response_model=ScoreOut)
def score_transaction(payload: TransactionIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    d = payload.dict()
    # augment with velocity and dark web exposure
    if d.get("user_id") or getattr(user, "id", None):
        uid = d.get("user_id") or user.id
        d["velocity_1min"] = count_user_tx_last_minutes(db, uid, 1)
    if d.get("card_hash"):
        d["darkweb_hit"] = is_exposed(d["card_hash"])

    features = ensemble_features(d)
    s, decision, reason = risk_score(features)

    tx = models.Transaction(
        user_id=payload.user_id or user.id,
        amount=payload.amount,
        currency=payload.currency,
        merchant=payload.merchant,
        mcc=payload.mcc,
        ip=payload.ip,
        gps_lat=payload.gps_lat,
        gps_lon=payload.gps_lon,
        device_id=payload.device_id,
        features=encrypt_json(features),
        score=s,
        decision=decision,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)

    if decision in ("block", "challenge"):
        alert = models.Alert(transaction_id=tx.id, risk_score=s, decision=decision, reason=reason)
        db.add(alert)
        db.commit()

    return ScoreOut(score=s, decision=decision, reason=reason, transaction_id=tx.id)


@router.post("/behavior")
def track_behavior(event: BehaviorEventIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    be = models.BehaviorEvent(user_id=event.user_id, event_type=event.event_type, data=encrypt_json(event.data))
    db.add(be)
    db.commit()
    return {"status": "ok"}


@router.post("/device")
def register_device(d: DeviceIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    dev = models.Device(user_id=d.user_id, device_id=d.device_id, fingerprint=encrypt_json(d.fingerprint), compromised=False)
    db.add(dev)
    db.commit()
    return {"status": "ok"}


@router.get("/alerts")
def alerts_feed(db: Session = Depends(get_db), user=Depends(get_current_user)):
    alerts = db.query(models.Alert).order_by(models.Alert.created_at.desc()).limit(100).all()
    return alerts


@router.post("/feedback")
def feedback_fb(fb: FeedbackIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # Stub: record feedback as audit log for now
    log = models.AuditLog(actor_user_id=user.id, action="feedback", target=str(fb.transaction_id), details=str(fb.label))
    db.add(log)
    db.commit()
    return {"status": "recorded"}


@router.get("/graph")
def fraud_graph(db: Session = Depends(get_db), user=Depends(get_current_user)):
    # Build a simple graph where nodes are users and devices; edges connect user<->device and user<->ip clusters
    G = nx.Graph()
    # Users nodes
    users = db.query(models.Transaction.user_id).distinct().all()
    for (uid,) in users:
        if uid is not None:
            G.add_node(f"user:{uid}", type="user", id=uid)
    # Devices and IPs from transactions
    txs = db.query(models.Transaction).all()
    for tx in txs:
        u = f"user:{tx.user_id}" if tx.user_id is not None else None
        if tx.device_id:
            d = f"device:{tx.device_id}"
            G.add_node(d, type="device", id=tx.device_id)
            if u:
                G.add_edge(u, d, kind="seen_on")
        if tx.ip:
            n = f"ip:{tx.ip}"
            G.add_node(n, type="ip", id=tx.ip)
            if u:
                G.add_edge(u, n, kind="used_from")
    data = json_graph.node_link_data(G)
    return data


@router.post("/otp/init")
def otp_init(payload: OTPInitIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    tx = db.query(models.Transaction).filter(models.Transaction.id == payload.transaction_id).first()
    if not tx:
        return {"error": "transaction_not_found"}
    code = f"{random.randint(0, 999999):06d}"
    challenge = models.OTPChallenge(transaction_id=tx.id, user_id=tx.user_id, code=code)
    db.add(challenge)
    db.commit()
    # In real-world, send via SMS/Email/Push. Here we return masked info and code for demo/testing.
    return {"status": "sent", "transaction_id": tx.id, "code": code}


@router.post("/otp/verify")
def otp_verify(payload: OTPVerifyIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    ch = db.query(models.OTPChallenge).filter(models.OTPChallenge.transaction_id == payload.transaction_id).order_by(models.OTPChallenge.created_at.desc()).first()
    if not ch:
        return {"error": "challenge_not_found"}
    if ch.verified:
        return {"status": "already_verified"}
    if ch.code != payload.code:
        return {"status": "invalid_code"}
    ch.verified = True
    db.add(ch)
    # If verified, mark transaction decision upgraded from challenge to allow
    tx = db.query(models.Transaction).filter(models.Transaction.id == payload.transaction_id).first()
    if tx and tx.decision == "challenge":
        tx.decision = "allow"
        db.add(tx)
    db.commit()
    return {"status": "verified"}
