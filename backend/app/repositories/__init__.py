"""
Repository layer: thin classes that own SQLAlchemy query construction for
one aggregate/table each, injected into routers via FastAPI `Depends()`.

Why this exists: the portfolio audit found route handlers calling
`db.query(models.X)...` directly and inconsistently (AR-03/AR-04 findings)
— which works, but means "how do I query alerts with eager-loaded
transactions?" or "what does ownership-scoped transaction lookup look
like?" has no single, reusable, testable answer; every router either
duplicates the query shape or drifts slightly from its siblings.

Design decisions:
- Each repository takes a `Session` in its constructor and exposes plain
  methods returning ORM instances or primitives — no FastAPI-specific code
  inside the repository classes themselves, so they're usable and testable
  outside a request context (e.g. from scripts/seed.py or a unit test)
  without needing to fake a Request.
- Repositories own *query shape* (filtering, sorting, eager-loading,
  pagination wiring) — they deliberately do NOT own authorization/business
  rules (e.g. "is this user allowed to see this transaction") or
  transaction-boundary decisions (commit/rollback), which stay in the
  router/service layer that already owns those per docs/architecture.md.
  A repository that both authorizes and stores data would blur exactly the
  separation this pattern exists to make explicit.
- Kept intentionally small (no generic `Repository[T]` base class with
  reflection-based CRUD): every method here corresponds to an actual,
  named query a router needs, per YAGNI — a generic base class would add
  indirection without a second real implementation to justify it yet.
"""
from .alerts import AlertRepository, get_alert_repository
from .audit_logs import AuditLogRepository, get_audit_log_repository
from .graph_jobs import GraphJobRepository, get_graph_job_repository
from .otp_challenges import OTPChallengeRepository, get_otp_challenge_repository
from .transactions import TransactionRepository, get_transaction_repository
from .users import UserRepository, get_user_repository

__all__ = [
    "AlertRepository",
    "get_alert_repository",
    "AuditLogRepository",
    "get_audit_log_repository",
    "GraphJobRepository",
    "get_graph_job_repository",
    "OTPChallengeRepository",
    "get_otp_challenge_repository",
    "TransactionRepository",
    "get_transaction_repository",
    "UserRepository",
    "get_user_repository",
]
