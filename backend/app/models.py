from datetime import datetime, timedelta

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
)
from sqlalchemy.orm import relationship

from .database import Base

# Role/decision/status vocabularies are enforced via CheckConstraint below.
# Kept as plain Python tuples (not a DB enum type) so SQLite and Postgres
# both support them identically without dialect-specific enum migrations.
USER_ROLES = ("analyst", "investigator", "admin", "manager")
TRANSACTION_DECISIONS = ("allow", "challenge", "block")
CASE_STATUSES = ("open", "investigating", "closed")
GRAPH_JOB_STATUSES = ("pending", "running", "done", "failed")

# How long a generated OTP challenge remains valid. Short enough to bound
# an attacker's window if a code leaks (e.g. shoulder-surfing, log
# exposure), long enough that a legitimate user isn't punished for a slow
# SMS/email delivery hop in a real (non-demo) delivery integration.
OTP_TTL_MINUTES = 5


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(f"role IN {USER_ROLES!r}", name="ck_users_role_valid"),
    )


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False, default="USD")
    merchant = Column(String(255))
    mcc = Column(String(4))
    ip = Column(String(45))  # long enough for IPv6
    gps_lat = Column(Float)
    gps_lon = Column(Float)
    device_id = Column(String(128))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    features = Column(JSON)
    score = Column(Float, nullable=False, default=0.0)
    decision = Column(String, nullable=False, default="allow")

    user = relationship("User")

    __table_args__ = (
        CheckConstraint(f"decision IN {TRANSACTION_DECISIONS!r}", name="ck_transactions_decision_valid"),
        CheckConstraint("amount >= 0", name="ck_transactions_amount_nonnegative"),
        CheckConstraint("score >= 0 AND score <= 1", name="ck_transactions_score_range"),
        # Supports the hot-path velocity query in services/analytics.py
        # (count_user_tx_last_minutes filters on exactly this pair on every
        # /fraud/score call) — previously unindexed, a demonstrable
        # performance gap called out in the code review (DB-04).
        Index("ix_transactions_user_id_timestamp", "user_id", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    decision = Column(String, nullable=False)
    reason = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    transaction = relationship("Transaction")

    __table_args__ = (
        CheckConstraint(f"decision IN {TRANSACTION_DECISIONS!r}", name="ck_alerts_decision_valid"),
    )


class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    status = Column(String, nullable=False, default="open")
    notes = Column(String(2000))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    alert = relationship("Alert")

    __table_args__ = (
        CheckConstraint(f"status IN {CASE_STATUSES!r}", name="ck_cases_status_valid"),
    )


class GraphJob(Base):
    """
    Tracks an asynchronous fraud-ring graph computation (SCALE-02 fix).

    Why a DB table rather than an in-memory dict: this is a single-instance
    portfolio deployment today, but a durable, queryable job record is what
    actually generalizes to a multi-worker deployment later (any worker
    can poll/complete a job row; an in-memory dict would only work for the
    exact process that created it, reintroducing the same single-instance
    coupling this fix is meant to move away from — see
    docs/adr/0004-rate-limiting.md for the same lesson learned about
    process-local state).
    """

    __tablename__ = "graph_jobs"
    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    requested_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    transactions_considered = Column(Integer, nullable=True)
    truncated = Column(Boolean, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(String(2000), nullable=True)

    requested_by = relationship("User")

    __table_args__ = (
        CheckConstraint(f"status IN {GRAPH_JOB_STATUSES!r}", name="ck_graph_jobs_status_valid"),
    )


class TokenBlacklist(Base):
    """
    Server-side JWT revocation list (AUTH-02 fix).

    Access tokens issued by create_access_token() now carry a `jti` (JWT
    ID) claim. Logging out inserts that jti here rather than attempting to
    invalidate the token itself (JWTs are stateless and cannot be
    "deleted"); get_current_user() checks incoming tokens' jti against
    this table on every request. `expires_at` mirrors the token's own
    `exp` claim purely for potential cleanup/observability (a scheduled
    job could prune rows past their `expires_at` without weakening
    security, since an expired token would already fail JWT validation on
    its own) — it is not currently used to bound the revocation check
    itself, which stays correct even if cleanup never runs.
    """

    __tablename__ = "token_blacklist"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)

    user = relationship("User")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(64), nullable=False)
    target = Column(String(255))
    details = Column(String(2000))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    actor = relationship("User")

    @property
    def actor_email(self) -> str | None:
        """
        Convenience accessor for schemas.AuditLogOut. Reads the already
        (eager-)loaded `actor` relationship rather than issuing a query
        itself — safe to call from a serialization context precisely
        because repositories/audit_logs.py joinedload()s `actor` up front.
        """
        return self.actor.email if self.actor is not None else None


class BehaviorEvent(Base):
    __tablename__ = "behavior_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    event_type = Column(String(32), nullable=False)  # typing, mouse, touch
    data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String(128), nullable=False, index=True)
    fingerprint = Column(JSON)
    compromised = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")


def _default_otp_expiry() -> datetime:
    """
    Default OTP TTL, computed at insert time rather than as a fixed
    interval baked into the migration/model default expression, so it
    stays in one place (OTP_TTL_MINUTES) and is trivially testable by
    constructing a challenge with an explicit `expires_at` in the past.
    """
    return datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)


class OTPChallenge(Base):
    __tablename__ = "otp_challenges"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # SECURITY FIX: OTP challenges previously had no expiry at all — a
    # 6-digit code stayed valid indefinitely while verified=False, which
    # defeats the time-boxed premise of step-up MFA (rate limiting alone
    # mitigated brute force, but not "an attacker who obtains a stale code
    # days later"). Enforced in routers/fraud.py::otp_verify.
    expires_at = Column(DateTime, default=_default_otp_expiry, nullable=False)

    transaction = relationship("Transaction")
    user = relationship("User")
