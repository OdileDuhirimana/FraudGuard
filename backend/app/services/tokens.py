"""
Server-side JWT revocation (logout) service.

Why this exists: the portfolio audit correctly identified that JWTs issued
by this API had no server-side revocation mechanism at all — once issued,
an access token remained valid for its full 8-hour lifetime no matter what
happened afterward (logout, compromised-token report, admin-forced
sign-out). A pure-JWT stateless design cannot "delete" an already-issued
token; the standard fix is a revocation list (this module) checked on
every authenticated request, trading a small amount of statelessness for
the ability to actually invalidate a session.

Design decision: a denylist (blacklist) of revoked jtis, not an allowlist
of active sessions — chosen because it only requires a write on logout
(the rare path) rather than a write on every single token issuance/login
(the common path), and because the existing token lifecycle already
depends on nothing being persisted at issuance time.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from .. import models


def revoke(db: Session, *, jti: str, user_id: Optional[int], expires_at: datetime) -> models.TokenBlacklist:
    """
    Record a jti as revoked. Callers are expected to db.commit() as part of
    their own transaction, matching services/audit.py's convention.
    """
    entry = models.TokenBlacklist(jti=jti, user_id=user_id, expires_at=expires_at)
    db.add(entry)
    db.flush()
    return entry


def is_revoked(db: Session, jti: Optional[str]) -> bool:
    """
    True if `jti` has been revoked. A missing/empty jti is treated as not
    revoked here (rather than raising) — callers that require every token
    to carry a jti should enforce that separately; this function only
    answers "is this specific jti on the denylist?".
    """
    if not jti:
        return False
    return db.query(models.TokenBlacklist).filter(models.TokenBlacklist.jti == jti).first() is not None


def prune_expired(db: Session, *, now: Optional[datetime] = None) -> int:
    """
    Delete blacklist rows whose underlying token has already expired on
    its own `exp` claim — safe to run at any time (an expired token would
    already fail JWT validation regardless of blacklist membership), and
    exists purely to bound table growth for a long-running deployment.
    Not currently scheduled automatically; documented in the README as an
    operational task for a production deployment (e.g. a periodic admin
    job or cron), rather than silently implied to run itself.
    """
    cutoff = now or datetime.utcnow()
    deleted = (
        db.query(models.TokenBlacklist)
        .filter(models.TokenBlacklist.expires_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
