"""
Centralized audit-trail writer.

Why: the audit found AuditLog was written to in exactly one place
(feedback submission) despite being the system's only durable record of
security-sensitive actions. Login, failed login, role changes, and OTP
verification attempts left no trail at all — undermining the
"compliance-grade authorization" the project claims. This module gives
every call site the same one-line call instead of hand-constructing
AuditLog rows inline (which is how the inconsistency crept in originally).
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .. import models


def record(
    db: Session,
    *,
    actor_user_id: Optional[int],
    action: str,
    target: Optional[str] = None,
    details: Optional[str] = None,
) -> models.AuditLog:
    """
    Write one audit log row. Callers are expected to db.commit() as part of
    their own transaction (this function only adds + flushes) so an audit
    write always lands atomically with the action it describes rather than
    as a separate, potentially-lost transaction.
    """
    entry = models.AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        target=target,
        details=details,
    )
    db.add(entry)
    db.flush()
    return entry
