from __future__ import annotations

from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session, joinedload

from .. import models
from ..database import get_db
from ..pagination import PageMeta, PageParams, paginate


class AuditLogRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_paginated(
        self, params: PageParams, *, action: Optional[str], actor_user_id: Optional[int], sort: str
    ) -> tuple[list[models.AuditLog], PageMeta]:
        """
        PERF-02 FIX: eager-loads each entry's `actor` (User) relationship
        via `joinedload` so `AuditLogOut.actor_email` (schemas.py) is
        populated from the single JOINed query instead of triggering one
        lazy-load `SELECT` per row on serialization.
        """
        query = self.db.query(models.AuditLog).options(joinedload(models.AuditLog.actor))
        if action:
            query = query.filter(models.AuditLog.action == action)
        if actor_user_id is not None:
            query = query.filter(models.AuditLog.actor_user_id == actor_user_id)

        sort_column = models.AuditLog.created_at
        query = query.order_by(sort_column.asc() if sort == "created_at" else sort_column.desc())
        return paginate(query, params)


def get_audit_log_repository(db: Session = Depends(get_db)) -> AuditLogRepository:
    return AuditLogRepository(db)
