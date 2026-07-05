from __future__ import annotations

from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session, joinedload

from .. import models
from ..database import get_db
from ..pagination import PageMeta, PageParams, paginate

_SORT_MAP = {
    "created_at": models.Alert.created_at.asc(),
    "-created_at": models.Alert.created_at.desc(),
    "risk_score": models.Alert.risk_score.asc(),
    "-risk_score": models.Alert.risk_score.desc(),
}


class AlertRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_paginated(
        self, params: PageParams, *, decision: Optional[str], sort: str
    ) -> tuple[list[models.Alert], PageMeta]:
        """
        PERF-02 FIX: eager-loads each alert's parent transaction via
        `joinedload` (a single SQL JOIN) instead of the default lazy-load,
        which would otherwise issue one extra `SELECT` per alert the first
        time `AlertOut.transaction` is accessed during response
        serialization — the textbook N+1 pattern the audit's SCALE-04
        finding was pointing at. `AlertOut` now serializes a nested
        transaction summary (see schemas.py), which is what makes this
        eager-load load-bearing rather than decorative.
        """
        query = self.db.query(models.Alert).options(joinedload(models.Alert.transaction))
        if decision:
            query = query.filter(models.Alert.decision == decision)
        query = query.order_by(_SORT_MAP.get(sort, models.Alert.created_at.desc()))
        return paginate(query, params)

    def create(self, *, transaction_id: int, risk_score: float, decision: str, reason: str) -> models.Alert:
        alert = models.Alert(
            transaction_id=transaction_id, risk_score=risk_score, decision=decision, reason=reason
        )
        self.db.add(alert)
        return alert


def get_alert_repository(db: Session = Depends(get_db)) -> AlertRepository:
    return AlertRepository(db)
