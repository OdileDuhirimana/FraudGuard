from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..pagination import PageMeta, PageParams, paginate


class TransactionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, transaction_id: int) -> Optional[models.Transaction]:
        return self.db.query(models.Transaction).filter(models.Transaction.id == transaction_id).first()

    def create(self, **fields: Any) -> models.Transaction:
        tx = models.Transaction(**fields)
        self.db.add(tx)
        return tx

    def count_since(self, user_id: int, since: datetime) -> int:
        """Backs the velocity feature; see services/analytics.py for the caller-facing wrapper."""
        return (
            self.db.query(models.Transaction)
            .filter(models.Transaction.user_id == user_id, models.Transaction.timestamp >= since)
            .count()
        )

    def list_recent_page(self, params: PageParams) -> tuple[list[models.Transaction], PageMeta]:
        """
        API-05 FIX: backs the now-paginated `/fraud/graph` endpoint. Replaces
        the previous hardcoded `.limit(GRAPH_MAX_TRANSACTIONS)` with the same
        `PageParams`/`paginate()` contract every other list endpoint in this
        API already uses, instead of a bespoke one-off cap.
        """
        query = self.db.query(models.Transaction).order_by(models.Transaction.timestamp.desc())
        return paginate(query, params)

    def list_bounded_by_recency(self, limit: int) -> list[models.Transaction]:
        """
        Used by the full (non-paginated) background graph job — bounded by
        an explicit hard ceiling (GRAPH_JOB_MAX_TRANSACTIONS) rather than
        left unbounded, since this path is intentionally allowed to scan
        much further back than the synchronous endpoint precisely because
        it runs off the request/response cycle.
        """
        return (
            self.db.query(models.Transaction)
            .order_by(models.Transaction.timestamp.desc())
            .limit(limit)
            .all()
        )


def get_transaction_repository(db: Session = Depends(get_db)) -> TransactionRepository:
    return TransactionRepository(db)
