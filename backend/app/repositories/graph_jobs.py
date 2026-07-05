from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db


class GraphJobRepository:
    """
    Backs the async fraud-ring graph job (SCALE-02). Deliberately commits
    inside each mutating method (unlike the request-scoped repositories
    elsewhere in this package) because the background task that drives
    most of this repository's lifecycle (see routers/fraud.py::_run_graph_job)
    has no surrounding request transaction to piggyback a shared commit on
    — each state transition (queued -> running -> done/failed) needs to be
    durable independently in case the process is interrupted mid-job.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, *, requested_by_user_id: int) -> models.GraphJob:
        job = models.GraphJob(requested_by_user_id=requested_by_user_id, status="pending")
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        return job

    def get_by_id(self, job_id: int) -> Optional[models.GraphJob]:
        return self.db.query(models.GraphJob).filter(models.GraphJob.id == job_id).first()

    def mark_running(self, job_id: int) -> None:
        job = self.get_by_id(job_id)
        if job is None:
            return
        job.status = "running"
        self.db.add(job)
        self.db.commit()

    def mark_done(
        self, job_id: int, *, transactions_considered: int, truncated: bool, result: Any
    ) -> None:
        job = self.get_by_id(job_id)
        if job is None:
            return
        job.status = "done"
        job.completed_at = datetime.utcnow()
        job.transactions_considered = transactions_considered
        job.truncated = truncated
        job.result = result
        self.db.add(job)
        self.db.commit()

    def mark_failed(self, job_id: int, *, error: str) -> None:
        job = self.get_by_id(job_id)
        if job is None:
            return
        job.status = "failed"
        job.completed_at = datetime.utcnow()
        job.error = error[:2000]
        self.db.add(job)
        self.db.commit()


def get_graph_job_repository(db: Session = Depends(get_db)) -> GraphJobRepository:
    return GraphJobRepository(db)
