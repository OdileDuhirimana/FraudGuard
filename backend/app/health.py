"""
Readiness/liveness health check.

Why: the original `/health` returned a hardcoded `{"ok": True}` regardless
of whether the database (or anything else the app depends on) was actually
reachable — a liveness stub, not a real readiness probe. Render's
`healthCheckPath` and any future orchestrator (k8s, ECS) needs a health
check that can distinguish "the process is up" from "the process can
actually serve traffic," otherwise a DB outage looks identical to a healthy
deployment right up until the first real request fails.
"""
from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("fraudguard.health")

Status = Literal["ok", "degraded"]


class DependencyStatus(BaseModel):
    name: str
    healthy: bool
    detail: str | None = None


class HealthReport(BaseModel):
    status: Status
    dependencies: list[DependencyStatus]


def check_database(db: Session) -> DependencyStatus:
    try:
        db.execute(text("SELECT 1"))
        return DependencyStatus(name="database", healthy=True)
    except Exception as exc:  # pragma: no cover - exercised via failure-path test with a broken session
        logger.error("health_check_database_failed", extra={"error": str(exc)})
        return DependencyStatus(name="database", healthy=False, detail="database connectivity check failed")


def build_health_report(db: Session) -> HealthReport:
    dependencies = [check_database(db)]
    overall: Status = "ok" if all(d.healthy for d in dependencies) else "degraded"
    return HealthReport(status=overall, dependencies=dependencies)
