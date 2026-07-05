"""
Structured (JSON) application logging.

Why: the previous codebase had zero `logging` calls anywhere — security
events (failed logins, role changes, OTP attempts, fraud decisions) left no
trail except the sparsely-populated AuditLog table. Structured JSON logs are
what any real deployment target (Render, Datadog, CloudWatch) expects for
log aggregation and searchability, so this is a minimal, dependency-light
step towards observability without overbuilding a full metrics/tracing stack
(explicitly out of scope for this pass).

Design decision: we use python-json-logger rather than hand-rolling a
Formatter, since it is a small, widely-used dependency and keeps the
formatter code itself trivial and low-risk.
"""
from __future__ import annotations

import logging
import sys

from pythonjsonlogger import jsonlogger

from .config import settings

_CONFIGURED = False


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        rename_fields={"asctime": "timestamp", "levelname": "level"},
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if not settings.is_production else logging.INFO)

    # Keep uvicorn's own loggers on the same structured handler instead of
    # uvicorn's default plain-text formatter, so log aggregation sees one
    # consistent shape.
    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(uvicorn_logger_name)
        uv_logger.handlers = [handler]
        uv_logger.propagate = False

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
