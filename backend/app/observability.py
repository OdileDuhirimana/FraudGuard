"""
Error tracking (Sentry) and metrics (Prometheus) wiring — OBS-02/OBS-03
fixes.

Design decisions:

1. Sentry is initialized only if `SENTRY_DSN` is set (`configure_error_tracking`).
   Unset is a fully supported, first-class state — a demo/portfolio
   deployment without a Sentry project must boot and behave identically,
   not degrade or warn. This mirrors the same "optional, no-op if unset"
   pattern already used for `FG_ML_ARTIFACTS` (config.py) rather than
   introducing a new pattern for this one dependency.

2. Metrics use `prometheus_client` directly rather than
   `prometheus-fastapi-instrumentator`: that package's pinned Starlette
   requirement (`>=1.0.0`) conflicts with this project's pinned
   `fastapi==0.115.5` (which requires `starlette<0.42,>=0.40`) — installing
   it in this environment silently upgraded Starlette to an incompatible
   version via pip's resolver, which is exactly the kind of
   dependency-manifest drift this project's own ADRs (0001) warn against
   elsewhere. A ~30-line hand-rolled middleware using the underlying
   `prometheus_client` library avoids the conflict entirely and is small
   enough to read in full, which is arguably more in keeping with this
   project's "no framework-in-a-framework" bias (see ADR 0004 preferring
   in-memory rate limiting over adding Redis for a single-instance demo).
"""
from __future__ import annotations

import time

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .config import settings
from .logging_config import get_logger

logger = get_logger("fraudguard.observability")

REQUEST_COUNT = Counter(
    "fraudguard_http_requests_total",
    "Total HTTP requests processed, labeled by method/path template/status code.",
    ["method", "path", "status_code"],
)
REQUEST_LATENCY_SECONDS = Histogram(
    "fraudguard_http_request_duration_seconds",
    "HTTP request latency in seconds, labeled by method/path template.",
    ["method", "path"],
)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Records request count and latency for every request. Uses the matched
    route's path *template* (e.g. `/v1/fraud/otp/verify` -> the route
    pattern, not `/v1/admin/audit?actor_user_id=123` with query params or a
    raw path with interpolated IDs) as the label value where available, so
    cardinality stays bounded regardless of how many distinct resource IDs
    or query strings are requested — an unbounded label (e.g. the raw path
    with a numeric id in it) would make this metric grow without bound in
    a way that defeats the point of using Prometheus at all.
    """

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        route = request.scope.get("route")
        path_label = route.path if route is not None else request.url.path

        REQUEST_COUNT.labels(
            method=request.method, path=path_label, status_code=str(response.status_code)
        ).inc()
        REQUEST_LATENCY_SECONDS.labels(method=request.method, path=path_label).observe(duration)
        return response


def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def configure_error_tracking() -> None:
    """
    No-op unless SENTRY_DSN is set. Imports sentry_sdk lazily (inside the
    function) rather than at module scope so a deployment that never sets
    SENTRY_DSN pays no import cost and — more importantly — can never fail
    to boot because of a Sentry SDK issue it isn't even using.
    """
    if not settings.sentry_dsn:
        logger.info("sentry_not_configured", extra={"detail": "SENTRY_DSN unset; error tracking disabled"})
        return

    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.env,
        integrations=[StarletteIntegration(), FastApiIntegration()],
        # Conservative default: capture all errors, sample a modest slice
        # of transactions for performance monitoring rather than 100% (which
        # would add overhead to every request in a demo deployment with no
        # real traffic budgeting).
        traces_sample_rate=0.1,
        send_default_pii=False,
    )
    logger.info("sentry_configured", extra={"environment": settings.env})


def instrument_app(app: FastAPI) -> None:
    """Wires both observability concerns into the FastAPI app in one call from main.py."""
    configure_error_tracking()
    app.add_middleware(PrometheusMiddleware)
    app.add_api_route("/metrics", metrics_endpoint, methods=["GET"], tags=["meta"], include_in_schema=False)
