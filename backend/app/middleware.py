"""
Per-IP, per-path-budget rate limiter with a swappable storage backend.

Known limitation, now mitigated (see docs/adr/0004-rate-limiting.md):
the original implementation was in-memory and process-local, meaning a
horizontally-scaled deployment (more than one instance) would enforce an
independent budget per instance rather than one shared budget. Setting
REDIS_URL now switches the limiter to a Redis-backed counter shared across
all instances; leaving it unset preserves the original in-memory behavior
for a single-instance deployment, unchanged.

Bug fixed in this pass (see `_bucket_scope_for_path`'s docstring): the
bucket key previously derived its "distinguishing" path segment via
`path.split('/')[1]`, which for every route in this API always evaluates
to the literal string "v1" — collapsing distinct sensitive endpoints
(e.g. `/v1/auth/login` and `/v1/auth/register`) that share a *type* of
budget into one shared counter.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import settings
from .logging_config import get_logger

logger = get_logger("fraudguard.middleware")


class RateLimitBackend(Protocol):
    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Record one hit against `key`; return True if still within `limit` for the current window."""
        ...


@dataclass
class _Bucket:
    count: int
    window_start: float


class InMemoryRateLimitBackend:
    """
    Process-local, in-memory fixed-window counter — the original (and
    still the default when `REDIS_URL` is unset) implementation. See
    docs/adr/0004-rate-limiting.md for its single-instance limitation.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        bucket = self._buckets.get(key)
        if bucket is None or now - bucket.window_start > window_seconds:
            bucket = _Bucket(count=0, window_start=now)
        bucket.count += 1
        self._buckets[key] = bucket
        return bucket.count <= limit


class RedisRateLimitBackend:
    """
    Shared, cross-instance fixed-window counter backed by Redis. Replaces
    InMemoryRateLimitBackend's single-instance limitation once `REDIS_URL`
    is configured — every instance behind a load balancer increments the
    same Redis key, so the configured budget is a real, shared budget
    rather than "budget × instance count".

    Implementation is a classic fixed-window counter: `INCR` the
    window-scoped key, and set its TTL only on the first hit of a window
    (`count == 1`) so the key naturally expires and the window resets
    without a separate cleanup job. This is simpler than a sliding-window
    log and sufficient for this API's purpose (bounding abuse, not
    billing-grade precision); its known tradeoff is allowing brief
    over-limit bursts at a window boundary, which is an accepted,
    documented characteristic of fixed-window limiting generally, not a
    defect specific to this implementation.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        count = self._redis.incr(key)
        if count == 1:
            self._redis.expire(key, window_seconds)
        return count <= limit


def _build_redis_backend(redis_url: str) -> RedisRateLimitBackend:
    """
    Raises if Redis is unreachable — callers are expected to catch this at
    startup (falling back to in-memory) rather than have every request
    pay a connection-probe cost.
    """
    import redis as redis_lib

    client = redis_lib.Redis.from_url(redis_url, socket_connect_timeout=0.5, socket_timeout=0.5)
    client.ping()
    return RedisRateLimitBackend(client)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        max_requests: int = 300,
        window_seconds: int = 60,
        sensitive_prefixes: tuple[tuple[str, int], ...] = (),
        backend: RateLimitBackend | None = None,
    ) -> None:
        """
        sensitive_prefixes: ordered (path_prefix, max_requests) pairs checked
        before the default budget. The window length is shared
        (window_seconds) across all buckets for simplicity.

        backend: explicit override, primarily for tests (e.g. pointing at a
        real Redis instance without relying on process-wide settings). When
        omitted, the backend is chosen from `settings.redis_url` — Redis if
        set and reachable at startup, in-memory otherwise.
        """
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.sensitive_prefixes = sensitive_prefixes
        self._fallback_backend = InMemoryRateLimitBackend()
        self.backend = backend or self._build_default_backend()

    def _build_default_backend(self) -> RateLimitBackend:
        if not settings.redis_url:
            return self._fallback_backend
        try:
            backend = _build_redis_backend(settings.redis_url)
            logger.info("rate_limit_backend_selected", extra={"backend": "redis"})
            return backend
        except Exception as exc:
            logger.error(
                "rate_limit_redis_unavailable_at_startup_falling_back_to_memory",
                extra={"error": str(exc)},
            )
            return self._fallback_backend

    def _bucket_scope_for_path(self, path: str) -> tuple[str, int]:
        """
        Returns (bucket_scope, limit) for a given request path.

        bucket_scope is the *distinguishing* identifier used to key the
        per-path budget. Bug fixed here: the previous implementation used
        `path.split('/')[1]`, which for every route under this API (all
        versioned under `/v1/...`) always evaluates to the literal string
        "v1" — collapsing every sensitive endpoint into one shared bucket
        regardless of which `sensitive_prefixes` entry actually matched.
        Concretely, `/v1/auth/login` and `/v1/auth/register` (and
        `/v1/fraud/otp/init` vs `/v1/fraud/otp/verify`) shared one budget,
        so exhausting the login limit also silently throttled registration
        attempts from the same IP, and vice versa. Using the matched
        `sensitive_prefixes` entry itself (falling back to a fixed sentinel
        for the default budget) makes each configured budget independent,
        which is the behavior `build_rate_limit_kwargs()` and
        docs/adr/0004-rate-limiting.md already document as intended.
        """
        for prefix, limit in self.sensitive_prefixes:
            if path.startswith(prefix):
                return prefix, limit
        return "__default__", self.max_requests

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        bucket_scope, limit = self._bucket_scope_for_path(path)
        bucket_key = f"{client_ip}:{bucket_scope}"

        try:
            allowed = self.backend.hit(bucket_key, limit, self.window)
        except Exception as exc:
            # AVAILABILITY-OVER-STRICT-ENFORCEMENT tradeoff (documented in
            # docs/adr/0004-rate-limiting.md): if the configured Redis
            # backend becomes unreachable mid-flight, fail open to the
            # in-memory backend for this request rather than either taking
            # the whole API down over a degraded rate-limit dependency, or
            # blocking every request outright. Logged as an error so a
            # degraded backend is observable even though the API stays up.
            logger.error("rate_limit_backend_error_failing_open_to_memory", extra={"error": str(exc)})
            allowed = self._fallback_backend.hit(bucket_key, limit, self.window)

        if not allowed:
            return JSONResponse(
                {"error": {"code": "rate_limit_exceeded", "message": "Too many requests. Please try again later.", "details": None}},
                status_code=429,
            )
        return await call_next(request)


def build_rate_limit_kwargs() -> dict:
    """Central place that decides which route prefixes get tighter budgets."""
    return {
        "max_requests": settings.rate_limit_default_per_minute,
        "window_seconds": 60,
        "sensitive_prefixes": (
            ("/v1/auth/login", settings.rate_limit_auth_per_minute),
            ("/v1/auth/register", settings.rate_limit_auth_per_minute),
            ("/v1/fraud/otp/verify", settings.rate_limit_otp_per_minute),
            ("/v1/fraud/otp/init", settings.rate_limit_otp_per_minute),
        ),
    }
