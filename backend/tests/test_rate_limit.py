"""
Regression tests for RateLimitMiddleware's per-path budget partitioning.

Background: the audited middleware derived its rate-limit bucket key via
`path.split('/')[1]`, which for every route in this API (all versioned
under `/v1/...`) always evaluates to the literal string "v1" — regardless
of which endpoint actually matched a `sensitive_prefixes` entry. That
collapsed distinct sensitive endpoints sharing a *type* of budget into one
shared counter: `/v1/auth/login` and `/v1/auth/register` both resolve to
`rate_limit_auth_per_minute`, so they shared one bucket keyed only by
`(client_ip, limit_value, "v1")` — exhausting login attempts also silently
throttled registration attempts (and vice versa) from the same IP, and the
same collision existed between OTP init and verify.

These tests build a minimal Starlette app directly (rather than the full
FastAPI app) so tight, deterministic limits can be configured per test
without fighting the app-wide `RATE_LIMIT_*` env vars that conftest.py
intentionally sets very high (1000/min) for the rest of the suite.

Backend note: these tests always force `InMemoryRateLimitBackend`
explicitly rather than letting the middleware auto-select a backend from
`settings.redis_url`. This file is testing bucket-partitioning *logic*,
which must hold regardless of backend — forcing the in-memory backend
keeps these tests deterministic and isolated from whatever `REDIS_URL` a
developer's shell happens to have exported (e.g. while also running
tests/test_rate_limit_redis.py's real-Redis suite, which necessarily
shares state across test functions the way a real multi-instance
deployment would).
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware import InMemoryRateLimitBackend, RateLimitMiddleware


async def _ok(request):
    return PlainTextResponse("ok")


def _build_app(sensitive_prefixes: tuple[tuple[str, int], ...], default_limit: int = 1000) -> Starlette:
    routes = [
        Route("/v1/auth/login", _ok, methods=["POST"]),
        Route("/v1/auth/register", _ok, methods=["POST"]),
        Route("/v1/fraud/otp/init", _ok, methods=["POST"]),
        Route("/v1/fraud/otp/verify", _ok, methods=["POST"]),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=default_limit,
        window_seconds=60,
        backend=InMemoryRateLimitBackend(),
        sensitive_prefixes=sensitive_prefixes,
    )
    return app


def test_login_and_register_have_independent_budgets():
    """
    Exhausting the login budget from a given IP must not throttle
    registration attempts from the same IP, and vice versa — this is the
    exact regression the bucket-key bug caused.
    """
    app = _build_app(
        sensitive_prefixes=(
            ("/v1/auth/login", 2),
            ("/v1/auth/register", 2),
        )
    )
    client = TestClient(app)

    assert client.post("/v1/auth/login").status_code == 200
    assert client.post("/v1/auth/login").status_code == 200
    assert client.post("/v1/auth/login").status_code == 429  # login budget now exhausted

    # Registration budget must be untouched by the login requests above.
    assert client.post("/v1/auth/register").status_code == 200
    assert client.post("/v1/auth/register").status_code == 200
    assert client.post("/v1/auth/register").status_code == 429  # register's own budget


def test_otp_init_and_verify_have_independent_budgets():
    """Same collision class as login/register, for the OTP endpoints."""
    app = _build_app(
        sensitive_prefixes=(
            ("/v1/fraud/otp/init", 1),
            ("/v1/fraud/otp/verify", 1),
        )
    )
    client = TestClient(app)

    assert client.post("/v1/fraud/otp/init").status_code == 200
    assert client.post("/v1/fraud/otp/init").status_code == 429

    # Verify must still have its own untouched budget.
    assert client.post("/v1/fraud/otp/verify").status_code == 200
    assert client.post("/v1/fraud/otp/verify").status_code == 429


def test_bucket_scope_for_path_uses_matched_prefix_not_path_segment():
    """
    Direct unit check on the fixed helper: two different sensitive prefixes
    that would previously have hashed to the identical `path.split('/')[1]`
    ("v1") must now resolve to distinct bucket scopes.
    """
    middleware = RateLimitMiddleware(
        app=None,
        max_requests=300,
        window_seconds=60,
        sensitive_prefixes=(
            ("/v1/auth/login", 10),
            ("/v1/auth/register", 10),
        ),
        backend=InMemoryRateLimitBackend(),
    )
    login_scope, login_limit = middleware._bucket_scope_for_path("/v1/auth/login")
    register_scope, register_limit = middleware._bucket_scope_for_path("/v1/auth/register")

    assert login_scope != register_scope
    assert login_limit == register_limit == 10


def test_unmatched_path_falls_back_to_default_budget():
    middleware = RateLimitMiddleware(
        app=None,
        max_requests=300,
        window_seconds=60,
        sensitive_prefixes=(("/v1/auth/login", 10),),
        backend=InMemoryRateLimitBackend(),
    )
    scope, limit = middleware._bucket_scope_for_path("/v1/fraud/alerts")
    assert scope == "__default__"
    assert limit == 300
