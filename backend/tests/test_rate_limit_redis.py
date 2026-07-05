"""
Integration tests for RedisRateLimitBackend against a *real* Redis
instance.

These tests are skipped unless a `REDIS_URL` environment variable points
at a reachable Redis server — they are not run as part of the default
`pytest` invocation in an environment with no Redis available (this
project's rate limiting remains fully functional without Redis; see
InMemoryRateLimitBackend). CI provisions a real `redis` service container
specifically so this file runs for real there rather than being
permanently skipped — see .github/workflows/ci.yml.

Local verification note: these tests were run directly against a Redis 7
container (`docker run -d -p 16379:6379 redis:7-alpine`) during
development by exporting `REDIS_URL=redis://localhost:16379/0` before
invoking pytest, confirming the backend's actual wire behavior against a
real server rather than only against the in-memory fallback.

Uniqueness note: Starlette's TestClient always reports a fixed loopback
client IP (it does not support overriding it), so tests that share one
real Redis instance instead get uniqueness from a per-test random route
path used as the `sensitive_prefixes` entry — each test's bucket key is
therefore distinct even though the "client IP" portion of the key is the
same for every test in this file.
"""
from __future__ import annotations

import os
import uuid

import pytest
import redis as redis_lib
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware import RateLimitMiddleware, RedisRateLimitBackend

REDIS_URL = os.environ.get("REDIS_URL")


def _redis_reachable(url: str) -> bool:
    try:
        client = redis_lib.Redis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5)
        client.ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not REDIS_URL or not _redis_reachable(REDIS_URL),
    reason="REDIS_URL not set or Redis unreachable; skipping real-Redis rate-limit tests",
)


def _unique_path(name: str) -> str:
    return f"/{name}-{uuid.uuid4().hex}"


async def _ok(request):
    return PlainTextResponse("ok")


def _build_app(sensitive_prefixes, *, backend=None) -> Starlette:
    routes = [Route(path, _ok, methods=["POST"]) for path, _ in sensitive_prefixes]
    app = Starlette(routes=routes)
    if backend is None:
        client = redis_lib.Redis.from_url(REDIS_URL)
        backend = RedisRateLimitBackend(client)
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=1000,
        window_seconds=60,
        sensitive_prefixes=sensitive_prefixes,
        backend=backend,
    )
    return app


def test_redis_backend_enforces_the_configured_limit():
    login_path = _unique_path("login")
    app = _build_app(sensitive_prefixes=((login_path, 2),))
    client = TestClient(app)

    assert client.post(login_path).status_code == 200
    assert client.post(login_path).status_code == 200
    assert client.post(login_path).status_code == 429


def test_redis_backend_partitions_distinct_sensitive_endpoints():
    """
    Same regression this project's bucket-key bug caused (see
    test_rate_limit.py) — verified against the real Redis-backed path too,
    since Step 4 explicitly ties the Redis migration to fixing that bug's
    severity for a multi-instance deployment.
    """
    login_path = _unique_path("login")
    register_path = _unique_path("register")
    app = _build_app(sensitive_prefixes=((login_path, 2), (register_path, 2)))
    client = TestClient(app)

    assert client.post(login_path).status_code == 200
    assert client.post(login_path).status_code == 200
    assert client.post(login_path).status_code == 429

    assert client.post(register_path).status_code == 200
    assert client.post(register_path).status_code == 200
    assert client.post(register_path).status_code == 429


def test_redis_backend_shares_state_across_separate_middleware_instances():
    """
    The entire point of the Redis migration: two independent
    RateLimitMiddleware instances (standing in for two separate app
    processes/instances behind a load balancer) sharing one Redis backend
    must share one budget — this is exactly what InMemoryRateLimitBackend
    cannot do across processes.
    """
    login_path = _unique_path("login")
    prefixes = ((login_path, 2),)
    shared_redis_client = redis_lib.Redis.from_url(REDIS_URL)

    app_instance_1 = _build_app(prefixes, backend=RedisRateLimitBackend(shared_redis_client))
    app_instance_2 = _build_app(prefixes, backend=RedisRateLimitBackend(shared_redis_client))

    client_to_instance_1 = TestClient(app_instance_1)
    client_to_instance_2 = TestClient(app_instance_2)

    assert client_to_instance_1.post(login_path).status_code == 200
    # Second "instance" sees the same budget already partially consumed,
    # because both share the same Redis-backed counter for this path.
    assert client_to_instance_2.post(login_path).status_code == 200
    assert client_to_instance_1.post(login_path).status_code == 429
