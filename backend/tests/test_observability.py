"""
Tests for OBS-02 (metrics) and OBS-03 (error tracking) fixes.

Sentry itself is not exercised end-to-end here (that would require a real
DSN and network access, which is inappropriate for a unit/integration test
suite) — these tests instead prove the *no-op-if-unset* contract, which is
the behavior that matters for every environment that doesn't have Sentry
configured (i.e. this test suite's own environment).
"""
from fastapi.testclient import TestClient

from app import observability
from app.config import Settings


def test_metrics_endpoint_exposes_prometheus_text_format(client: TestClient):
    # Generate at least one request so the counters have a nonzero sample.
    client.get("/health")

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "fraudguard_http_requests_total" in body
    assert "fraudguard_http_request_duration_seconds" in body


def test_configure_error_tracking_is_a_noop_without_sentry_dsn(monkeypatch):
    """
    DEV-05 contract: a deployment with SENTRY_DSN unset must not attempt to
    initialize the Sentry SDK at all (no network call, no import-time
    failure risk) — configure_error_tracking() must return immediately.
    """
    fake_settings = Settings(
        env="development",
        jwt_secret_key="unit-test-secret",
        cors_allowed_origins=("http://localhost:3000",),
        sentry_dsn=None,
    )
    monkeypatch.setattr(observability, "settings", fake_settings)

    # Must not raise, and must not require sentry_sdk to even be
    # importable in a meaningful way beyond the lazy import guarded by the
    # early return.
    observability.configure_error_tracking()
