"""
Integration tests for POST /v1/auth/logout and server-side JWT revocation
(services/tokens.py, models.TokenBlacklist).

Critical cases covered:
- Logging out invalidates the specific token used to log out.
- A revoked token is rejected on every subsequent authenticated request,
  not just a hardcoded "logout succeeded" response.
- Logging out twice with the same (already-revoked) token is rejected,
  not silently accepted.
- Logging out does not affect a *different* token issued for the same
  user (i.e. this is single-session revocation, not a blunt
  invalidate-everything-for-this-user operation) — matches the documented
  behavior in routers/auth.py::logout.
"""
from fastapi.testclient import TestClient

from app import models
from tests.conftest import auth_headers, login_user, register_user


def test_logout_revokes_the_current_token(client: TestClient):
    register_user(client, "logout1@example.com")
    token = login_user(client, "logout1@example.com")

    logout_response = client.post("/v1/auth/logout", headers=auth_headers(token))
    assert logout_response.status_code == 200
    assert logout_response.json()["status"] == "logged_out"

    # The same token must now be rejected everywhere, not just accepted
    # once more before "really" logging out.
    follow_up = client.get("/v1/fraud/alerts", headers=auth_headers(token))
    assert follow_up.status_code == 401
    assert follow_up.json()["error"]["code"] == "token_revoked"


def test_logout_twice_with_same_token_is_rejected(client: TestClient):
    register_user(client, "logout2@example.com")
    token = login_user(client, "logout2@example.com")

    assert client.post("/v1/auth/logout", headers=auth_headers(token)).status_code == 200
    second_attempt = client.post("/v1/auth/logout", headers=auth_headers(token))
    assert second_attempt.status_code == 401
    assert second_attempt.json()["error"]["code"] == "token_revoked"


def test_logout_does_not_affect_a_different_token_for_the_same_user(client: TestClient):
    register_user(client, "logout3@example.com")
    token_a = login_user(client, "logout3@example.com")
    token_b = login_user(client, "logout3@example.com")
    assert token_a != token_b  # each login mints a fresh jti

    client.post("/v1/auth/logout", headers=auth_headers(token_a))

    # token_a is now dead...
    assert client.get("/v1/fraud/alerts", headers=auth_headers(token_a)).status_code == 401
    # ...but token_b, a separate session for the same user, still works.
    assert client.get("/v1/fraud/alerts", headers=auth_headers(token_b)).status_code == 200


def test_logout_requires_authentication(client: TestClient):
    response = client.post("/v1/auth/logout")
    assert response.status_code == 401


def test_logout_persists_a_blacklist_row(client: TestClient, db_session):
    register_user(client, "logout4@example.com")
    token = login_user(client, "logout4@example.com")

    client.post("/v1/auth/logout", headers=auth_headers(token))

    count = db_session.query(models.TokenBlacklist).count()
    assert count == 1
