"""
Integration tests for POST /v1/fraud/feedback ownership enforcement.

This file directly targets a confirmed code-review finding: `/fraud/feedback`
checked only that the referenced transaction_id existed, never that the
caller was authorized to attach feedback to it — the same broken-access-
control bug class the OTP endpoints were previously fixed for (see
test_otp.py). The fix reuses the same shared
`_require_transaction_ownership` helper as otp_init/otp_verify instead of
re-deriving the rule a third time.
"""
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def _score_a_transaction(client: TestClient, token: str, amount: float = 25.0) -> int:
    response = client.post(
        "/v1/fraud/score", json={"amount": amount}, headers=auth_headers(token)
    )
    assert response.status_code == 200
    return response.json()["transaction_id"]


def test_feedback_requires_ownership(client: TestClient):
    register_user(client, "fb_owner@example.com")
    owner_token = login_user(client, "fb_owner@example.com")
    tx_id = _score_a_transaction(client, owner_token)

    register_user(client, "fb_stranger@example.com")
    stranger_token = login_user(client, "fb_stranger@example.com")

    response = client.post(
        "/v1/fraud/feedback",
        json={"transaction_id": tx_id, "label": True},
        headers=auth_headers(stranger_token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "not_authorized_for_transaction"


def test_feedback_succeeds_for_owner(client: TestClient):
    register_user(client, "fb_owner2@example.com")
    token = login_user(client, "fb_owner2@example.com")
    tx_id = _score_a_transaction(client, token)

    response = client.post(
        "/v1/fraud/feedback",
        json={"transaction_id": tx_id, "label": False},
        headers=auth_headers(token),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "recorded"


def test_admin_can_submit_feedback_for_any_transaction(client: TestClient):
    register_user(client, "fb_admin@example.com")  # first user -> admin
    admin_token = login_user(client, "fb_admin@example.com")

    register_user(client, "fb_someone@example.com")
    someone_token = login_user(client, "fb_someone@example.com")
    tx_id = _score_a_transaction(client, someone_token)

    response = client.post(
        "/v1/fraud/feedback",
        json={"transaction_id": tx_id, "label": True},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 201


def test_feedback_for_nonexistent_transaction_returns_404(client: TestClient):
    register_user(client, "fb_owner3@example.com")
    token = login_user(client, "fb_owner3@example.com")

    response = client.post(
        "/v1/fraud/feedback",
        json={"transaction_id": 999999, "label": True},
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "transaction_not_found"
