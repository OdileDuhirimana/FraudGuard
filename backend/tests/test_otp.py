"""
Integration tests for the OTP MFA flow (routers/fraud.py otp_init/otp_verify).

This file directly targets Critical Issue #2 from the code review and
portfolio evaluation: `otp_verify` previously performed no ownership check,
letting any authenticated user attempt to verify OTP codes against another
user's transaction. test_otp_verify_rejects_non_owner is the regression
test that proves the fix; it must fail against the old, unpatched
otp_verify implementation and pass against the current one.
"""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app import models
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def _score_a_transaction(client: TestClient, token: str, amount: float = 25.0) -> int:
    response = client.post(
        "/v1/fraud/score", json={"amount": amount}, headers=auth_headers(token)
    )
    assert response.status_code == 200
    return response.json()["transaction_id"]


def _read_otp_code(db_session: Session, transaction_id: int) -> str:
    challenge = (
        db_session.query(models.OTPChallenge)
        .filter(models.OTPChallenge.transaction_id == transaction_id)
        .order_by(models.OTPChallenge.created_at.desc())
        .first()
    )
    assert challenge is not None
    return challenge.code


def test_otp_init_requires_ownership(client: TestClient):
    register_user(client, "owner@example.com")
    owner_token = login_user(client, "owner@example.com")
    tx_id = _score_a_transaction(client, owner_token)

    register_user(client, "stranger@example.com")
    stranger_token = login_user(client, "stranger@example.com")

    response = client.post(
        "/v1/fraud/otp/init",
        json={"transaction_id": tx_id},
        headers=auth_headers(stranger_token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "not_authorized_for_transaction"


def test_otp_init_succeeds_for_owner(client: TestClient):
    register_user(client, "owner2@example.com")
    token = login_user(client, "owner2@example.com")
    tx_id = _score_a_transaction(client, token)

    response = client.post(
        "/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(token)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "sent"


def test_otp_verify_rejects_non_owner(client: TestClient, db_session: Session):
    """
    Regression test for the broken-access-control bug: otp_verify must
    enforce the same ownership check as otp_init. Before the fix, this
    request would have proceeded to compare the guessed code against the
    real one instead of being rejected outright by authorization.
    """
    register_user(client, "victim@example.com")
    victim_token = login_user(client, "victim@example.com")
    tx_id = _score_a_transaction(client, victim_token)

    init_response = client.post(
        "/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(victim_token)
    )
    assert init_response.status_code == 200
    real_code = _read_otp_code(db_session, tx_id)

    register_user(client, "attacker@example.com")
    attacker_token = login_user(client, "attacker@example.com")

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": real_code},
        headers=auth_headers(attacker_token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "not_authorized_for_transaction"


def test_otp_verify_succeeds_for_owner_with_correct_code(client: TestClient, db_session: Session):
    register_user(client, "owner3@example.com")
    token = login_user(client, "owner3@example.com")
    tx_id = _score_a_transaction(client, token)

    client.post("/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(token))
    code = _read_otp_code(db_session, tx_id)

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": code},
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "verified"


def test_otp_verify_rejects_wrong_code_for_owner(client: TestClient):
    register_user(client, "owner4@example.com")
    token = login_user(client, "owner4@example.com")
    tx_id = _score_a_transaction(client, token)

    client.post("/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(token))

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": "000000"},
        headers=auth_headers(token),
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_code"


def test_otp_verify_rejects_malformed_code(client: TestClient):
    register_user(client, "owner5@example.com")
    token = login_user(client, "owner5@example.com")
    tx_id = _score_a_transaction(client, token)

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": "abc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_otp_verify_for_nonexistent_transaction_returns_404(client: TestClient):
    register_user(client, "owner6@example.com")
    token = login_user(client, "owner6@example.com")

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": 999999, "code": "123456"},
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "transaction_not_found"


def test_otp_verify_rejects_expired_code(client: TestClient, db_session: Session):
    """
    Regression test for Critical Issue #1 (code review): OTPChallenge
    previously had no expiry at all, so a correct 6-digit code stayed
    valid indefinitely. This forces a challenge into the past directly at
    the DB layer (the only way to deterministically test expiry without a
    real clock-dependent sleep) and asserts verify rejects it even though
    the code itself is correct.
    """
    register_user(client, "expiry_owner@example.com")
    token = login_user(client, "expiry_owner@example.com")
    tx_id = _score_a_transaction(client, token)

    client.post("/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(token))
    challenge = (
        db_session.query(models.OTPChallenge)
        .filter(models.OTPChallenge.transaction_id == tx_id)
        .order_by(models.OTPChallenge.created_at.desc())
        .first()
    )
    code = challenge.code
    challenge.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db_session.add(challenge)
    db_session.commit()

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": code},
        headers=auth_headers(token),
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "code_expired"


def test_otp_verify_accepts_code_still_within_ttl(client: TestClient, db_session: Session):
    """Sanity counterpart: a challenge within its TTL must still verify."""
    register_user(client, "not_expired_owner@example.com")
    token = login_user(client, "not_expired_owner@example.com")
    tx_id = _score_a_transaction(client, token)

    client.post("/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(token))
    code = _read_otp_code(db_session, tx_id)

    response = client.post(
        "/v1/fraud/otp/verify",
        json={"transaction_id": tx_id, "code": code},
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "verified"


def test_admin_can_init_otp_for_any_transaction(client: TestClient):
    register_user(client, "admin_otp@example.com")  # first user -> admin
    admin_token = login_user(client, "admin_otp@example.com")

    register_user(client, "someone@example.com")
    someone_token = login_user(client, "someone@example.com")
    tx_id = _score_a_transaction(client, someone_token)

    response = client.post(
        "/v1/fraud/otp/init", json={"transaction_id": tx_id}, headers=auth_headers(admin_token)
    )
    assert response.status_code == 200
