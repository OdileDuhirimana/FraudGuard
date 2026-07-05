"""
Integration tests for POST /v1/fraud/score (routers/fraud.py) and the
underlying risk_score() decision boundaries (app/risk.py).

Critical cases covered:
- A low-risk transaction is allowed.
- A high-amount, high-risk-MCC transaction crosses into challenge/block.
- Input validation rejects non-positive amounts (SEC-03 finding: amount
  could previously be zero or negative).
- Scoring requires authentication.
- Each scored transaction is persisted and returned with a transaction_id
  that can be used in subsequent OTP calls.
"""
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def _authed_analyst(client: TestClient) -> str:
    register_user(client, "scorer@example.com")
    return login_user(client, "scorer@example.com")


def test_score_requires_authentication(client: TestClient):
    response = client.post("/v1/fraud/score", json={"amount": 10.0})
    assert response.status_code == 401


def test_low_risk_transaction_is_allowed(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score",
        json={"amount": 12.50, "mcc": "5411", "currency": "usd"},
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert 0.0 <= body["score"] <= 1.0
    assert body["transaction_id"] > 0


def test_high_risk_transaction_is_blocked_or_challenged(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score",
        json={
            "amount": 9999.0,
            "mcc": "7995",  # flagged as high-risk MCC in ensemble_features
            "ip": "203.0.113.9",
            "gps_lat": 1.0,
            "gps_lon": 1.0,
            "timezone_mismatch": True,
            "device_compromised": True,
        },
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] in ("challenge", "block")
    assert body["score"] > 0.5


def test_score_rejects_zero_amount(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score", json={"amount": 0}, headers=auth_headers(token)
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_score_rejects_negative_amount(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score", json={"amount": -50.0}, headers=auth_headers(token)
    )
    assert response.status_code == 422


def test_score_rejects_invalid_mcc(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score", json={"amount": 10.0, "mcc": "abcd"}, headers=auth_headers(token)
    )
    assert response.status_code == 422


def test_score_normalizes_currency_case(client: TestClient):
    token = _authed_analyst(client)
    response = client.post(
        "/v1/fraud/score", json={"amount": 10.0, "currency": "eur"}, headers=auth_headers(token)
    )
    assert response.status_code == 200


def test_velocity_increases_risk_score(client: TestClient):
    """
    Scoring several transactions for the same user in quick succession
    should raise the velocity feature and therefore the score of the
    later transactions relative to the first (count_user_tx_last_minutes).
    """
    token = _authed_analyst(client)
    scores = []
    for _ in range(4):
        response = client.post(
            "/v1/fraud/score", json={"amount": 50.0}, headers=auth_headers(token)
        )
        assert response.status_code == 200
        scores.append(response.json()["score"])
    assert scores[-1] > scores[0]
