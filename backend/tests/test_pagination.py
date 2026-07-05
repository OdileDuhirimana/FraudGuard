"""
Tests for pagination/filtering/sorting on list endpoints
(API-05/API-06/API-07 findings from the audit).
"""
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def _admin_and_scores(client: TestClient, count: int) -> str:
    register_user(client, "pgadmin@example.com")
    admin_token = login_user(client, "pgadmin@example.com")
    for i in range(count):
        # Alternate risky/non-risky amounts so decisions vary across records.
        amount = 9000.0 if i % 2 == 0 else 5.0
        client.post(
            "/v1/fraud/score",
            json={"amount": amount, "mcc": "7995" if i % 2 == 0 else "5411"},
            headers=auth_headers(admin_token),
        )
    return admin_token


def test_alerts_pagination_respects_page_size(client: TestClient):
    token = _admin_and_scores(client, 6)
    response = client.get("/v1/fraud/alerts?page=1&page_size=2", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) <= 2
    assert body["meta"]["page"] == 1
    assert body["meta"]["page_size"] == 2


def test_alerts_page_size_is_capped_server_side(client: TestClient):
    token = _admin_and_scores(client, 3)
    response = client.get("/v1/fraud/alerts?page_size=99999", headers=auth_headers(token))
    assert response.status_code == 422  # exceeds le=200 constraint


def test_alerts_filter_by_decision(client: TestClient):
    token = _admin_and_scores(client, 6)
    response = client.get("/v1/fraud/alerts?decision=block", headers=auth_headers(token))
    assert response.status_code == 200
    for item in response.json()["items"]:
        assert item["decision"] == "block"


def test_alerts_include_eager_loaded_transaction_summary(client: TestClient):
    """
    PERF-02 regression guard: AlertRepository.list_paginated() eager-loads
    each alert's parent transaction via joinedload(Alert.transaction), and
    AlertOut serializes it as a nested `transaction` object. This asserts
    that data actually arrives in the response (i.e. the eager-load is
    load-bearing, not decorative) rather than only checking the HTTP
    status code.
    """
    token = _admin_and_scores(client, 6)
    response = client.get("/v1/fraud/alerts", headers=auth_headers(token))
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) > 0
    for item in items:
        assert item["transaction"] is not None
        assert item["transaction"]["id"] == item["transaction_id"]
        assert "amount" in item["transaction"]


def test_alerts_rejects_invalid_decision_filter(client: TestClient):
    token = _admin_and_scores(client, 1)
    response = client.get("/v1/fraud/alerts?decision=not_a_real_decision", headers=auth_headers(token))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_filter_value"


def test_admin_users_sorting_by_email(client: TestClient):
    register_user(client, "zz_admin@example.com")
    admin_token = login_user(client, "zz_admin@example.com")
    register_user(client, "aa_user@example.com")

    response = client.get("/v1/admin/users?sort=email", headers=auth_headers(admin_token))
    assert response.status_code == 200
    emails = [u["email"] for u in response.json()["items"]]
    assert emails == sorted(emails)


def test_admin_audit_filter_by_action(client: TestClient):
    register_user(client, "audit_admin@example.com")
    admin_token = login_user(client, "audit_admin@example.com")

    response = client.get("/v1/admin/audit?action=user_registered", headers=auth_headers(admin_token))
    assert response.status_code == 200
    for item in response.json()["items"]:
        assert item["action"] == "user_registered"


def test_admin_audit_includes_eager_loaded_actor_email(client: TestClient):
    """
    PERF-02 regression guard: AuditLogRepository.list_paginated() eager-
    loads the `actor` relationship via joinedload(AuditLog.actor), and
    AuditLogOut.actor_email is sourced from it. Asserts the data is
    actually populated, not just that the endpoint returns 200.
    """
    register_user(client, "audit_admin2@example.com")
    admin_token = login_user(client, "audit_admin2@example.com")

    response = client.get(
        "/v1/admin/audit?action=user_registered", headers=auth_headers(admin_token)
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) > 0
    assert any(item["actor_email"] == "audit_admin2@example.com" for item in items)
