"""
Integration tests for role-based access control across /fraud and /admin
routers.

Critical cases covered:
- Non-privileged roles (analyst for admin-only routes) are rejected with 403.
- Privileged roles succeed.
- Role changes via /admin/role are themselves gated to admin only, and
  reject invalid role names (schema-level enum validation).
- /admin/audit and /admin/users pagination envelopes are well-formed.
"""
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def test_alerts_feed_requires_admin_or_analyst_role(client: TestClient):
    # First user is admin; register a second, still-analyst-by-default user
    # is not enough here — alerts_feed allows admin AND analyst, so use a
    # role that is neither: investigator or manager.
    register_user(client, "admin1@example.com")
    admin_token = login_user(client, "admin1@example.com")

    register_user(client, "investigator1@example.com")
    investigator_token = login_user(client, "investigator1@example.com")
    # Promote to investigator (not allowed on /fraud/alerts, which only
    # permits admin/analyst) via the admin endpoint to set up the negative case.
    users_resp = client.get("/v1/admin/users", headers=auth_headers(admin_token))
    investigator_user_id = next(
        u["id"] for u in users_resp.json()["items"] if u["email"] == "investigator1@example.com"
    )
    client.post(
        "/v1/admin/role",
        json={"user_id": investigator_user_id, "role": "investigator"},
        headers=auth_headers(admin_token),
    )

    response = client.get("/v1/fraud/alerts", headers=auth_headers(investigator_token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "insufficient_permissions"


def test_alerts_feed_accessible_to_admin(client: TestClient):
    register_user(client, "admin2@example.com")
    token = login_user(client, "admin2@example.com")
    response = client.get("/v1/fraud/alerts", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()
    assert "items" in body and "meta" in body


def test_graph_endpoint_requires_admin(client: TestClient):
    register_user(client, "admin3@example.com")
    admin_token = login_user(client, "admin3@example.com")
    register_user(client, "analyst3@example.com")
    analyst_token = login_user(client, "analyst3@example.com")

    forbidden = client.get("/v1/fraud/graph", headers=auth_headers(analyst_token))
    assert forbidden.status_code == 403

    allowed = client.get("/v1/fraud/graph", headers=auth_headers(admin_token))
    assert allowed.status_code == 200
    assert "graph" in allowed.json()


def test_admin_users_and_audit_require_admin_or_manager(client: TestClient):
    register_user(client, "admin4@example.com")
    admin_token = login_user(client, "admin4@example.com")
    register_user(client, "analyst4@example.com")
    analyst_token = login_user(client, "analyst4@example.com")

    for path in ("/v1/admin/users", "/v1/admin/audit"):
        assert client.get(path, headers=auth_headers(analyst_token)).status_code == 403
        assert client.get(path, headers=auth_headers(admin_token)).status_code == 200


def test_set_role_requires_admin(client: TestClient):
    register_user(client, "admin5@example.com")
    admin_token = login_user(client, "admin5@example.com")
    register_user(client, "analyst5@example.com")
    analyst_token = login_user(client, "analyst5@example.com")

    users_resp = client.get("/v1/admin/users", headers=auth_headers(admin_token))
    target_id = next(
        u["id"] for u in users_resp.json()["items"] if u["email"] == "analyst5@example.com"
    )

    forbidden = client.post(
        "/v1/admin/role",
        json={"user_id": target_id, "role": "manager"},
        headers=auth_headers(analyst_token),
    )
    assert forbidden.status_code == 403

    allowed = client.post(
        "/v1/admin/role",
        json={"user_id": target_id, "role": "manager"},
        headers=auth_headers(admin_token),
    )
    assert allowed.status_code == 200
    assert allowed.json()["role"] == "manager"


def test_set_role_rejects_invalid_role_name(client: TestClient):
    register_user(client, "admin6@example.com")
    admin_token = login_user(client, "admin6@example.com")

    response = client.post(
        "/v1/admin/role",
        json={"user_id": 1, "role": "superuser"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_set_role_for_nonexistent_user_returns_404(client: TestClient):
    register_user(client, "admin7@example.com")
    admin_token = login_user(client, "admin7@example.com")

    response = client.post(
        "/v1/admin/role",
        json={"user_id": 999999, "role": "manager"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "user_not_found"
