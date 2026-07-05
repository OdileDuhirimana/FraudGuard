"""
Tests for the async fraud-ring graph job (SCALE-02 fix): POST /v1/fraud/graph/jobs
and GET /v1/fraud/graph/jobs/{job_id}, plus the now-paginated synchronous
GET /v1/fraud/graph (API-05 fix).

BackgroundTasks run synchronously (before the response is returned) under
FastAPI's TestClient when used as a context manager, per Starlette's test
transport — so these tests can assert the job reaches "done" without
needing to poll or sleep.
"""
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def _admin_with_transactions(client: TestClient, count: int = 3) -> str:
    register_user(client, "graph_admin@example.com")
    admin_token = login_user(client, "graph_admin@example.com")
    for i in range(count):
        client.post(
            "/v1/fraud/score",
            json={"amount": 42.0 + i, "device_id": f"dev-{i}", "ip": f"10.0.0.{i}"},
            headers=auth_headers(admin_token),
        )
    return admin_token


def test_graph_endpoint_is_paginated(client: TestClient):
    token = _admin_with_transactions(client, count=3)
    response = client.get("/v1/fraud/graph?page=1&page_size=2", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()
    assert "graph" in body
    assert "meta" in body
    assert body["meta"]["page_size"] == 2
    assert body["transactions_considered"] <= 2


def test_graph_endpoint_requires_admin_role(client: TestClient):
    register_user(client, "graph_first_admin@example.com")  # consumes the first-user-is-admin slot
    register_user(client, "graph_analyst@example.com")
    analyst_token = login_user(client, "graph_analyst@example.com")
    response = client.get("/v1/fraud/graph", headers=auth_headers(analyst_token))
    assert response.status_code == 403


def test_graph_job_runs_to_completion_and_is_pollable(client: TestClient):
    token = _admin_with_transactions(client, count=3)

    create_response = client.post("/v1/fraud/graph/jobs", headers=auth_headers(token))
    assert create_response.status_code == 202
    job_id = create_response.json()["job_id"]
    assert create_response.json()["status"] in ("pending", "running", "done")

    status_response = client.get(f"/v1/fraud/graph/jobs/{job_id}", headers=auth_headers(token))
    assert status_response.status_code == 200
    body = status_response.json()
    assert body["job_id"] == job_id
    assert body["status"] == "done"
    assert body["transactions_considered"] >= 3
    assert "graph" in body
    assert "nodes" in body["graph"]


def test_graph_job_creation_requires_admin_role(client: TestClient):
    register_user(client, "graph_job_first_admin@example.com")  # consumes the first-user-is-admin slot
    register_user(client, "graph_job_analyst@example.com")
    analyst_token = login_user(client, "graph_job_analyst@example.com")
    response = client.post("/v1/fraud/graph/jobs", headers=auth_headers(analyst_token))
    assert response.status_code == 403


def test_graph_job_status_for_unknown_id_returns_404(client: TestClient):
    register_user(client, "graph_job_admin2@example.com")
    admin_token = login_user(client, "graph_job_admin2@example.com")
    response = client.get("/v1/fraud/graph/jobs/999999", headers=auth_headers(admin_token))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "graph_job_not_found"
