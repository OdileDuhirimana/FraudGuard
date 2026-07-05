"""
Tests for the dependency-checking /health endpoint and the standardized
error envelope (OBS-04 and API-04/ERR-01 findings from the audit).
"""
from fastapi.testclient import TestClient


def test_health_reports_ok_with_working_database(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert any(dep["name"] == "database" and dep["healthy"] for dep in body["dependencies"])


def test_root_endpoint_reports_api_prefix(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["api_prefix"] == "/v1"


def test_404_uses_standard_error_envelope(client: TestClient):
    response = client.get("/v1/does/not/exist")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    assert "code" in body["error"]
    assert "message" in body["error"]


def test_validation_error_uses_standard_envelope_with_details(client: TestClient):
    response = client.post("/v1/auth/register", json={"email": "bad", "password": "short"})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert isinstance(body["error"]["details"], list)
    assert len(body["error"]["details"]) > 0
