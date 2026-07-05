"""
Integration tests for registration and login (routers/auth.py).

Critical cases covered:
- Successful registration issues the expected shape and role.
- First registered user becomes admin; subsequent ones default to analyst.
- Duplicate email registration is rejected with the standard error envelope.
- Login succeeds with correct credentials and fails with incorrect ones.
- Password/email validation constraints are enforced at the API boundary.
"""
from fastapi.testclient import TestClient

from app import models
from app.auth import pwd_context
from tests.conftest import auth_headers, register_user


def test_register_first_user_becomes_admin(client: TestClient):
    body = register_user(client, "first@example.com")
    assert body["email"] == "first@example.com"
    assert body["role"] == "admin"
    assert "id" in body
    assert "hashed_password" not in body  # never leak the hash


def test_register_second_user_becomes_analyst(client: TestClient):
    register_user(client, "first@example.com")
    body = register_user(client, "second@example.com")
    assert body["role"] == "analyst"


def test_register_duplicate_email_rejected(client: TestClient):
    register_user(client, "dupe@example.com")
    response = client.post(
        "/v1/auth/register", json={"email": "dupe@example.com", "password": "SecurePass123!"}
    )
    assert response.status_code == 409
    body = response.json()
    assert body["error"]["code"] == "email_already_registered"


def test_register_rejects_short_password(client: TestClient):
    response = client.post(
        "/v1/auth/register", json={"email": "weak@example.com", "password": "short"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_register_rejects_invalid_email(client: TestClient):
    response = client.post(
        "/v1/auth/register", json={"email": "not-an-email", "password": "SecurePass123!"}
    )
    assert response.status_code == 422


def test_login_success_returns_bearer_token(client: TestClient):
    register_user(client, "loginme@example.com")
    response = client.post(
        "/v1/auth/login", json={"email": "loginme@example.com", "password": "SecurePass123!"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 10


def test_login_wrong_password_rejected(client: TestClient):
    register_user(client, "loginme2@example.com")
    response = client.post(
        "/v1/auth/login", json={"email": "loginme2@example.com", "password": "WrongPassword1!"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


def test_login_unknown_email_rejected_with_same_error_as_wrong_password(client: TestClient):
    """
    Regression guard: the error must not reveal whether the email exists,
    which would let an attacker enumerate registered accounts.
    """
    response = client.post(
        "/v1/auth/login", json={"email": "nobody@example.com", "password": "WhoKnows123!"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


def test_protected_endpoint_rejects_missing_token(client: TestClient):
    response = client.get("/v1/fraud/alerts")
    assert response.status_code == 401


def test_protected_endpoint_rejects_garbage_token(client: TestClient):
    response = client.get("/v1/fraud/alerts", headers=auth_headers("not-a-real-jwt"))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_new_registrations_are_hashed_with_argon2(client: TestClient, db_session):
    """
    Dependency-drift regression guard: requirements.txt previously pinned
    passlib[bcrypt] while auth.py actually configured pbkdf2_sha256. The
    fix makes argon2 the default scheme for all new hashes.
    """
    register_user(client, "argon_check@example.com")
    user = db_session.query(models.User).filter(models.User.email == "argon_check@example.com").first()
    assert user.hashed_password.startswith("$argon2")


def test_legacy_pbkdf2_hash_still_authenticates_and_is_upgraded_on_login(
    client: TestClient, db_session
):
    """
    Rolling migration test: a user hashed under the previous default
    scheme (pbkdf2_sha256) must still be able to log in, and their stored
    hash must be transparently upgraded to argon2 as a side effect of that
    successful login — without a forced password reset.
    """
    legacy_hash = pwd_context.hash("SecurePass123!", scheme="pbkdf2_sha256")
    assert legacy_hash.startswith("$pbkdf2-sha256$")

    user = models.User(email="legacy_hash@example.com", hashed_password=legacy_hash, role="analyst")
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/v1/auth/login",
        json={"email": "legacy_hash@example.com", "password": "SecurePass123!"},
    )
    assert response.status_code == 200

    db_session.expire_all()
    refreshed = db_session.query(models.User).filter(models.User.email == "legacy_hash@example.com").first()
    assert refreshed.hashed_password.startswith("$argon2")
    assert refreshed.hashed_password != legacy_hash
