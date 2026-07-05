"""
Shared pytest fixtures for the FraudGuard test suite.

Design decisions:

1. Environment variables required by app.config.Settings (ENV,
   CORS_ALLOWED_ORIGINS, JWT_SECRET_KEY) are set *before* any `app.*`
   module is imported, at collection time, via `pytest_configure` below.
   Settings are read once at import time by design (see config.py's
   module-level `settings = Settings()`), so setting env vars inside a
   fixture that runs after import would be too late.

2. Each test function gets its own fresh SQLite database (file-based, in a
   temp directory) with the full schema created via SQLAlchemy metadata
   directly — not via Alembic — so the test suite doesn't depend on
   migration state and stays fast. Alembic's own upgrade/downgrade path is
   exercised separately (see tests/test_migrations.py), which is what
   actually proves the migrations are correct.

3. FastAPI's dependency_overrides mechanism swaps `get_db` for a
   test-scoped session factory, so route handlers use the isolated test
   database without any code changes to the app itself.
"""
from __future__ import annotations

import os

# Must happen before any `app.*` import anywhere in the test session.
os.environ.setdefault("ENV", "development")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("RATE_LIMIT_DEFAULT_PER_MINUTE", "1000")
os.environ.setdefault("RATE_LIMIT_AUTH_PER_MINUTE", "1000")
os.environ.setdefault("RATE_LIMIT_OTP_PER_MINUTE", "1000")

import uuid
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401  (registers tables on Base.metadata)
from app.database import Base, get_db, get_session_factory
from app.main import app


@pytest.fixture()
def db_engine(tmp_path):
    db_path = tmp_path / f"test_{uuid.uuid4().hex}.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_engine) -> Generator[TestClient, None, None]:
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    # Background tasks (e.g. the async fraud-ring graph job in
    # routers/fraud.py) open their own session directly from a session
    # factory rather than via get_db(), since they run after the request/
    # response cycle has already ended. Overriding get_session_factory the
    # same way get_db is overridden ensures that code path also operates
    # against this test's isolated database instead of the real one.
    app.dependency_overrides[get_session_factory] = lambda: TestSessionLocal
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def register_user(client: TestClient, email: str, password: str = "SecurePass123!") -> dict:
    response = client.post("/v1/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201, response.text
    return response.json()


def login_user(client: TestClient, email: str, password: str = "SecurePass123!") -> str:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_token(client: TestClient) -> str:
    # First registered user is always promoted to admin (see routers/auth.py).
    register_user(client, "admin@example.com")
    return login_user(client, "admin@example.com")


@pytest.fixture()
def analyst_token(client: TestClient, admin_token: str) -> str:
    # admin_token is consumed as a fixture dependency purely to guarantee
    # this user is NOT the first registered user (so it gets the default
    # "analyst" role instead of being auto-promoted to admin).
    register_user(client, "analyst@example.com")
    return login_user(client, "analyst@example.com")
