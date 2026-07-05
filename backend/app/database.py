from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

if not settings.database_url and settings.is_production:
    raise RuntimeError("DATABASE_URL must be set in production")

SQLALCHEMY_DATABASE_URL = settings.database_url or "sqlite:///./fraudguard.db"

if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif SQLALCHEMY_DATABASE_URL.startswith("postgresql://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Request-scoped DB session dependency. On any exception raised while the
    session is open, roll back before closing so a failed request never
    leaves a half-committed transaction pinned to a pooled connection.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_session_factory():
    """
    Exposes the active session *factory* itself (not a session) as a
    FastAPI dependency, for the narrow case of code that must open its own
    session outside the request-scoped get_db() lifecycle — concretely,
    routers/fraud.py's background graph job, which runs after the response
    has already been sent and cannot depend on a request-scoped session
    still being open.

    Why this is a dependency rather than importing SessionLocal directly:
    tests override `get_db` (see tests/conftest.py) to point at an
    isolated per-test SQLite database via FastAPI's `dependency_overrides`
    mechanism. Code that imports `SessionLocal` directly bypasses that
    override entirely and would silently operate against the real
    application database even under test — overriding this dependency the
    same way keeps the background-job code path testable without a special
    case.
    """
    return SessionLocal
