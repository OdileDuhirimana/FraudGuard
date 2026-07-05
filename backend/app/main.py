from fastapi import Depends, FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .errors import register_exception_handlers
from .health import build_health_report
from .logging_config import configure_logging, get_logger
from .middleware import RateLimitMiddleware, build_rate_limit_kwargs
from .observability import instrument_app
from .routers import admin as admin_router
from .routers import auth as auth_router
from .routers import fraud as fraud_router

configure_logging()
logger = get_logger("fraudguard.main")

app = FastAPI(
    title="FraudGuard ML API",
    version="1.0.0",
    description=(
        "Fraud-scoring backend API. See /docs for interactive OpenAPI docs "
        "and README.md for architecture, known limitations, and what is "
        "mocked vs. real in the current implementation."
    ),
)

register_exception_handlers(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_allowed_origins),
    # SECURITY FIX: this API has no cookie-based session anywhere — every
    # authenticated request carries its JWT in an explicit `Authorization`
    # header (see auth.py's OAuth2PasswordBearer), never an ambient
    # browser-managed cookie. `allow_credentials=True` (which governs
    # whether the browser attaches/exposes cookies and other ambient
    # credentials on cross-origin requests) was therefore both unnecessary
    # and the exact precondition CSRF attacks rely on — a bug the code
    # review correctly flagged as "allow_credentials=True with no CSRF
    # protection and no justification". Setting this to False removes the
    # CSRF attack surface structurally (a forged cross-site request cannot
    # make the victim's browser attach a bearer token it doesn't have
    # ambient access to) rather than bolting on a CSRF-token mechanism this
    # API's auth model doesn't need. See docs/adr/0005-csrf-and-credentials.md.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware, **build_rate_limit_kwargs())

# OBS-02/OBS-03 FIX: wires a `/metrics` endpoint (Prometheus text format)
# and, if SENTRY_DSN is configured, error tracking — see observability.py
# for why a hand-rolled metrics middleware was used instead of
# prometheus-fastapi-instrumentator (dependency conflict with this
# project's pinned FastAPI/Starlette versions) and why Sentry is a
# no-op-if-unset integration rather than a hard requirement.
instrument_app(app)

API_V1_PREFIX = "/v1"

app.include_router(auth_router.router, prefix=f"{API_V1_PREFIX}/auth", tags=["auth"])
app.include_router(fraud_router.router, prefix=f"{API_V1_PREFIX}/fraud", tags=["fraud"])
app.include_router(admin_router.router, prefix=f"{API_V1_PREFIX}/admin", tags=["admin"])


@app.on_event("startup")
def on_startup() -> None:
    logger.info("app_startup", extra={"env": settings.env, "version": app.version})


@app.get("/", tags=["meta"])
def root():
    return {"name": "FraudGuard ML API", "status": "ok", "api_prefix": API_V1_PREFIX}


@app.get("/health", status_code=status.HTTP_200_OK, tags=["meta"])
def health(db: Session = Depends(get_db)):
    """
    Readiness probe: verifies actual dependency connectivity (database)
    rather than only confirming the process is running. Returns 200 with
    status "degraded" (not a 5xx) when a dependency is unhealthy, so
    orchestrator health-check tooling can distinguish "process crashed"
    from "process up but a dependency is down" — the response body carries
    the detail either way.
    """
    return build_health_report(db)
