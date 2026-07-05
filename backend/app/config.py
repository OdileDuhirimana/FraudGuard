"""
Centralized application configuration.

Why this exists: environment-variable reads were previously scattered across
auth.py, database.py, main.py, and security.py, each with slightly different
fallback/fail-closed semantics. That made it easy to introduce mismatches
(see: the JWT_SECRET vs JWT_SECRET_KEY incident documented in
docs/adr/0001-secrets-and-config.md). A single Settings object gives one
place to reason about "what happens if this env var is missing," and makes
the app's configuration surface testable and injectable instead of being
read ad hoc at import time.

Assumption: this stays a lightweight dataclass rather than pydantic-settings
to avoid adding a new dependency for a small, already-curated project.
"""
from __future__ import annotations

import os
import secrets as _secrets
from dataclasses import dataclass, field


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    env: str = field(default_factory=lambda: os.environ.get("ENV", "development"))
    port: int = field(default_factory=lambda: int(os.environ.get("PORT", "8000")))

    database_url: str | None = field(
        default_factory=lambda: os.environ.get("DATABASE_URL") or os.environ.get("FG_DB_URL")
    )

    jwt_secret_key: str = field(default_factory=lambda: _resolve_jwt_secret())
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8

    aes_key_b64: str | None = field(default_factory=lambda: os.environ.get("FG_AES_KEY"))

    cors_allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: _resolve_cors_origins()
    )

    rate_limit_default_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("RATE_LIMIT_DEFAULT_PER_MINUTE", "300"))
    )
    rate_limit_auth_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("RATE_LIMIT_AUTH_PER_MINUTE", "10"))
    )
    rate_limit_otp_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("RATE_LIMIT_OTP_PER_MINUTE", "5"))
    )

    ml_artifacts_path: str | None = field(default_factory=lambda: os.environ.get("FG_ML_ARTIFACTS"))

    # Selects which scorer POST /fraud/score uses. "heuristic" (default)
    # is app/risk.py's hand-weighted sum, unchanged from before this
    # setting existed — every existing test asserting specific heuristic
    # thresholds/behavior continues to exercise exactly that path.
    # "isolation_forest" switches to the trained model in
    # app/ml/trained_scorer.py (see docs/ml_evaluation.md for its real,
    # measured precision/recall/AUC — not asserted to be a drop-in
    # equivalent to the heuristic's threshold calibration).
    risk_scorer_backend: str = field(
        default_factory=lambda: os.environ.get("RISK_SCORER_BACKEND", "heuristic")
    )

    # Error tracking (DEV-05 fix). Optional by design: a demo/portfolio
    # deployment without a Sentry project configured must still boot and
    # run identically — see observability.py::configure_error_tracking for
    # the no-op-if-unset behavior this setting drives.
    sentry_dsn: str | None = field(default_factory=lambda: os.environ.get("SENTRY_DSN"))

    # Optional Redis backend for rate limiting (see middleware.py). Falls
    # back to the in-memory limiter when unset — see
    # docs/adr/0004-rate-limiting.md's update for the tradeoff.
    redis_url: str | None = field(default_factory=lambda: os.environ.get("REDIS_URL"))

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def require_aes_key(self) -> bool:
        """
        In production, encryption-at-rest for sensitive JSON blobs
        (behavioral biometrics, device fingerprints) must not silently
        no-op. See docs/adr/0002-encryption-at-rest.md for the tradeoff.
        """
        return self.is_production


def _resolve_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET_KEY")
    if secret:
        return secret
    if os.environ.get("ENV", "development").lower() == "production":
        raise RuntimeError("JWT_SECRET_KEY env var must be set in production")
    # Non-production convenience fallback: random per-process secret.
    # This intentionally invalidates tokens across restarts in dev, which
    # is an acceptable tradeoff for never letting a demo secret leak.
    return _secrets.token_hex(32)


def _resolve_cors_origins() -> tuple[str, ...]:
    """
    Fail-closed CORS: unlike the previous implementation, an unset or empty
    CORS_ALLOWED_ORIGINS no longer defaults to "*". Production requires an
    explicit allow-list; non-production defaults to the local dev frontend
    origin only. See docs/adr/0003-cors-policy.md.
    """
    raw = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    origins = tuple(origin.strip() for origin in raw.split(",") if origin.strip())
    if origins:
        if "*" in origins:
            raise RuntimeError(
                "CORS_ALLOWED_ORIGINS must not contain '*' — provide an explicit "
                "comma-separated allow-list of origins."
            )
        return origins
    if os.environ.get("ENV", "development").lower() == "production":
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must be set to an explicit allow-list in production"
        )
    return ("http://localhost:3000",)


settings = Settings()
