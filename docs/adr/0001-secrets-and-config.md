# ADR 0001: Centralized configuration and the JWT secret naming incident

## Status
Accepted

## Context
The original codebase read environment variables ad hoc in four different
modules (`auth.py`, `database.py`, `main.py`, `security.py`), each with
slightly different fallback and fail-closed semantics. This produced a real
bug: `backend/.env.example` documented `JWT_SECRET`, but `auth.py` actually
read `JWT_SECRET_KEY`. Anyone who copied `.env.example` to `.env` and
trusted it would silently get a randomly generated, non-persistent JWT
secret in non-production environments (invalidating all issued tokens on
every restart), while production would correctly hard-fail — but only
because production enforcement happened to check the right variable name.

## Decision
Introduce a single `app/config.py` module with one `Settings` dataclass
that is the only place environment variables are read. Every other module
imports `settings` instead of calling `os.environ.get(...)` directly. This
doesn't prevent every possible misconfiguration, but it collapses "where do
I check what an env var does" down to one file, and makes the
fail-closed-in-production behavior consistent and auditable in one place
instead of four.

## Consequences
- `.env.example` and `config.py` must be kept in sync by construction —
  there is exactly one file defining what each variable means.
- Settings are read once at process start (module-level `settings =
  Settings()`), not per-request. This means environment variable changes
  require a process restart to take effect, which is the expected and
  desired behavior for secrets and infra config.
- Tests must set environment variables before importing any `app.*` module
  (see `tests/conftest.py`), since `Settings()` is evaluated at import time.
