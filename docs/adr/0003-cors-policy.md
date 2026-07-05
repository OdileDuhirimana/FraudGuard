# ADR 0003: Fail-closed CORS with an explicit allow-list

## Status
Accepted (supersedes a prior decision recorded in commit history)

## Context
Git history shows this project's CORS policy was tightened and then
deliberately loosened again: commit `4b8dea4` ("enforce JWT_SECRET_KEY in
prod and restrict CORS origins") was followed by `e8afd80` ("remove CORS
env var — app defaults to open for public demo API"). The resulting
behavior — `CORS_ALLOWED_ORIGINS` defaulting to `"*"` while
`allow_credentials=True` is also set — is a configuration most browsers and
security scanners flag, and one that a hiring-committee-level code review
correctly identified as a regression, not a feature.

The original justification (a public demo API with no cookie-based
session) was reasonable in isolation, but was never documented as a
deliberate, scoped decision in the code — it just looked like an
open-CORS bug to anyone reading `main.py` cold.

## Decision
`app/config.py`'s `_resolve_cors_origins()` now fails closed:
- An explicit, non-wildcard, comma-separated allow-list is required in
  production; the app raises `RuntimeError` at startup otherwise.
- A wildcard (`"*"`) is rejected outright in `CORS_ALLOWED_ORIGINS` at any
  environment — if broad access is genuinely desired, that has to be an
  explicit list of real origins, not a wildcard.
- Non-production defaults to `http://localhost:3000` only (the expected
  local frontend dev origin), not `"*"`.

## Consequences
- A demo deployment must set `CORS_ALLOWED_ORIGINS` to whatever frontend
  origin(s) actually call the API before it will boot in production. This
  is a deliberate deployment-time cost in exchange for the app never
  silently running with an open, credentialed CORS policy again.
- If a genuinely public, credential-less API is wanted in the future, that
  should be a distinct code path (e.g. `allow_credentials=False` with a
  wildcard), not the default for a Bearer-token API that also happens to
  set `allow_credentials=True`.
