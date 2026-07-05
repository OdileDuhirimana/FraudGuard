# ADR 0004: In-memory per-IP rate limiting with per-endpoint sensitivity

## Status
Accepted, with a documented scaling limitation

## Context
The original `RateLimitMiddleware` applied one global budget (300
requests/minute per IP) to every endpoint, including `/auth/login` and
`/fraud/otp/verify` — the two most brute-forceable endpoints in the system.
A 6-digit OTP has 1,000,000 possible values; at 300 requests/minute that
space is exhaustible in under an hour from a single IP, and trivially so
from a handful of rotated IPs. Treating login/OTP identically to read-heavy
endpoints like `/fraud/alerts` under-protected exactly the flows that most
need throttling.

## Decision
`RateLimitMiddleware` now accepts an ordered list of `(path_prefix,
max_requests)` overrides, checked before the default budget. `main.py`
wires `/v1/auth/login`, `/v1/auth/register`, `/v1/fraud/otp/init`, and
`/v1/fraud/otp/verify` to much tighter budgets (configurable via
`RATE_LIMIT_AUTH_PER_MINUTE` / `RATE_LIMIT_OTP_PER_MINUTE`, defaulting to
10/min and 5/min respectively) than the general API default (300/min).

## Consequences and known limitation (original)
This remains **process-local, in-memory state**. It does not function
correctly the moment this API is horizontally scaled to more than one
instance — each instance enforces its own independent budget, so the
effective rate limit multiplies by instance count and resets whenever an
instance restarts. This is an acceptable, explicitly-scoped tradeoff for a
single-instance Render deployment (the project's actual current deployment
target), not an oversight. A production system serving real transaction
volume would need a shared-state limiter (Redis with a sliding-window or
token-bucket algorithm) — this is called out as a roadmap item in the
README's "Known Limitations" section rather than silently left unaddressed.

## Update: optional Redis-backed backend (this pass)

The roadmap item above is now implemented, not just described.
`middleware.py` introduces a `RateLimitBackend` protocol with two
implementations:

- `InMemoryRateLimitBackend` — the original behavior, unchanged, and still
  the default when `REDIS_URL` is unset.
- `RedisRateLimitBackend` — a fixed-window counter (`INCR` + `EXPIRE` on
  first hit) shared across every instance connected to the same Redis
  server, replacing the single-instance limitation described above.

Backend selection happens once at middleware construction time
(`RateLimitMiddleware._build_default_backend`): if `REDIS_URL` is set and
reachable, Redis is used; otherwise the app falls back to the in-memory
backend and logs the reason (unset vs. unreachable are logged
differently). This means a deployment can adopt Redis incrementally —
setting `REDIS_URL` is the entire migration, no code change required — and
a deployment that never sets it (e.g. this project's current Render free
tier target) is completely unaffected by this change.

**New tradeoff introduced, documented rather than hidden:** if Redis is
configured but becomes unreachable *during* request handling (not just at
startup), `RateLimitMiddleware.dispatch` catches the error and falls open
to a per-process in-memory backend for that request, logging an error.
This is an explicit availability-over-strict-enforcement choice: a
transient Redis outage degrades rate-limiting precision (each instance
temporarily reverts to its own local budget) rather than taking the whole
API down over a dependency that is not the primary data store. A stricter
alternative (fail closed — reject all requests if Redis is down) was
considered and rejected for a fraud-scoring API, where availability of the
core scoring path matters more than perfect rate-limit enforcement during
a Redis incident.

**Verification note:** this backend was verified against a real Redis 7
instance (`docker run -d -p 16379:6379 redis:7-alpine`) during development
— see `tests/test_rate_limit_redis.py`, which is skipped unless a reachable
`REDIS_URL` is available and is wired into CI via a `redis` service
container (`.github/workflows/ci.yml`) so it runs for real in that
environment too, not only locally.
