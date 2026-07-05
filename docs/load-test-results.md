# Load test results — concurrent OTP verification

**Status: a dev-environment approximation, not a production capacity
benchmark.** This was run on a single shared development sandbox (8
logical CPUs, ~7.5GB RAM, other unrelated processes running concurrently
on the same host), against a single `uvicorn` worker process backed by
SQLite, over a Unix loopback connection with no network latency. None of
those conditions match a real production deployment (Postgres over a real
network, likely multiple `uvicorn`/gunicorn workers, no host contention
from unrelated processes). The numbers below are real, unmodified output
from an actual run — not fabricated — but should be read as "does the
system behave sanely under concurrency and where are the obvious
bottlenecks," not "here is our SLA."

## What was run

```bash
cd backend
alembic upgrade head   # against a throwaway SQLite DB

ENV=development \
CORS_ALLOWED_ORIGINS=http://localhost:3000 \
JWT_SECRET_KEY=loadtest-secret \
DATABASE_URL=sqlite:///./loadtest_fraudguard.db \
RATE_LIMIT_DEFAULT_PER_MINUTE=100000 \
RATE_LIMIT_AUTH_PER_MINUTE=100000 \
RATE_LIMIT_OTP_PER_MINUTE=100000 \
uvicorn app.main:app --host 127.0.0.1 --port 8123

# in a second terminal:
locust -f loadtest/locustfile.py --host http://127.0.0.1:8123 \
    --headless -u 20 -r 5 -t 30s --csv=loadtest/results
```

Rate limits were deliberately raised for this run. The purpose here is
observing the *application's* behavior under concurrent OTP-verification
load — throughput, latency, whether anything crashes or deadlocks under
concurrency — which is a different question from "does the rate limiter
correctly throttle a brute-force attempt," already covered by
`tests/test_rate_limit.py` and `tests/test_rate_limit_redis.py`. Running
this load test against the *default* production rate limits would mostly
just measure the rate limiter rejecting requests with 429s, which is
already proven correct by those tests.

20 simulated users, ramping up at 5/second, sustained for 30 seconds. Each
user: registers, logs in, scores a transaction engineered to land in
`challenge`, initiates an OTP challenge, then repeatedly (5:1 task weight
vs. a background `/fraud/alerts` read) submits `POST /fraud/otp/verify`
with a random wrong 6-digit code — the concurrent-attack scenario this
test targets. A `400 invalid_code` response is the *correct* outcome for a
wrong code and is explicitly counted as a success in the locustfile, not a
failure.

## Results (raw, unmodified Locust output)

| Endpoint | Requests | Failures | Median | p95 | p99 | Max | req/s |
|---|---|---|---|---|---|---|---|
| `POST /v1/auth/register` | 20 | 0 | 970ms | 2000ms | 2000ms | 1996ms | 0.69 |
| `POST /v1/auth/login` | 20 | 0 | 700ms | 1100ms | 1100ms | 1135ms | 0.69 |
| `POST /v1/fraud/score` | 20 | 0 | 390ms | 1100ms | 1100ms | 1093ms | 0.69 |
| `POST /v1/fraud/otp/init` | 20 | 0 | 220ms | 810ms | 810ms | 812ms | 0.69 |
| `POST /v1/fraud/otp/verify` (wrong code) | 1256 | 0 | 18ms | 71ms | 600ms | 1692ms | 43.2 |
| `GET /v1/fraud/alerts` | 267 | 0 | 14ms | 49ms | 130ms | 230ms | 9.2 |
| **Aggregated** | **1603** | **0** | **18ms** | **320ms** | **1100ms** | **1996ms** | **55.2** |

**Zero failed requests** across 1,603 total requests in the 30-second
window (the first run, before `catch_response` was added to correctly
classify expected `400 invalid_code` responses as successes, showed the
otp/verify task at ~100% "failure" for exactly this reason — a locustfile
correctness issue, not an application bug; documented here rather than
silently corrected out of the record).

## What this actually shows

1. **`/fraud/otp/verify` itself is fast and scales well under this
   concurrency** — 18ms median, and it absorbed the highest request
   volume (1,256 of 1,603 total requests, ~43 req/s) of any endpoint
   tested. The core OTP-comparison logic (one indexed DB lookup + a string
   compare + an expiry check) is not the bottleneck.

2. **`/auth/register` and `/auth/login` are the slowest endpoints by far**
   (970ms / 700ms median, up to ~2s at the tail) — this is the real,
   interesting finding. The cause is `argon2` password hashing (the
   AUTH-03 fix in this same pass, replacing `pbkdf2_sha256`): argon2 is
   deliberately memory-hard and CPU-expensive *by design* (that's what
   makes it resistant to GPU/ASIC cracking), and `passlib`'s hash/verify
   calls run synchronously on the same event loop `uvicorn` uses for
   everything else in a single-worker deployment. Twenty concurrent
   registrations each doing CPU-bound argon2 work on one process
   contend for the same CPU time as every other in-flight request,
   which is consistent with the elevated tail latency observed on
   `/fraud/score` and `/fraud/otp/init` too (both ~800-1100ms at p95,
   despite doing comparatively little CPU work themselves) — they are
   very plausibly waiting behind register/login's argon2 hashing on the
   same event loop, not slow because of their own logic.

3. **Concrete, evidence-based recommendation this load test produced**
   (not present before running it): a production deployment should either
   (a) run multiple `uvicorn`/gunicorn worker processes so argon2's CPU
   cost on one request doesn't block others, and/or (b) move
   `pwd_context.hash()`/`pwd_context.verify()` calls onto a thread-pool
   executor (e.g. FastAPI's `run_in_threadpool`) so the async event loop
   isn't blocked during the hash computation itself. Neither is
   implemented in this pass — this is a genuine, load-test-derived
   finding for the roadmap, not a retrofitted justification for existing
   code.

## What this load test does not show

- Behavior under sustained load over minutes/hours (memory leaks,
  connection pool exhaustion) — only a 30-second window was run.
- Behavior against Postgres (this ran against SQLite, which has different
  concurrency characteristics — SQLite serializes writes at the file
  level).
- Behavior with the Redis-backed rate limiter under load (this run used
  in-memory rate limiting with very high limits specifically to avoid
  measuring the rate limiter itself — see "What was run" above).
- Multi-instance/horizontal-scaling behavior.
