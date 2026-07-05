# FraudGuard

A FastAPI backend for scoring financial transactions for fraud risk, with
JWT authentication, 4-role RBAC, an OTP step-up authentication flow, and
AES-256 encryption at rest for sensitive data. Backend-only — no frontend
exists (see [What's Mocked vs. Real](#whats-mocked-vs-real)).

- [Architecture diagram](docs/architecture.md)
- [Entity-relationship diagram](docs/erd.md)
- [Architecture decision records](docs/adr/)
- [Data access policy (lazy vs. eager loading)](docs/data-access-policy.md)
- [Project scope (what's real vs. roadmap)](project.md)
- [OpenAPI schema (checked-in artifact)](docs/api/openapi.json)
- [Postman collection](docs/api/postman_collection.json)
- [Load test results (dev-environment approximation)](docs/load-test-results.md)

## Tech stack

| Layer | Technology |
|---|---|
| API framework | FastAPI (Python 3.11+) |
| Database | SQLite (local dev) / PostgreSQL (production, via `psycopg`) |
| ORM & migrations | SQLAlchemy 2.0 + Alembic |
| Auth | JWT (PyJWT) with server-side revocation (logout), `argon2` password hashing (passlib), legacy `pbkdf2_sha256` verification for rolling migration |
| Encryption at rest | AES-256-GCM (`cryptography`) |
| Rate limiting | In-memory (default) or Redis-backed shared limiter (`REDIS_URL`) — see `docs/adr/0004-rate-limiting.md` |
| Background jobs | FastAPI `BackgroundTasks` (fraud-ring graph computation) |
| Observability | Structured JSON logs, Prometheus `/metrics`, optional Sentry error tracking (`SENTRY_DSN`) |
| Logging | Structured JSON logs (`python-json-logger`) |
| Testing | pytest + httpx (FastAPI `TestClient`), Locust (load test) |
| CI/CD | GitHub Actions (lint, migrate, test with coverage, OpenAPI contract check) + a gated Render-deploy-hook job on merge to `main` |
| Deployment target | Render (see `render.yaml`), Docker (see `Dockerfile` / `docker-compose.yml`) |

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

cd backend
cp .env.example .env   # then edit .env — see "Environment variables" below
alembic upgrade head
python -m scripts.seed  # optional: creates demo users + sample transactions
uvicorn app.main:app --reload
```

API docs (Swagger UI) are then available at `http://127.0.0.1:8000/docs`.

### Environment variables

See `backend/.env.example` for the full, commented list. The three that
most affect local setup:

| Variable | Required in prod? | Local default if unset |
|---|---|---|
| `JWT_SECRET_KEY` | Yes (app refuses to boot without it) | random per-process value |
| `CORS_ALLOWED_ORIGINS` | Yes, explicit allow-list, no `*` | `http://localhost:3000` |
| `DATABASE_URL` | Yes | `sqlite:///./fraudguard.db` |

`FG_AES_KEY` is required in production (the app fails closed rather than
silently storing plaintext) but optional in development.

`REDIS_URL` and `SENTRY_DSN` are both fully optional — unset means
in-memory rate limiting and no-op error tracking respectively, with no
degraded behavior otherwise.

### Running tests

```bash
cd backend
pytest                      # runs the full suite with coverage report
pytest tests/test_otp.py -v # e.g. just the OTP authorization regression tests
```

CI (`.github/workflows/ci.yml`) runs `ruff check`, applies migrations
up/down/up against a throwaway database, runs the full pytest suite with a
coverage gate (including an OpenAPI-schema contract check — see
`tests/test_openapi_contract.py`) against a real Redis service container,
on every push and pull request to `main`. A second job triggers a Render
deploy hook on a successful push to `main` (see "Deployment" below for its
current unverified status).

## API overview

All routes are versioned under `/v1`. See `docs/api/openapi.json` (checked-in
schema snapshot) and `docs/api/postman_collection.json` for a browsable
artifact beyond this table and the live `/docs` page.

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/v1/auth/register` | POST | none | Create a user. First registered user becomes `admin`. |
| `/v1/auth/login` | POST | none | Exchange credentials for a JWT. |
| `/v1/auth/logout` | POST | any user | Revoke the current token server-side (see AUTH-02 fix below). |
| `/v1/fraud/score` | POST | any user | Score a transaction; returns `allow`/`challenge`/`block`. |
| `/v1/fraud/behavior` | POST | any user | Record a behavioral biometric event (typing/mouse/touch). |
| `/v1/fraud/device` | POST | any user | Register a device fingerprint. |
| `/v1/fraud/alerts` | GET | admin, analyst | Paginated, filterable, sortable alert feed (eager-loads each alert's transaction). |
| `/v1/fraud/otp/init` | POST | transaction owner or admin | Start OTP step-up challenge (expires after 5 minutes). |
| `/v1/fraud/otp/verify` | POST | transaction owner or admin | Verify OTP code. |
| `/v1/fraud/feedback` | POST | transaction owner or admin | Record investigator fraud/legit feedback (audit-only; does not retrain anything — see below). |
| `/v1/fraud/graph` | GET | admin | Paginated, bounded user/device/IP relationship graph (one page of recent transactions). |
| `/v1/fraud/graph/jobs` | POST | admin | Kick off a background job computing the *full* relationship graph. |
| `/v1/fraud/graph/jobs/{id}` | GET | admin | Poll a graph job's status/result. |
| `/v1/admin/users` | GET | admin, manager | Paginated, filterable, sortable user list. |
| `/v1/admin/audit` | GET | admin, manager | Paginated, filterable, sortable audit log (eager-loads each entry's actor). |
| `/v1/admin/role` | POST | admin | Change a user's role. |
| `/metrics` | GET | none | Prometheus text-format metrics (request count/latency). |

Every error response uses one envelope:

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Invalid email or password",
    "details": null
  }
}
```

### Example: score a transaction and complete the OTP flow

```bash
# 1. Register + login
curl -s -X POST http://127.0.0.1:8000/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"SecurePass123!"}'

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"SecurePass123!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Score a risky transaction
curl -s -X POST http://127.0.0.1:8000/v1/fraud/score \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"amount":1850.0,"mcc":"7995","ip":"203.0.113.9","timezone_mismatch":true}'
# -> {"score":0.7...,"decision":"challenge","reason":"Medium risk","transaction_id":1}

# 3. Initiate OTP for that transaction_id, then verify with the code
#    (in dev, read the code directly from the otp_challenges table —
#    there is no SMS/email integration; see "What's Mocked vs. Real")
curl -s -X POST http://127.0.0.1:8000/v1/fraud/otp/init \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"transaction_id":1}'
```

## What's Mocked vs. Real

Being explicit about this is more useful to a reviewer than pretending
otherwise. This table is the single source of truth for project scope —
`project.md` links back here.

| Component | Status | Detail |
|---|---|---|
| JWT auth, password hashing, RBAC | **Real** | `argon2` (with legacy `pbkdf2_sha256` verification for a rolling migration), enforced role checks on every sensitive route. |
| Server-side logout / token revocation | **Real** | Every token carries a `jti`; logout records it in `TokenBlacklist`, checked on every request (`services/tokens.py`). |
| Encryption at rest (AES-256-GCM) | **Real** | Fails closed in production if `FG_AES_KEY` is unset (see ADR 0002). |
| Fraud risk scoring | **Heuristic, not ML** | `app/risk.py` is a hand-weighted sum, not a trained model. No labeled training data, no evaluation metrics. |
| "Isolation Forest" / "Autoencoder" scores | **Surrogate math, not trained models** | `app/ml/model.py` computes norm/std-based heuristics that mimic the *shape* of these algorithms' outputs, not actual fitted models. |
| Dark-web exposure check | **Demo stub** | `services/darkweb.py` checks against a hardcoded 2-hash in-memory set, not a real breach database. |
| OTP delivery | **Not implemented** | Codes are generated and stored server-side; there is no SMS/email/push delivery integration. Codes now expire after 5 minutes. |
| Feedback loop / retraining | **Audit-only, no retraining** | `/fraud/feedback` records an audit log entry. There is no model to retrain. |
| Fraud-ring graph (synchronous) | **Real, paginated** | `GET /fraud/graph` builds an actual `networkx` graph from one page of recent transactions, using the same pagination contract as every other list endpoint. |
| Fraud-ring graph (background job) | **Real** | `POST /fraud/graph/jobs` computes the full graph (up to 50,000 transactions) via `BackgroundTasks`, polled via `GET /fraud/graph/jobs/{id}`. |
| Rate limiting | **Real; in-memory by default, Redis-backed if `REDIS_URL` is set** | See ADR 0004. Verified against a real Redis 7 instance in development and in CI (`redis` service container). |
| Metrics | **Real** | `/metrics` (Prometheus text format): request count + latency, labeled by method/route/status. |
| Error tracking | **Real, opt-in** | No-op unless `SENTRY_DSN` is set (`app/observability.py`). Not exercised against a live Sentry project in this environment — only the no-op path is tested. |
| Repository pattern | **Real** | `app/repositories/` — routers call repository methods, not raw `db.query(...)`, for the endpoints that previously mixed query construction into route handlers. |
| Frontend | **Does not exist** | This is a backend-only project. |
| CI | **Real** | GitHub Actions runs lint + migrations + tests (incl. an OpenAPI-schema contract check) against a real Redis service, on every push/PR. |
| CD | **Configured, not live-verified** | A GitHub Actions job triggers a Render deploy hook on push to `main`, gated on the test job passing. No `RENDER_DEPLOY_HOOK_URL` secret is configured in this environment, so the job currently no-ops by design rather than failing — see "Deployment" below. |
| Live deployment | **Not provisioned** | `render.yaml` is a complete, correct blueprint; no live Render service has actually been created for this repository in this environment. |

## Known limitations

- **Offset-based pagination** on list endpoints has O(n) skip cost at very
  large table sizes. Acceptable for the current data volumes; a
  keyset/cursor approach would be the next step if this data grew into the
  millions of rows (see `backend/app/pagination.py` module docstring).
- **No SMS/email delivery for OTP codes** — see table above.
- **`datetime.utcnow()` deprecation warnings** appear under Python 3.13
  (naive-UTC timestamps throughout `models.py`/`auth.py`). Functionally
  correct today; a future pass should migrate to timezone-aware
  datetimes.
- **Token blacklist rows are not automatically pruned.** `services/tokens.py::prune_expired`
  exists but is not scheduled — a real deployment would run it periodically
  (cron/scheduled job) to bound table growth. Not a correctness issue: an
  unpruned row for an already-expired token is inert (the token would fail
  JWT expiry validation regardless of blacklist membership).
- **The Redis-backed rate limiter's failure mode is "fail open" to the
  in-memory backend** if Redis becomes unreachable mid-flight, trading
  strict rate-limit enforcement for API availability during a Redis
  incident — see the "Update" section of `docs/adr/0004-rate-limiting.md`.
- **The CD pipeline is configured but not connected to a live deployment**
  in this environment (no Render account/service was provisioned as part
  of this work) — see "Deployment" below.

## Challenges faced

- **The single hardest bug to find was also the most serious one**: `
  otp_verify` had no ownership check while its sibling `otp_init` did.
  Both looked superficially similar and both "worked" in manual testing
  with a single user account — the gap only became obvious once a test
  was written from a second, unauthorized user's perspective
  (`tests/test_otp.py::test_otp_verify_rejects_non_owner`). This is the
  main reason the test suite added in this pass explicitly tests
  cross-user authorization boundaries, not just happy-path flows.
- **Reconciling `project.md` with reality was uncomfortable but
  necessary.** It's tempting to leave an ambitious-sounding feature list in
  a portfolio project; the actual effect is the opposite of the intended
  one once a reviewer compares it against the code. Rewriting it as an
  honest "what's real / what's roadmap" doc was a deliberate trade of
  short-term impressiveness for long-term credibility.
- **Retrofitting FK constraints onto an existing schema** required
  generating a fresh Alembic baseline rather than an incremental
  migration, since several columns needed to go from nullable
  unconstrained integers to non-null foreign keys — a change that isn't
  safely auto-generatable against data that might violate the new
  constraint. For this project's stage (no production data yet), a clean
  baseline migration was the right tradeoff; a live system with existing
  data would need a multi-step backfill-then-constrain migration instead.

## Tradeoffs

| Decision | Alternative considered | Why this choice |
|---|---|---|
| Heuristic risk scoring, clearly labeled as such | Ship a trained model now | A poorly-trained model on synthetic data would be less honest than a documented heuristic. Scope for this pass was fixing structural/security issues, not building a real ML pipeline. |
| Offset pagination | Cursor/keyset pagination | Simpler client contract ("page N"); acceptable at current and expected near-term data volumes for an admin/investigator tool. |
| In-memory rate limiting, with an optional Redis backend | Require Redis unconditionally | Redis is now supported and verified (see ADR 0004 update), but is not made mandatory — a deployment that doesn't need multi-instance scaling shouldn't have to run and operate a Redis instance just to boot. |
| SQLite for dev, Postgres for prod | SQLite everywhere | SQLite has no native network round-trip for local iteration speed; Postgres is what the `render.yaml` production target actually uses, so tests should be compatible with both dialects (verified: all `CheckConstraint`/`ForeignKey` usage here is standard SQL, not SQLite- or Postgres-specific). |
| Alembic migrations | `Base.metadata.create_all()` | The original approach had no upgrade/rollback path and ran as a side effect of importing a router module. Alembic gives real migration history at the cost of a small amount of extra process. |
| FastAPI `BackgroundTasks` for the graph job | Celery + Redis (or another broker) | This project isn't otherwise running a message broker; `BackgroundTasks` is the right-sized tool for "run this after the response, in the same process" without a new infrastructure dependency. If Redis becomes a hard requirement later (e.g. once rate limiting is Redis-only in production), revisiting Celery becomes more attractive since the broker dependency would already be paid for. |
| Denylist (blacklist) for token revocation | Allowlist of active sessions | A denylist only writes on the rare path (logout); an allowlist would write on every login, the common path. |
| `argon2` as the new default password hash, `pbkdf2_sha256` kept verifiable | Force-reset all passwords | Avoids a disruptive mass password reset; existing hashes upgrade transparently on next successful login (see routers/auth.py::login). |

## Deployment and rollback runbook

**Current status:** `render.yaml` is a complete, correct Render blueprint,
and `.github/workflows/ci.yml` has a `deploy` job that POSTs to a Render
deploy hook on a successful push to `main`. Neither has been exercised
against a live Render service in this environment — there is no
`RENDER_DEPLOY_HOOK_URL` secret configured, so the `deploy` job
intentionally no-ops (logs why, exits 0) rather than failing the build.
Provisioning a real Render service and adding that secret is the only step
left to make this pipeline live.

**Rollback procedure**, for whenever a deploy is live and needs to be
reverted:

1. **Application code rollback.** Render deploys are triggered by the deploy
   hook, which builds from whatever commit is on `main` at trigger time.
   To roll back the application: revert the offending commit(s) on `main`
   (`git revert <sha>`, not a force-push/history rewrite) and push — this
   triggers the same CI -> deploy-hook pipeline forward, rolling the live
   service back to the previous known-good code without any manual step on
   Render itself. (Render also supports manually redeploying a previous
   build from its dashboard as a faster, out-of-band alternative if CI
   itself is unavailable.)
2. **Database migration rollback.** Every migration in `backend/migrations/versions/`
   has a real, tested `downgrade()` (see `tests/test_migrations.py`, which
   drives a real upgrade -> downgrade -> upgrade cycle in CI). To roll back
   the schema one migration: `alembic downgrade -1` against the production
   `DATABASE_URL`. **Order matters**: roll back the application code first
   (or simultaneously) if the migration being reverted removed a column or
   table the *currently deployed* code still reads/writes — downgrading
   the schema before the code that depends on the old schema is rolled
   back would turn a planned rollback into an outage.
3. **Verify.** After either rollback, hit `GET /health` — it performs a
   real database connectivity check (not a liveness stub) and returns
   `"degraded"` rather than a 5xx if the database is reachable but
   unhealthy, so a rollback that leaves the schema and code mismatched is
   visible immediately rather than surfacing as scattered 500s later.
4. **Audit trail.** `GET /admin/audit` and the structured JSON logs both
   predate this incident's response — `role_changed`, `login_failed`, etc.
   are already durable, so a rollback investigation has a real trail to
   consult rather than needing to be reconstructed from memory.

**What this runbook does not cover** (explicitly, rather than silently):
zero-downtime blue/green deployment (Render's free/starter tiers used by
this project's `render.yaml` do not support it), and a rollback of
in-flight background graph jobs (`GraphJob` rows from before a rollback
remain in whatever state they reached; they are not automatically
re-queued or invalidated by a rollback — an operator would need to inspect
`/fraud/graph/jobs/{id}` and manually re-trigger if needed).

## Lessons learned

- **A checklist-driven audit is worth more than it feels like in the
  moment.** Several of the fixes here (FK constraints, check constraints,
  the composite index) are individually small, but the OTP authorization
  bug specifically would very plausibly have shipped to a real interview
  demo undetected without a systematic pass that asked "does every
  endpoint that checks ownership have a sibling that doesn't?"
- **Error-envelope consistency is a design decision, not a formatting
  detail.** Mixing `raise HTTPException` with `return {"error": ...}`
  (implicit 200) isn't just inconsistent style — it actively lies to
  API consumers about whether a request succeeded. Fixing this required a
  single choke point (`app/errors.py`) rather than fixing call sites
  piecemeal.
- **Documentation that oversells scope is a bigger risk than
  documentation that undersells it.** The original `project.md` was
  clearly meant to be impressive; the effect on a careful technical
  reviewer is closer to a credibility red flag. Being specific about what
  is real, heuristic, or aspirational reads as more senior, not less.

## Future improvements

See [`project.md` — Roadmap](project.md#roadmap-explicitly-aspirational--not-implemented)
for the full list. Several previously-listed items here are now done —
Redis-backed rate limiting, the background graph job, and
metrics/observability instrumentation — see "What's Mocked vs. Real"
above. Highest priority remaining, in order:

1. Replace the heuristic scorer with a real trained model + evaluation
   report on a public labeled fraud dataset (see `docs/ml_evaluation.md`
   for an initial attempt at this — an IsolationForest baseline with real,
   not fabricated, precision/recall/AUC numbers on a synthetic dataset).
2. Provision a live Render deployment and connect the already-configured
   CD pipeline's deploy hook to it.
3. A minimal investigator frontend (alert list + case status updates).
4. Scheduled pruning of expired `TokenBlacklist` rows.
5. Timezone-aware datetimes throughout (replace `datetime.utcnow()`).
