# FraudGuard — Project Scope

This file exists to state, plainly, what FraudGuard actually is right now
versus what is aspirational. An earlier version of this file described a
much larger, partially fictional system (LightGBM/GNN ensembles, Kafka
streaming, a React+D3 dashboard, MongoDB, MLflow). None of that existed in
the code, and leaving it undocumented like that is a credibility risk, not
a feature — a reviewer who reads marketing copy next to the actual
repository will reasonably conclude the scope was overstated. This
rewrite fixes that.

For full technical detail see `README.md`, `docs/architecture.md`, and
`docs/erd.md`. This file is intentionally short.

## Who this is for, and how "working" would be measured

This section is intentionally short and concrete rather than aspirational
marketing copy — matching the rest of this file's stated goal.

**Primary user: a fraud analyst or investigator at a small-to-mid-size
fintech/payments company.** Concretely, someone who logs in each shift to
review the alert queue (`GET /fraud/alerts`), investigates a flagged
transaction (`GET /fraud/graph` / `POST /fraud/graph/jobs` for relationship
context), and records a fraud/legit determination (`POST /fraud/feedback`).
Their goal is to clear the highest-risk queue items quickly without missing
real fraud or spending time on false positives.

**Secondary user: a platform/security engineer or manager** who manages
analyst accounts and roles (`/admin/users`, `/admin/role`), audits who did
what and when (`/admin/audit`), and is accountable for the system's own
security posture (rate limiting, encryption at rest, RBAC) — this is why
those controls are implemented as real, tested behavior rather than
described-only in this project.

**Success metrics this system would need to hit in production** (not
currently measured — see "What FraudGuard is not (yet)" below for why):
- **Precision/recall/AUC of the risk scorer** against a labeled fraud
  dataset. Today there is no labeled data and no trained model (`risk.py`
  is a heuristic), so this number does not exist yet — see the roadmap
  item on a trained-model evaluation report.
- **Alert-to-investigation latency**: time from `Alert` creation to an
  investigator recording feedback on it. The pagination/sorting on
  `/fraud/alerts` exists specifically to make triaging a large queue
  practical, but there is no current dashboard measuring this end-to-end.
- **False-positive rate on `challenge`/`block` decisions**, inferred from
  the ratio of `feedback_submitted` audit entries labeled "legit" for
  transactions the system challenged/blocked. The data model supports
  computing this (feedback labels + transaction decisions are both
  persisted) but no report currently aggregates it — a concrete,
  buildable next step rather than a vague "add analytics" line item.

**Competitive landscape (why this differs from, e.g., Sift, Stripe Radar,
or a bank's in-house fraud stack):** those are production ML platforms
with real trained models, live data pipelines, and years of labeled fraud
data feeding continuous retraining. FraudGuard does not compete with them
on modeling sophistication — it is a portfolio-scale demonstration of the
*engineering scaffolding* a fraud system needs regardless of how
sophisticated its model is: authn/authz with real ownership checks,
step-up MFA, audit logging, rate limiting, encryption at rest, pagination/
filtering at scale, and now background job processing and shared
rate-limit state for horizontal scaling. The explicit differentiation is
architectural honesty: this project documents exactly which parts are
production-grade engineering (auth, RBAC, encryption, testing, CI) versus
which parts are heuristic placeholders standing in for a real ML pipeline
(the scorer itself) — see "What's Mocked vs. Real" in README.md.

## What FraudGuard is today

A FastAPI backend service that:
- Authenticates users with JWT and enforces 4-role RBAC (analyst,
  investigator, admin, manager).
- Scores submitted transactions against a hand-tuned heuristic risk
  function (not a trained ML model — see README "What's Mocked vs. Real").
- Issues `allow` / `challenge` / `block` decisions and creates `Alert`
  records for anything above the `allow` threshold.
- Implements a step-up OTP (6-digit code) verification flow for challenged
  transactions, with ownership enforced on both initiation and
  verification.
- Encrypts sensitive JSON blobs (transaction features, behavioral events,
  device fingerprints) at rest with AES-256-GCM.
- Exposes a bounded, investigator-facing user/device/IP relationship graph,
  both synchronously (paginated) and as a background job for the full
  graph (`POST /fraud/graph/jobs`).
- Provides paginated, filterable, sortable admin endpoints for audit logs
  and user management, with eager-loaded related data (no N+1 queries).
- Optionally scores transactions with a real trained `IsolationForest`
  (`RISK_SCORER_BACKEND=isolation_forest`) instead of the default
  heuristic, with an honest evaluation report on synthetic data — see
  `docs/ml_evaluation.md`.
- Optionally rate-limits via Redis for multi-instance deployments
  (`REDIS_URL`), falling back to in-memory otherwise.
- Ships with Alembic migrations, a seed script, pytest integration tests
  (including a real Redis integration and an OpenAPI contract check), a
  Locust load test, and a GitHub Actions CI pipeline with a gated
  (currently unconnected) CD deploy-hook job.

There is no frontend. This is a backend-only project.

## What FraudGuard is not (yet)

- Not a production-grade trained ML system. `app/ml/trained_scorer.py`
  wraps a real, trained `IsolationForest` with a real evaluation report
  (`docs/ml_evaluation.md`) — a genuine step beyond a pure heuristic — but
  it is trained on synthetic data, not real fraud outcomes, and is offered
  as an opt-in alternative, not the default scorer. `app/risk.py` (the
  default) remains an explicit, documented heuristic — see inline "HONEST
  STATUS" comments.
- Not a real-time streaming system. There is no Kafka or message queue.
  The fraud-ring graph now has a background-job path
  (`POST /fraud/graph/jobs`, via FastAPI `BackgroundTasks`), but
  transaction scoring itself remains synchronous by design (a fraud
  decision needs to be returned in the same request/response cycle to be
  useful).
- Not horizontally scalable by default, though it can be: rate limiting is
  in-memory unless `REDIS_URL` is set (documented in
  `docs/adr/0004-rate-limiting.md`), and there is no live multi-instance
  deployment to point to as proof.
- Not integrated with any real dark-web breach database — `is_exposed()`
  checks against a small in-memory demo set of hashes.
- Not PCI-DSS or GDPR certified. Encryption at rest and RBAC are real,
  implemented controls that would be *part of* a compliance program, not a
  substitute for one.
- Not deployed anywhere live. `render.yaml` and the CD pipeline job are
  both real and correct, but no Render service has actually been
  provisioned in this environment — see README "Deployment and rollback
  runbook".

## Roadmap (explicitly aspirational — not implemented)

These are ideas for where the project could go, not claims about its
current state. Several items previously listed here are now implemented
(trained-model scorer, background graph job, Redis-backed rate limiting,
Prometheus metrics) — see "What FraudGuard is today" above; they are not
relisted here.

- Train the IsolationForest scorer (`docs/ml_evaluation.md`) on a real
  labeled fraud dataset instead of synthetic data, and recalibrate its
  decision thresholds independently of the heuristic's.
- Build a minimal investigator frontend (alert list, case status updates).
- Provision a live Render deployment and connect the already-configured
  CD pipeline's deploy hook to it.
- OpenTelemetry distributed tracing, beyond the current Prometheus
  request-count/latency metrics and structured JSON logs.
- Scheduled pruning of expired `TokenBlacklist` rows.
