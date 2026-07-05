# Architecture

FraudGuard is a single FastAPI backend service (no frontend — see
[README: What's Mocked vs. Real](../README.md#whats-mocked-vs-real)) that
scores transactions for fraud risk using a heuristic rules-based engine,
enforces role-based access control, and exposes an OTP-based step-up
authentication flow for medium-risk transactions.

## Component diagram

```mermaid
flowchart TB
    subgraph Client["Client (curl / Postman / future frontend)"]
        C[HTTP client]
    end

    subgraph API["FastAPI app (backend/app)"]
        MW1["CORSMiddleware<br/>(explicit allow-list, fail-closed,<br/>allow_credentials=False)"]
        MW2["RateLimitMiddleware<br/>(per-IP, per-endpoint budgets;<br/>in-memory or Redis-backed)"]
        MW3["PrometheusMiddleware<br/>(request count/latency -> /metrics)"]
        EH["Exception handlers<br/>(errors.py — single error envelope)"]

        subgraph Routers["Routers (/v1 prefix)"]
            RAuth["/v1/auth<br/>register, login, logout"]
            RFraud["/v1/fraud<br/>score, behavior, device,<br/>alerts, otp/*, graph, graph/jobs, feedback"]
            RAdmin["/v1/admin<br/>users, audit, role"]
        end

        subgraph Repos["Repositories (app/repositories/)"]
            RepoTx["TransactionRepository"]
            RepoAlert["AlertRepository<br/>(joinedload transaction)"]
            RepoAudit["AuditLogRepository<br/>(joinedload actor)"]
            RepoUser["UserRepository"]
            RepoOTP["OTPChallengeRepository"]
            RepoGraph["GraphJobRepository"]
        end

        subgraph Domain["Domain / business logic"]
            Risk["risk.py<br/>compute_risk_score() dispatcher"]
            Ensemble["ml/ensemble.py<br/>feature extraction"]
            MLModel["ml/model.py<br/>iforest/pca surrogate scorers"]
            Trained["ml/trained_scorer.py<br/>real IsolationForest (opt-in)"]
            Analytics["services/analytics.py<br/>velocity queries"]
            Darkweb["services/darkweb.py<br/>breach-hash lookup"]
            Audit["services/audit.py<br/>audit log writer"]
            Tokens["services/tokens.py<br/>JWT revocation (logout)"]
            Sec["security.py<br/>AES-256-GCM encrypt/decrypt"]
        end

        Auth["auth.py<br/>JWT issue/verify (+jti), require_role()"]
        Obs["observability.py<br/>Sentry (opt-in) + Prometheus"]
    end

    subgraph Data["Persistence"]
        DB[("SQLite (dev) /<br/>PostgreSQL (prod)")]
        Redis[("Redis<br/>(optional, rate limiting only)")]
    end

    C -->|HTTPS + Bearer JWT| MW1 --> MW2 --> MW3 --> Routers
    RAuth --> Auth
    RFraud --> Auth
    RAdmin --> Auth
    RFraud --> Repos
    RAdmin --> Repos
    RAuth --> Repos
    Repos --> DB
    RFraud --> Domain
    Domain --> DB
    MW2 -.->|if REDIS_URL set| Redis
    Routers -.->|raises AppError / HTTPException| EH
    EH -->|standard error envelope| C
    Obs -.->|no-op unless SENTRY_DSN set| EH
```

## Request flow: transaction scoring + step-up auth

```mermaid
sequenceDiagram
    actor User
    participant API as FastAPI (/v1/fraud)
    participant Risk as risk.py
    participant DB as Database

    User->>API: POST /v1/auth/login
    API->>DB: verify credentials
    API-->>User: JWT access token

    User->>API: POST /v1/fraud/score (Bearer token)
    API->>DB: count_user_tx_last_minutes(user_id)
    API->>Risk: risk_score(features)
    Risk-->>API: score, decision, reason
    API->>DB: insert Transaction (+ Alert if challenge/block)
    API-->>User: ScoreOut{score, decision, reason, transaction_id}

    alt decision == "challenge"
        User->>API: POST /v1/fraud/otp/init {transaction_id}
        API->>DB: verify ownership (user_id == tx.user_id OR admin)
        API->>DB: create OTPChallenge (random 6-digit code, expires in 5 min)
        API-->>User: {status: "sent"}
        User->>API: POST /v1/fraud/otp/verify {transaction_id, code}
        API->>DB: verify ownership (SAME check as otp_init)
        API->>DB: check expiry, compare code, mark verified, upgrade decision to "allow"
        API-->>User: {status: "verified"}
    end
```

## Request flow: async fraud-ring graph job

```mermaid
sequenceDiagram
    actor Admin
    participant API as FastAPI (/v1/fraud/graph/jobs)
    participant BG as BackgroundTasks
    participant DB as Database

    Admin->>API: POST /v1/fraud/graph/jobs
    API->>DB: create GraphJob(status="pending")
    API-->>Admin: 202 {job_id, status: "pending"}
    API->>BG: schedule _run_graph_job(job_id) (after response is sent)

    BG->>DB: mark_running(job_id)
    BG->>DB: query up to GRAPH_JOB_MAX_TRANSACTIONS transactions
    BG->>BG: build networkx graph
    BG->>DB: mark_done(job_id, result=graph)

    Admin->>API: GET /v1/fraud/graph/jobs/{job_id}
    API->>DB: fetch GraphJob
    API-->>Admin: {status: "done", graph: {...}}
```

## Known limitations (see README for full list)

- No frontend exists; every diagram above is a backend-only system.
- The default scoring in `risk.py`/`ml/` is a hand-tuned heuristic, not a
  trained model — see README "What's Mocked vs. Real." An opt-in trained
  `IsolationForest` (`ml/trained_scorer.py`) exists with a real evaluation
  report (`docs/ml_evaluation.md`), trained on synthetic (not real) data.
- Rate limiting is in-memory by default, with an optional Redis-backed
  shared limiter (`REDIS_URL`) — see `docs/adr/0004-rate-limiting.md`.
- The fraud-ring graph has both a synchronous, paginated path
  (`GET /fraud/graph`, portfolio-scale) and an async background-job path
  (`POST /fraud/graph/jobs`, up to `GRAPH_JOB_MAX_TRANSACTIONS`).
