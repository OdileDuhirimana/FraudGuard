# Entity-Relationship Diagram

Generated from the actual SQLAlchemy models in `backend/app/models.py`
(source of truth — if this ever drifts from the code, the code wins).

```mermaid
erDiagram
    USERS ||--o{ TRANSACTIONS : "places"
    USERS ||--o{ AUDIT_LOGS : "acts as (nullable — failed logins have no actor)"
    USERS ||--o{ BEHAVIOR_EVENTS : "generates"
    USERS ||--o{ DEVICES : "registers"
    USERS ||--o{ OTP_CHALLENGES : "owns"
    USERS ||--o{ TOKEN_BLACKLIST : "revokes tokens for"
    USERS ||--o{ GRAPH_JOBS : "requests"
    TRANSACTIONS ||--o{ ALERTS : "triggers"
    TRANSACTIONS ||--o{ OTP_CHALLENGES : "requires"
    ALERTS ||--o{ CASES : "opens"

    USERS {
        int id PK
        string email UK "unique, indexed"
        string hashed_password
        string role "CHECK IN (analyst, investigator, admin, manager)"
        datetime created_at
    }

    TRANSACTIONS {
        int id PK
        int user_id FK "-> users.id, NOT NULL"
        float amount "CHECK amount >= 0"
        string currency
        string merchant
        string mcc
        string ip
        float gps_lat
        float gps_lon
        string device_id
        datetime timestamp "indexed; composite index with user_id"
        json features "AES-256-GCM encrypted at rest"
        float score "CHECK 0 <= score <= 1"
        string decision "CHECK IN (allow, challenge, block)"
    }

    ALERTS {
        int id PK
        int transaction_id FK "-> transactions.id, NOT NULL"
        float risk_score
        string decision "CHECK IN (allow, challenge, block)"
        string reason
        datetime created_at "indexed"
    }

    CASES {
        int id PK
        int alert_id FK "-> alerts.id, NOT NULL"
        string status "CHECK IN (open, investigating, closed)"
        string notes
        datetime created_at
    }

    AUDIT_LOGS {
        int id PK
        int actor_user_id FK "-> users.id, NULLABLE (system/failed-login events)"
        string action
        string target
        string details
        datetime created_at "indexed"
    }

    BEHAVIOR_EVENTS {
        int id PK
        int user_id FK "-> users.id, NOT NULL"
        string event_type "typing | mouse | touch"
        json data "AES-256-GCM encrypted at rest"
        datetime created_at
    }

    DEVICES {
        int id PK
        int user_id FK "-> users.id, NOT NULL"
        string device_id "indexed"
        json fingerprint "AES-256-GCM encrypted at rest"
        boolean compromised
        datetime created_at
    }

    OTP_CHALLENGES {
        int id PK
        int transaction_id FK "-> transactions.id, NOT NULL"
        int user_id FK "-> users.id, NOT NULL"
        string code "6-digit, cryptographically random"
        boolean verified
        datetime created_at
        datetime expires_at "added: OTP_TTL_MINUTES from creation"
    }

    TOKEN_BLACKLIST {
        int id PK
        string jti UK "unique, indexed; the revoked JWT's jti claim"
        int user_id FK "-> users.id, NULLABLE"
        datetime revoked_at
        datetime expires_at "indexed; mirrors the token's own exp claim"
    }

    GRAPH_JOBS {
        int id PK
        string status "CHECK IN (pending, running, done, failed)"
        int requested_by_user_id FK "-> users.id, NOT NULL"
        datetime created_at "indexed"
        datetime completed_at "nullable"
        int transactions_considered "nullable until done"
        boolean truncated "nullable until done"
        json result "nullable; the computed graph once done"
        string error "nullable; populated only if status=failed"
    }
```

## Notes on constraints added during the remediation pass

Every `user_id`/`actor_user_id` column is now a real `ForeignKey` (the
original schema had these as plain, unconstrained `Integer` columns —
referential integrity was not enforced at the database level). `CASE`
columns (`role`, `decision`, `status`) are restricted to their valid value
sets via `CheckConstraint`, not just a Python comment. `amount` and `score`
have range constraints. See `backend/migrations/versions/` for the
executable migration and `backend/app/models.py` for the ORM definitions.

## Tables added after the initial migration

- **`OTP_CHALLENGES.expires_at`** (migration `ba66accbbf9e`) — closes the
  "OTP challenges never expire" finding; enforced in
  `routers/fraud.py::otp_verify`.
- **`TOKEN_BLACKLIST`** (migration `eba17c8732ad`) — backs server-side JWT
  revocation (logout); see `services/tokens.py` and `auth.py::get_current_user`.
- **`GRAPH_JOBS`** (migration `fb2d63b85ad8`) — backs the asynchronous
  fraud-ring graph computation; see `routers/fraud.py::create_graph_job`/
  `_run_graph_job`.

Each was added as an incremental migration (not folded into the original
baseline), consistent with real-world practice once a schema has any
possibility of existing deployments — see `backend/migrations/versions/`
for each migration's `upgrade()`/`downgrade()`, both exercised by
`tests/test_migrations.py`.
