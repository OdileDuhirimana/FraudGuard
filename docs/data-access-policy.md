# Data access policy: repositories, lazy vs. eager loading

This document exists because the code review's PERF-02 finding
("Relationships ... default lazy-loaded with no eager-loading strategy
configured anywhere") is exactly the kind of thing that re-appears
silently if it isn't written down as a policy new endpoints are expected
to follow, not just a one-time fix applied to two routes.

## Repository layer

`backend/app/repositories/` holds one class per aggregate/table
(`AlertRepository`, `AuditLogRepository`, `TransactionRepository`,
`UserRepository`, `OTPChallengeRepository`, `GraphJobRepository`), each
constructed from a `Session` and injected into routers via
`Depends(get_x_repository)`. Routers call repository methods instead of
building `db.query(...)` directly; this is where query shape (filtering,
sorting, pagination, and — the subject of this document — eager-loading)
lives, in one reviewable place per aggregate instead of scattered inline
across route handlers.

Repositories deliberately do **not** own authorization checks or
transaction boundaries (commit/rollback) — those stay in the router/
service layer. A repository answers "what does the query for X look
like?", not "is the current user allowed to see X?" or "when does this
transaction commit?".

## Policy: when to eager-load

**Default: lazy loading (SQLAlchemy's default).** Most queries in this API
serialize only the primary entity's own columns (e.g. `ScoreOut`,
`UserOut`), never touching a relationship attribute — eager-loading a
relationship nothing ever reads would add a JOIN for no benefit.

**Eager-load (`joinedload`) when a list endpoint's response schema
serializes a to-one relationship.** This is the concrete rule the PERF-02
fix applies:

| Endpoint | Relationship accessed | Eager-load applied |
|---|---|---|
| `GET /fraud/alerts` | `Alert.transaction` (via `AlertOut.transaction`) | `joinedload(Alert.transaction)` in `AlertRepository.list_paginated` |
| `GET /admin/audit` | `AuditLog.actor` (via `AuditLogOut.actor_email`) | `joinedload(AuditLog.actor)` in `AuditLogRepository.list_paginated` |

Both are to-one relationships (`Alert.transaction`, `AuditLog.actor`), so
`joinedload` (a single SQL JOIN) is the right tool — it doesn't multiply
row counts the way joining a to-many relationship would. If a future
endpoint needs to eager-load a to-many relationship across a paginated
list (e.g. "each Case with all its related Alerts"), the correct tool is
`selectinload`, not `joinedload`, specifically to avoid the row-count
multiplication a JOIN across a one-to-many would cause against a paginated
query. No such case exists yet in this codebase; noted here so the choice
isn't re-litigated from scratch when one does.

**Do not eager-load "just in case."** `Transaction.user`,
`Case.alert`, `BehaviorEvent.user`, and `Device.user` are not eager-loaded
anywhere, because nothing currently serializes them. Eager-loading a
relationship no response schema reads is a wasted JOIN on every request
that uses that query — the same class of premature-optimization YAGNI
violation as adding a cache for data nothing re-reads.

## How to verify this policy is actually followed

`tests/test_pagination.py::test_alerts_include_eager_loaded_transaction_summary`
and `::test_admin_audit_includes_eager_loaded_actor_email` assert the
*data* the eager-load exists to serve is actually present in the response
— not just that the endpoint returns 200. A `joinedload()` call with
nothing downstream ever reading the relationship would pass a "does this
crash" test while providing zero actual benefit; asserting the served data
is what makes the eager-load load-bearing rather than decorative.
