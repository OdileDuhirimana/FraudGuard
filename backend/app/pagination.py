"""
Shared offset-based pagination for list endpoints.

Why: the audit found list endpoints using hardcoded `.limit(100)` /
`.limit(200)` with no client-controllable offset — that's a cap, not
pagination. This module gives every list endpoint the same `page`/`page_size`
query-parameter contract and the same response envelope, so a client only
has to learn the pattern once.

Design decision: offset-based (not cursor-based) pagination was chosen
because the underlying tables (alerts, audit logs, users) are queried by
admins/analysts in an ops/dashboard context, not a high-throughput public
feed — offset pagination's O(n) skip cost is an acceptable tradeoff for the
simplicity and "jump to page N" UX it provides. If these tables grow to
millions of rows, a keyset/cursor approach (via `id < last_id`) would be the
next step; documented as a known limitation in the README.
"""
from __future__ import annotations

from typing import Generic, Sequence, TypeVar

from fastapi import Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Query as SAQuery

T = TypeVar("T")

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 25


class PageParams:
    """
    FastAPI dependency that validates and exposes pagination query params.

    `page` is 1-indexed for a friendlier API surface; `page_size` is capped
    server-side (MAX_PAGE_SIZE) regardless of what a client requests, so a
    caller cannot force an unbounded/near-unbounded query (the exact
    DB-07/SCALE-05 issue previously found on `/fraud/graph` and the admin
    list endpoints).
    """

    def __init__(
        self,
        page: int = Query(1, ge=1, description="1-indexed page number"),
        page_size: int = Query(
            DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Items per page"
        ),
    ) -> None:
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class PageMeta(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int


class Page(BaseModel, Generic[T]):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    items: Sequence[T]
    meta: PageMeta


def paginate(query: SAQuery, params: PageParams) -> tuple[list, PageMeta]:
    """
    Apply offset/limit to a SQLAlchemy query and compute page metadata in a
    single extra COUNT query. Callers are responsible for applying filters
    and ordering to `query` before calling this.

    BUG FIX (found during functional verification): this previously computed
    the count via `query.order_by(None).with_entities(func.count()).scalar()`.
    On SQLAlchemy 2.0, `with_entities(func.count())` on a Query does not
    reliably preserve the original FROM clause — for every call site in this
    codebase (including ones with no joinedload at all, e.g. `/admin/users`)
    it silently compiled to the FROM-less `SELECT count(*) AS count_1`, which
    SQLite (and most backends) evaluate as a single-row scalar subquery
    returning 1, regardless of how many rows actually matched. `items` were
    never affected (a separate, correct `.offset().limit().all()` call), but
    `meta.total_items`/`meta.total_pages` were wrong on every paginated list
    endpoint, which breaks any client relying on them to know whether more
    pages exist. `Query.count()` is the correct, documented idiom here: it
    wraps the query (filters, joins, joinedload options and all) in a
    subquery and counts that, which both keeps the FROM clause intact and
    avoids joinedload row-fanout inflating the count. `order_by(None)` first
    because the ORDER BY is irrelevant to a count and some backends reject
    it inside the subquery `Query.count()` builds.
    """
    total_items = query.order_by(None).count()
    items = query.offset(params.offset).limit(params.page_size).all()
    total_pages = (total_items + params.page_size - 1) // params.page_size if total_items else 0
    meta = PageMeta(
        page=params.page,
        page_size=params.page_size,
        total_items=total_items,
        total_pages=total_pages,
    )
    return items, meta
