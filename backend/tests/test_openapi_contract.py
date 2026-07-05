"""
Contract test: the live OpenAPI schema must match the checked-in snapshot
at docs/api/openapi.json.

Why: this is what actually prevents doc/implementation drift, rather than
just hoping a developer remembers to re-export the schema after changing a
route/schema. If this test fails, it means either (a) the API changed and
scripts/export_openapi.py needs to be re-run and the diff committed, or
(b) the schema file was hand-edited and no longer reflects reality — both
are exactly the kind of drift this test exists to catch in CI before merge.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

SNAPSHOT_PATH = Path(__file__).resolve().parent.parent.parent / "docs" / "api" / "openapi.json"


def test_openapi_schema_matches_checked_in_snapshot(client: TestClient):
    live_schema = client.get("/openapi.json").json()

    assert SNAPSHOT_PATH.exists(), (
        f"{SNAPSHOT_PATH} does not exist. Run `python -m scripts.export_openapi` "
        "from backend/ and commit the result."
    )
    snapshot_schema = json.loads(SNAPSHOT_PATH.read_text())

    assert live_schema == snapshot_schema, (
        "The live OpenAPI schema no longer matches docs/api/openapi.json. "
        "If this API change was intentional, regenerate the snapshot with "
        "`cd backend && python -m scripts.export_openapi` and commit the result."
    )
