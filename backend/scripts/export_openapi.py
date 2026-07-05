"""
Exports the current FastAPI OpenAPI schema to docs/api/openapi.json.

Why this exists (API-06 / API quality doc finding): FastAPI's default
`/docs` Swagger UI is a live, framework-generated surface — real, but not
a *reviewable artifact*. A hiring-committee reviewer (or a teammate
integrating against this API without running it locally) benefits from a
versioned, diffable JSON file they can open directly, and CI benefits from
having something concrete to diff the *current* schema against to catch
accidental breaking changes (see tests/test_openapi_contract.py, which
fails if the live schema and this checked-in file diverge).

Usage:
    cd backend
    python -m scripts.export_openapi

Run this and commit the result whenever an intentional API change is made
(new endpoint, changed request/response shape, etc.) — the contract test
in the test suite exists specifically to catch the case where this file
was *not* regenerated after such a change.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.main import app

OUTPUT_PATH = Path(__file__).resolve().parent.parent.parent / "docs" / "api" / "openapi.json"


def main() -> int:
    schema = app.openapi()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
