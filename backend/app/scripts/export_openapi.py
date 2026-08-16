"""`python -m app.scripts.export_openapi` — regenerates `backend/openapi.json`, the committed
snapshot of `app.main.app`'s OpenAPI schema.

change 25 (docs/v2_migration/MIGRATION-01-evidence-first.md), Contract row: "OpenAPI schema
matches generated TS types ... schema drift fails CI." The committed `openapi.json` is the single
source of truth both halves of that gate compare against:

1. `tests/test_contract_openapi_schema.py` (backend, runs in the normal `pytest` CI job)
   regenerates the schema live from `app.main.app` and asserts it is byte-for-byte identical to
   this committed file — a real assertion, not a comment, per change 25's "schema drift fails CI."
2. `frontend/package.json`'s `gen:api` script points `openapi-typescript` at this same committed
   file (a local path, not a live server URL) rather than `http://localhost:8000/api/openapi.json`
   — the schema this repo's TypeScript types are generated from should be exactly the schema this
   repo's own tests already prove the backend produces, and pointing at a file (not a live server)
   is what lets the frontend CI job run the drift check with zero backend/DB/RabbitMQ dependency.

`app.main.app.openapi()` needs no live database or broker connection — it is pure route/Pydantic-
model introspection, computed once and cached by FastAPI (`app.openapi_schema`) — so this script
(and the pytest test that mirrors it) is safe to run standalone, the same way `app/scripts/seed*.
py` already assume a running Postgres but this one deliberately does not.

Run this after any change to a route's request/response model, then re-run
`cd frontend && npm run gen:api` to regenerate `lib/api/schema.d.ts` from the new snapshot, and
commit both files together — same discipline as an Alembic migration and its model change.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.logging import configure_logging, get_logger

log = get_logger(__name__)

# backend/openapi.json — a sibling of this package's grandparent (app/scripts/ -> app/ -> backend/).
OPENAPI_SNAPSHOT_PATH = Path(__file__).resolve().parents[2] / "openapi.json"


def render_schema_json() -> str:
    """The exact bytes both the export script and the drift test compare against: `app.main.app`'s
    OpenAPI schema, serialized deterministically (sorted keys, 2-space indent, trailing newline)
    so the committed file has a stable diff and importing `app.main` twice in the same process
    (script once, test once) never produces a spurious difference from key ordering alone."""
    from app.main import app  # imported lazily -- app.main has import-time side effects

    # openapi() lazily builds and caches `app.openapi_schema`; called fresh here regardless of
    # whether some earlier import in this process already triggered it.
    schema = app.openapi()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> None:
    configure_logging("info")
    rendered = render_schema_json()
    OPENAPI_SNAPSHOT_PATH.write_text(rendered, encoding="utf-8")
    log.info(
        "export_openapi.written",
        path=str(OPENAPI_SNAPSHOT_PATH),
        bytes=len(rendered),
    )


if __name__ == "__main__":
    main()
