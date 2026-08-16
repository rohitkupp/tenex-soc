"""change 25's Contract row: "OpenAPI schema matches generated TS types ... schema drift fails
CI." The two ends of that contract are the OpenAPI schema `app.main.app` actually produces and
`frontend/lib/api/schema.d.ts`, which `openapi-typescript` generates *from* it
(`frontend/package.json`'s `gen:api` script). Both are only trustworthy if neither can silently
drift from the committed `backend/openapi.json` snapshot they share:

* This file is the backend half — it regenerates the schema live from `app.main.app` (no
  database, no broker, no live server: `app.export_openapi.render_schema_json`'s own docstring)
  and asserts it is byte-for-byte identical to the committed snapshot. A route whose
  request/response model changed without anyone running
  `python -m app.scripts.export_openapi` fails here, in the normal `pytest` CI job — a real
  assertion, not a comment.
* The frontend half lives in CI, not here: `.github/workflows/ci.yml`'s `frontend` job runs
  `npm run verify:api-contract`, which regenerates `lib/api/schema.d.ts` from this same committed
  `openapi.json` into a temp file and diffs it against the committed one, failing the build on any
  difference. Nothing in that half needs Python or this test file to know about it, only that the
  same `openapi.json` this test guards is the file it points at.

`test_pipeline_messages.py::test_round_trips_through_encode_decode` is the sibling "matches" test
for the *other* generated-and-checked contract change 25 names for this row, `StageMessage`'s
wire format -- not duplicated here.
"""

from __future__ import annotations

from app.scripts.export_openapi import OPENAPI_SNAPSHOT_PATH, render_schema_json


def test_committed_openapi_snapshot_exists() -> None:
    assert OPENAPI_SNAPSHOT_PATH.exists(), (
        f"{OPENAPI_SNAPSHOT_PATH} is missing -- run `python -m app.scripts.export_openapi` "
        "and commit the result"
    )


def test_live_schema_matches_the_committed_openapi_snapshot() -> None:
    """The real drift gate: regenerate the schema from `app.main.app` right now and compare it,
    byte for byte, to what is checked into `backend/openapi.json`. A route added, removed, or
    changed without a matching `python -m app.scripts.export_openapi` re-run fails here."""
    live = render_schema_json()
    committed = OPENAPI_SNAPSHOT_PATH.read_text(encoding="utf-8")
    assert live == committed, (
        "backend/openapi.json is stale -- the live schema from app.main.app no longer matches "
        "the committed snapshot. Run `python -m app.scripts.export_openapi` from backend/, "
        "review the diff, then `cd frontend && npm run gen:api` to regenerate "
        "lib/api/schema.d.ts to match, and commit all three together."
    )


def test_committed_openapi_snapshot_is_a_real_schema() -> None:
    """A cheap sanity check that the committed file is the real thing and not an empty/truncated
    write -- if this ever fails while the byte-for-byte test above passes, both files are wrong
    in the same way, which the diff test alone would not catch."""
    import json

    schema = json.loads(OPENAPI_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert schema["info"]["title"] == "Tenex SOC Analyst API"
    assert len(schema["paths"]) > 10
