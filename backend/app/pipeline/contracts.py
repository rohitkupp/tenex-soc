"""Stage contracts — docs/01-ARCHITECTURE.md "Stage contracts" table:

| Stage | Precondition | Postcondition |
|---|---|---|
| ingest | file in MinIO | `analyses` row, source types detected, `pending_parsers` set |
| parse | raw artifact exists | `events` rows written, `parse_failure_rate` recorded |
| enrich | events exist | `events.enrichment` populated, `entities` seeded |
| anonymize | events enriched | privacy audit counted (see below) |
| detect | events anonymized | `signals` rows with calibrated confidence |
| correlate | signals exist | `entities`, `entity_edges`, `incidents` |
| triage | incidents exist | `triage_verdicts` for top-N, citations verified |
| tier2 | verdicts exist | `tier2_signatures` rows |

Every stage is real, wired to a live queue worker (`app/pipeline/stages/*.py`, one module per
row above — `enrich`, `anonymize`, `detect`, `correlate`, and `triage`/`tier2` were skeletons
through M4; the post-skeleton wiring made every one of them do the real work its own module
docstring describes).

`anonymize`'s postcondition is *not* docs/01's literal original wording ("`pseudonym_map`
written, `events.redacted` populated") — that names two structures docs/02 never actually
specified and no migration ever added. `app.pipeline.stages.anonymize`'s own module docstring
explains why the real, honest postcondition here is a privacy *audit* (genuine pseudonymization/
redaction counts, computed for real) rather than a redacted copy of every event at rest — the
per-call enforcement point (`app.agent.context`, CLAUDE.md rule 4) already exists and does not
depend on this stage having run.

The `respond` stage (response action graph / enforcement plane) was removed in
docs/v2_migration change 20. `triage` forwards directly to `tier2` — see `NEXT_QUEUE`.
"""

from __future__ import annotations

from typing import Any

# Order matches the table above. Used only to compute `STAGE_PROGRESS` below — nothing
# iterates this to decide routing (`NEXT_QUEUE` does that explicitly, since the
# ingest -> parse hop fans out to N queues and the parse -> enrich hop is gated by
# `pending_parsers`, neither of which is "the next name in a list").
STAGE_SEQUENCE: tuple[str, ...] = (
    "ingest",
    "parse",
    "enrich",
    "detect",
    "correlate",
    "triage",
    "anonymize",
    "tier2",
)

# `analyses.progress` on completion of each stage — a simple 1/8, 2/8, ... ladder. The
# funnel counters (docs/01 "Progress streaming") are the headline UI element; this
# number is secondary (a progress bar position), so an even split is a deliberate,
# defensible simplification rather than a weighted estimate of real stage cost.
STAGE_PROGRESS: dict[str, float] = {
    stage: round((i + 1) / len(STAGE_SEQUENCE), 4) for i, stage in enumerate(STAGE_SEQUENCE)
}

# Skeleton stages (M5+) forward 1:1 to the next queue once M4's pass-through runs.
# `parse` is deliberately absent — its fan-in (pending_parsers -> single q.enrich
# publish) is handled explicitly in app.pipeline.stages.parse, not by this table.
#
# `triage` -> `tier2` directly: `respond` (the response action graph / enforcement plane) was
# removed in docs/v2_migration change 20, closing the gap in the chain so `triage` never
# publishes into a queue that no longer exists.
# `anonymize` moved from between `enrich` and `detect` to between `triage` and `tier2`.
#
# In its old position it could not actually anonymise anything. Every stage downstream of it
# needed the plaintext — a detector cannot match `u_8f3a91c204de` against a baseline built from
# `alice@corp.example`, correlation cannot group entities it can no longer recognise, and the
# agent's evidence would cite pseudonyms it has no way to resolve. So the stage degraded to an
# audit: it computed how many identifiers *would* have been pseudonymised and wrote the count to
# a counter, while its own docstring conceded it "does not rewrite any row".
#
# The boundary CLAUDE.md rule 4 actually names is where data leaves the tenant, and that is
# `tier2` — the one cross-tenant surface in the system. Sitting immediately before it, the stage
# does the thing it is named for: pseudonymise, redact, and write the result into the Tier 2
# database. The count and the act become the same operation.
NEXT_QUEUE: dict[str, str | None] = {
    "enrich": "detect",
    "detect": "correlate",
    "correlate": "triage",
    "triage": "anonymize",
    "anonymize": "tier2",
    "tier2": None,  # terminal — docs/01's `tier2-sync` "Produces" column is "—"
}

# The `analyses.stage` value each queue's traffic represents. The parser queue(s) all collapse to
# the single "parse" stage label — from the pipeline's perspective (and the UI's) they are one
# stage fanned out across source types, not one stage per source. ZScaler is the only source
# today (Okta and CloudTrail were removed), so this collapses to one entry, but the label stays
# keyed by queue name rather than hardcoded to "parse.zscaler" so adding a source back is "add one
# more `parse.<source>` key here", not a structural change.
QUEUE_STAGE_LABEL: dict[str, str] = {
    "orchestrator": "ingest",
    "parse.zscaler": "parse",
    "enrich": "enrich",
    "anonymize": "anonymize",
    "detect": "detect",
    "correlate": "correlate",
    "triage": "triage",
    "tier2": "tier2",
}

# Source type -> its parse queue. One entry today (ZScaler); this is the fan-out table
# `app.pipeline.stages.orchestrator` iterates to publish one `StageMessage` per detected source
# type, and `app.pipeline.stages.parse`'s fan-in gate (`pending_parsers`) is sized off its length
# for a given upload -- both keep working unchanged with one entry, which is what makes adding a
# second source back a one-line addition here rather than a redesign.
PARSER_QUEUES: dict[str, str] = {
    "zscaler": "parse.zscaler",
}

DEFAULT_COUNTERS: dict[str, int] = {
    "events": 0,
    "signals": 0,
    "incidents": 0,
    "needs_attention": 0,
}


def public_counters(raw: dict[str, Any] | None) -> dict[str, int]:
    """Project a raw `analyses.counters` JSONB read back to exactly the four keys
    docs/09's SSE event and docs/02's column comment name — dropping any internal
    bookkeeping keys a stage may have stashed alongside them (see
    `app.pipeline.stages.parse` for why `_parse_failed_lines` lives in the same JSONB
    column but must never reach the wire). Every SSE/Redis publish call site uses this
    rather than forwarding a DB row's `counters` verbatim."""
    raw = raw or {}
    return {key: int(raw.get(key) or 0) for key in DEFAULT_COUNTERS}
