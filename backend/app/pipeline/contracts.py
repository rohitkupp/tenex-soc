"""Stage contracts — docs/01-ARCHITECTURE.md "Stage contracts" table, matched exactly:

| Stage | Precondition | Postcondition |
|---|---|---|
| ingest | file in MinIO | `analyses` row, source types detected, `pending_parsers` set |
| parse | raw artifact exists | `events` rows written, `parse_failure_rate` recorded |
| enrich | events exist | `events.enrichment` populated, `entities` seeded |
| anonymize | events enriched | `pseudonym_map` written, `events.redacted` populated |
| detect | events anonymized | `signals` rows with calibrated confidence |
| correlate | signals exist | `entities`, `entity_edges`, `incidents` |
| triage | incidents exist | `triage_verdicts` for top-N, citations verified |
| respond | verdicts exist | `response_plans` in `pending_approval` |
| tier2 | plans exist | `tier2_signatures` rows |

`ingest` and `parse` are real as of this milestone (M4's "the real parse stage"); every
stage from `enrich` on is a **documented skeleton** until its own milestone (M5 through
M14 per docs/13) — each one honestly advances `analyses.stage`/`progress`, forwards the
`StageMessage`, and says in its progress `message` that it is a pass-through, rather
than claiming a postcondition it did not actually produce.
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
    "anonymize",
    "detect",
    "correlate",
    "triage",
    "respond",
    "tier2",
)

# `analyses.progress` on completion of each stage — a simple 1/9, 2/9, ... ladder. The
# funnel counters (docs/01 "Progress streaming") are the headline UI element; this
# number is secondary (a progress bar position), so an even split is a deliberate,
# defensible simplification rather than a weighted estimate of real stage cost.
STAGE_PROGRESS: dict[str, float] = {
    stage: round((i + 1) / len(STAGE_SEQUENCE), 4) for i, stage in enumerate(STAGE_SEQUENCE)
}

# Skeleton stages (M5+) forward 1:1 to the next queue once M4's pass-through runs.
# `parse` is deliberately absent — its fan-in (pending_parsers -> single q.enrich
# publish) is handled explicitly in app.pipeline.stages.parse, not by this table.
NEXT_QUEUE: dict[str, str | None] = {
    "enrich": "anonymize",
    "anonymize": "detect",
    "detect": "correlate",
    "correlate": "triage",
    "triage": "respond",
    "respond": "tier2",
    "tier2": None,  # terminal — docs/01's `tier2-sync` "Produces" column is "—"
}

# Skeleton stages' honest description of what they do at M4, surfaced verbatim in the
# progress `message` sent to Redis/SSE so the UI (and this report) never implies work
# that has not shipped yet.
SKELETON_MESSAGE: dict[str, str] = {
    "enrich": "Enrichment stage — pass-through skeleton, real enrichment lands at M5.",
    "anonymize": "Anonymization stage — pass-through skeleton, real redaction lands at M5.",
    "detect": "Detection stage — pass-through skeleton, real detectors land M6-M9.",
    "correlate": "Correlation stage — pass-through skeleton, real graph correlation lands at M10.",
    "triage": "Triage stage — pass-through skeleton, the real agent lands at M11.",
    "respond": "Response stage — pass-through skeleton, the real response graph lands at M12.",
    "tier2": "Tier 2 sync — pass-through skeleton, real signature sync lands at M14.",
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
    "respond": "respond",
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
