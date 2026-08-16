"""Pydantic v2 schemas for change 16's evidence views (docs/v2_migration/MIGRATION-01-evidence-
first.md, changes 2, 11, 16):

    GET /api/incidents/{id}/evidence     per-incident evidence section (primary, change 16) +
                                          `highlight_lines` / `highlight_line_violations`
                                          (change 11)
    GET /api/analyses/{id}/evidence      analysis-wide evidence browser (secondary, change 16),
                                          including evidence that never formed an incident

Both routes live in `app.api.incident_detail`, not here — this module only owns the wire shapes,
matching every other `app.schemas.*` module's split from its router.

**Why these are their own routes, not fields folded into `IncidentDetail`.** Mirrors
`app.schemas.incident`'s own precedent: `/timeline` and `/graph` are already separate routes
"so the case file's sections stream in independently" rather than embedded in the composite
detail response. `EvidencePayload` computation
(`app.agent.context.compute_evidence_payloads`) re-runs every extractor over the analysis's
events — that module's own docstring spells out the cost — so folding it into
`GET /api/incidents/{id}` would make *every* case-file load pay that cost even when the
evidence section is never scrolled to. A sibling route lets the frontend fetch it independently.

## Change 11 — `highlight_lines` is derived, never LLM-authored

"The analysis layer decides which lines are anomalous ... the LLM receives `highlight_lines` as
input and may not add to it." `IncidentEvidenceResponse.highlight_lines` is computed in
`app.api.incident_detail` as the union of `contributing_line_numbers` across every
`EvidencePayload` that belongs to the incident (via `app.agent.context.build_agent_context`'s
own entity+window filtering) — never read off the verdict or the narrative. `highlight_line_
violations` (see `highlight_line_violations` below) is the enforcement half: it reports every
`LOG-n` citation in the verdict's *narrative* that falls outside that derived set, which is
exactly a presenter having "added" a line the attribution layer never nominated.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.detection.evidence.payload import EvidencePayload

__all__ = [
    "AnalysisEvidenceResponse",
    "EvidencePayloadOut",
    "IncidentEvidenceResponse",
    "evidence_payload_out",
    "highlight_line_violations",
]


class EvidencePayloadOut(BaseModel):
    """`app.detection.evidence.payload.EvidencePayload`, serialised for the wire. `entity`/
    `window` are flattened from the dataclass's `dict`/`tuple` fields into `entity_type`/
    `entity_value`/`window_start`/`window_end` to match `SignalOut`/`EntityOut`'s own
    convention elsewhere in `app.schemas.incident`.

    `historical` is passed through verbatim, not narrowed to a typed model — change 1's cold-
    start contract (`{prefix}_baseline_status: "insufficient_history"`, `{prefix}_n_windows`,
    `app.detection.evidence.payload.historical_from_percentile`) lives inside it exactly as the
    extractor layer produced it. Narrowing this here would mean re-declaring six extractors'
    worth of different historical-context shapes (some single-scope, burst triple-namespaced by
    `user_`/`department_`/`org_` prefixes) for no gain over passing the dict straight through —
    the frontend's evidence cards already read it defensively, the same way every detector
    explanation payload in this codebase is rendered (`ExplanationRenderer`, never raw JSON, but
    also never assuming a rigid shared shape across detectors).
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    extractor: str
    entity_type: str
    entity_value: str
    window_start: datetime
    window_end: datetime
    measurements: dict[str, Any]
    historical: dict[str, Any]
    contributing_line_numbers: list[int]
    nominates_candidate: bool
    nomination_score: float | None
    # Which of this analysis's incidents this payload contributed to (entity+window overlap,
    # same rule `app.agent.context._filter_evidence_for_incident` triage runs on) — change 16:
    # "including evidence that never formed an incident". An empty list is the expected, common
    # case on the analysis-wide browser, not missing data. Always `[incident_id]` on the
    # per-incident route, where membership is the query itself.
    incident_ids: list[uuid.UUID]


def evidence_payload_out(
    payload: EvidencePayload, *, incident_ids: Sequence[uuid.UUID] = ()
) -> EvidencePayloadOut:
    window_start, window_end = payload.window
    return EvidencePayloadOut(
        evidence_id=payload.evidence_id,
        extractor=payload.extractor,
        entity_type=payload.entity.get("type", ""),
        entity_value=payload.entity.get("value", ""),
        window_start=window_start,
        window_end=window_end,
        measurements=payload.measurements,
        historical=payload.historical,
        contributing_line_numbers=list(payload.contributing_line_numbers),
        nominates_candidate=payload.nominates_candidate,
        nomination_score=payload.nomination_score,
        incident_ids=list(incident_ids),
    )


class IncidentEvidenceResponse(BaseModel):
    items: list[EvidencePayloadOut]
    # change 11: the attribution-derived union of every item's `contributing_line_numbers`,
    # sorted. Authoritative — a presenter citation outside this set is what `highlight_line_
    # violations` reports, not a reason to widen this list.
    highlight_lines: list[int]
    highlight_line_violations: list[int]


class AnalysisEvidenceResponse(BaseModel):
    items: list[EvidencePayloadOut]
    total: int
    truncated: bool


def highlight_line_violations(
    narrative: Sequence[dict[str, Any]] | None, highlight_lines: Sequence[int]
) -> list[int]:
    """change 11 enforcement: "if the presenter references a line outside the set, it is a
    scope violation." `narrative` is `TriageVerdict.narrative` — a list of
    `NarrativeStep.model_dump()` dicts (`app.agent.schemas.NarrativeStep`), each step's
    `evidence_ids` a tuple mixing `EVIDENCE-n` / `BASELINE-n` / `LOG-n` / `MITRE-*` /
    `ZSCALER-KB-*` citation strings (change 7). Only `LOG-` citations reference a raw line
    number at all — everything else is ignored here, not flagged.

    Returns every cited raw line number that falls **outside** `highlight_lines`, sorted and
    de-duplicated. An empty result means every `LOG-n` citation in this verdict's narrative
    stayed inside the attribution-derived set.

    This is a reporting function, not a rewrite: it does not strip the offending claim from the
    narrative (that would be `app.agent`'s job, out of this package's ownership) — it closes a
    gap that existed before it: `app.agent.verifier`'s own citation "scope" check (docs/07 check
    4) is a *time-window* check (±1h of the incident), not a check against this specific
    attribution-derived line set, so nothing before this counted a `highlight_lines` violation
    as its own, reportable thing.

    Tolerant of malformed input on purpose (`narrative` is LLM-authored JSONB, same "one
    malformed entry should cost that entry, not the whole page" policy as
    `app.api.incident_detail._technique_ids`): a step that isn't a dict, or a citation that
    isn't a `LOG-{int}` string, is skipped rather than raising.
    """
    allowed = set(highlight_lines)
    cited: set[int] = set()
    for step in narrative or ():
        if not isinstance(step, dict):
            continue
        for citation_id in step.get("evidence_ids") or ():
            if not isinstance(citation_id, str) or not citation_id.startswith("LOG-"):
                continue
            try:
                line_no = int(citation_id[len("LOG-") :])
            except ValueError:
                continue
            cited.add(line_no)
    return sorted(cited - allowed)
