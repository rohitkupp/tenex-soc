"""Citation verification — docs/07-AGENT.md "Citation verification", the anti-hallucination
guarantee, run after every verdict. For each `narrative[].evidence_event_ids` entry:

    1. Existence — the ID exists in `events` for this analysis.
    2. Scope — the event's entities intersect the incident's `entity_ids`.
    3. Temporal plausibility — the event falls within the incident's time window +/- 1h.

    All checks pass -> citation_valid = true
    Any failure -> record in invalid_citations, set citation_valid = false, and render the
    affected claim in the UI with a warning marker rather than hiding it.

"Never silently drop a bad citation" — `invalid_citations` always lists every failing citation
with which specific check(s) failed, never just a boolean. This module never removes a bad
citation from `narrative`; the caller (orchestrator) persists the narrative exactly as given and
lets the flag do the work.

`hallucination_rate = invalid_citations / total_citations` (docs/12) is a simple ratio over this
module's own output — `HallucinationStats` below computes it directly so eval/reporting code
doesn't have to re-derive it.

## Confidence integrity (docs/v2_migration change 3, arriving early as change 7's own check)

`verify_anomaly_confidence` below is a **different kind of check from citation verification
above** — deliberately so. Citation failures are surfaced, not suppressed: a bad citation gets
flagged in `invalid_citations` and the claim still renders, with a warning marker. A changed
`anomaly_confidence` gets no such leniency: `anomaly_confidence` is not something the LLM has any
basis to recompute (it never sees raw detector scores, only the one already-calibrated number),
so any difference from the value it was given is not "weak evidence" the way a shaky citation can
be — it is either a copy that happened to be exact, or the model overrode a number CLAUDE.md rule
5 says it never gets to touch. `app.agent.orchestrator` treats a failure here as a hard rejection
of the whole verdict (the run falls back to `needs_review` with the failure reason recorded in
`needs_review_reason`), not a flag rendered alongside an otherwise-trusted verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import select

from app.agent.context import CITATION_TEMPORAL_SLACK, AgentContext
from app.agent.schemas import SchemaValidationError, TriageVerdictOut
from app.models.base import tenant_scope
from app.models.event import Event

__all__ = [
    "ANOMALY_CONFIDENCE_TOLERANCE",
    "AnomalyConfidenceCheck",
    "AnomalyConfidenceIntegrityError",
    "CitationCheck",
    "HallucinationStats",
    "hallucination_stats",
    "parse_verdict_payload",
    "verify_anomaly_confidence",
    "verify_citations",
]

# Both `ctx.anomaly_confidence` and `verdict.anomaly_confidence` are already rounded to one
# decimal place before comparison here (`AgentContext.anomaly_confidence`,
# `app.detection.fusion.anomaly_confidence_from_fused_score`) -- this tolerance only needs to
# absorb IEEE-754 binary representation noise from that rounding and from Postgres' `REAL`
# (4-byte float) column round-tripping the value, not from any legitimate "close enough" reading
# of the model's output. A real change (the model rounding, adjusting, or recomputing the number)
# will always differ by orders of magnitude more than this.
ANOMALY_CONFIDENCE_TOLERANCE: Final[float] = 1e-6


@dataclass(frozen=True, slots=True)
class CitationCheck:
    step: int
    claim: str
    event_id: int
    existence_ok: bool
    scope_ok: bool
    temporal_ok: bool

    @property
    def valid(self) -> bool:
        return self.existence_ok and self.scope_ok and self.temporal_ok

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "claim": self.claim,
            "event_id": self.event_id,
            "existence_ok": self.existence_ok,
            "scope_ok": self.scope_ok,
            "temporal_ok": self.temporal_ok,
        }


@dataclass(frozen=True, slots=True)
class HallucinationStats:
    total_citations: int
    invalid_citations: int

    @property
    def hallucination_rate(self) -> float:
        if self.total_citations == 0:
            return 0.0
        return self.invalid_citations / self.total_citations


def hallucination_stats(checks: list[CitationCheck]) -> HallucinationStats:
    return HallucinationStats(
        total_citations=len(checks), invalid_citations=sum(1 for c in checks if not c.valid)
    )


class AnomalyConfidenceIntegrityError(Exception):
    """Raised by `app.agent.orchestrator._run_flow` when `verify_anomaly_confidence` fails —
    caught alongside `AgentTimeoutError`/`AgentRefusalError`/`SchemaValidationError`/`ToolError`
    in `app.agent.orchestrator.triage_incident`, which converts it into a `needs_review` verdict
    with the reason recorded in `needs_review_reason`. A hard rejection of the *whole* verdict,
    not a per-claim flag — see this module's own docstring for why confidence integrity gets
    different treatment from citation verification."""


@dataclass(frozen=True, slots=True)
class AnomalyConfidenceCheck:
    expected: float
    actual: float
    ok: bool
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "actual": self.actual,
            "ok": self.ok,
            "reason": self.reason,
        }


def verify_anomaly_confidence(
    ctx: AgentContext, verdict: TriageVerdictOut
) -> AnomalyConfidenceCheck:
    """docs/v2_migration change 3: **the LLM may not modify `anomaly_confidence`.** `ctx.
    anomaly_confidence` is the value actually persisted on `incidents.anomaly_confidence` (read
    once in `app.agent.context.build_agent_context`); `verdict.anomaly_confidence` is whatever the
    Reporter's `emit_verdict` call echoed back after being instructed, in the prompt, to reproduce
    it unchanged (`app.agent.prompts.REPORTER_SYSTEM_PROMPT`). Anything outside
    `ANOMALY_CONFIDENCE_TOLERANCE` is a failure, with a reason that names both values — this is a
    deterministic code check, not a prompt hope, and the reason string is what makes the rejection
    inspectable rather than a silent `False`."""
    expected = ctx.anomaly_confidence
    actual = verdict.anomaly_confidence
    ok = abs(expected - actual) <= ANOMALY_CONFIDENCE_TOLERANCE
    reason = (
        None
        if ok
        else (
            f"anomaly_confidence integrity check failed: incident {ctx.incident_id} carries "
            f"{expected!r}, the model's emit_verdict returned {actual!r} instead. "
            "anomaly_confidence is upstream-computed (app.detection.fusion."
            "anomaly_confidence_from_fused_score) and the LLM has no basis to change it — "
            "CLAUDE.md rule 5, docs/v2_migration change 3."
        )
    )
    return AnomalyConfidenceCheck(expected=expected, actual=actual, ok=ok, reason=reason)


def verify_citations(
    ctx: AgentContext, verdict: TriageVerdictOut
) -> tuple[bool, list[dict[str, Any]], list[CitationCheck]]:
    """Runs all three checks for every citation in `verdict.narrative`. Returns
    `(citation_valid, invalid_citations, all_checks)` — `citation_valid`/`invalid_citations` are
    exactly the two `TriageVerdictOut`/`triage_verdicts` fields docs/07 names; `all_checks` is
    returned too so callers that want `hallucination_stats` (eval reporting) don't have to
    re-run the checks.

    A narrative with zero citations (only possible when `disposition == "needs_review"` — see
    `TriageVerdictOut._narrative_required_unless_needs_review`) is vacuously
    `citation_valid = True`: there is nothing to have hallucinated."""
    cited_event_ids = {eid for step in verdict.narrative for eid in step.evidence_event_ids}

    events_by_id: dict[int, Event] = {}
    if cited_event_ids:
        with tenant_scope(ctx.session, ctx.tenant_id):
            rows = (
                ctx.session.execute(
                    select(Event)
                    .where(Event.analysis_id == ctx.analysis_id)
                    .where(Event.id.in_(cited_event_ids))
                )
                .scalars()
                .all()
            )
        events_by_id = {e.id: e for e in rows}

    lo = ctx.window_start - CITATION_TEMPORAL_SLACK
    hi = ctx.window_end + CITATION_TEMPORAL_SLACK

    checks: list[CitationCheck] = []
    for step in verdict.narrative:
        for event_id in step.evidence_event_ids:
            event = events_by_id.get(event_id)
            existence_ok = event is not None
            scope_ok = False
            temporal_ok = False
            if event is not None:
                pairs = ctx.event_entity_pairs(
                    principal=event.principal,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    domain=event.domain,
                )
                scope_ok = bool(pairs & ctx.entity_scope)
                temporal_ok = lo <= event.ts <= hi
            checks.append(
                CitationCheck(
                    step=step.step,
                    claim=step.claim,
                    event_id=event_id,
                    existence_ok=existence_ok,
                    scope_ok=scope_ok,
                    temporal_ok=temporal_ok,
                )
            )

    invalid = [c.as_dict() for c in checks if not c.valid]
    citation_valid = len(invalid) == 0
    return citation_valid, invalid, checks


def parse_verdict_payload(raw: dict[str, Any]) -> TriageVerdictOut:
    """docs/06 defense #5 ("Output validation... Failures are rejected, not coerced"): parse a
    raw `emit_verdict` tool-call payload into a validated `TriageVerdictOut`, or raise
    `SchemaValidationError` with every field error collected. This is the second, independent
    layer behind the tool-schema enums (see `app.agent.schemas`'s module docstring) — the layer
    that lets a test prove a fabricated technique/action id cannot survive validation without
    needing a live or fixture API response that somehow bypassed layer one."""
    try:
        return TriageVerdictOut.model_validate(raw)
    except ValidationError as exc:
        raise SchemaValidationError(str(exc)) from exc
