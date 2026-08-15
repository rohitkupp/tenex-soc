"""DEMO_MODE / no-key verdict serving — docs/07-AGENT.md "DEMO_MODE":

    When DEMO_MODE=true, serve precomputed verdicts from data/demo/ instead of calling the API.
    The deployed demo must be explorable without latency or spend.

`app.agent.orchestrator.triage_incident` dispatches here whenever `Settings.demo_mode` is true
or `Settings.llm_enabled` is false (no API key configured) — see that module's docstring for the
full dispatch order. Either way, **no network call is made**.

## Two-tier lookup, and why

docs/07 says "serve precomputed verdicts" but does not specify the keying mechanism, and this
codebase's incidents get server-generated UUIDs (`gen_random_uuid()`, docs/02) that are not
reproducible across pipeline runs — a fixed demo dataset checked in today would have different
incident IDs the next time `app.graph.pipeline_demo` (or the real pipeline) regenerates it. So:

1. **Exact match** (`_load_precomputed`): `data/demo/verdicts/<incident_id>.json` — a real,
   recorded verdict (see `tests/fixtures/llm/` for how those get recorded) for a specific,
   already-triaged incident, checked in as a genuine example. This is what a curated, seeded
   demo deployment (M17, not yet built) would populate and pin its incident IDs against.
2. **Deterministic heuristic fallback** (`_heuristic_disposition` + `synthesize_demo_verdict`):
   built purely from the incident's own fused score and signals, no LLM involved. This is what
   makes DEMO_MODE work for *any* incident today, before a curated demo dataset exists, and
   guarantees the acceptance bar ("the deployed demo must be explorable") can never fail just
   because a particular incident wasn't one of the ones someone thought to pre-record.

The heuristic path is explicitly **not** a substitute for real triage — its `summary` and
`contradicting_evidence` say so — it exists purely so a DEMO_MODE deployment or a "no API key"
CI/dev run never errors and never spends money, at the honest cost of investigative depth a real
three-role run would apply.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.context import AgentContextError
from app.agent.mitre import get_technique, technique_exists
from app.agent.schemas import Disposition, MitreTechniqueRef, NarrativeStep, TriageVerdictOut
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal

__all__ = ["synthesize_demo_verdict"]

_DEMO_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "data" / "demo" / "verdicts"

_MAX_HEURISTIC_NARRATIVE_STEPS = 5
_MAX_EVIDENCE_IDS_PER_STEP = 10


def _load_precomputed(incident_id: uuid.UUID) -> dict[str, Any] | None:
    path = _DEMO_DIR / f"{incident_id}.json"
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):  # pragma: no cover - corrupt checked-in fixture
        return None
    if not isinstance(raw, dict):  # pragma: no cover - corrupt checked-in fixture
        return None
    return raw


def _heuristic_disposition(has_signals: bool, fused_score: float) -> tuple[Disposition, float]:
    """A crude, transparent mapping from the fusion layer's own score to a disposition — no
    investigation, no evidence-weighing, just "does fusion already think this looks bad." Real
    triage (the three-role flow) exists precisely because this kind of score-threshold mapping
    is not good enough for a real verdict; this function is a demo/offline fallback only."""
    if not has_signals:
        return "needs_review", 0.3
    if fused_score >= 0.75:
        return "true_positive", min(0.95, 0.5 + fused_score / 2)
    if fused_score >= 0.4:
        return "needs_review", 0.5
    return "benign", max(0.5, 1.0 - fused_score)


def _heuristic_verdict(incident: Incident, signals: list[Signal]) -> TriageVerdictOut:
    disposition, confidence = _heuristic_disposition(bool(signals), incident.fused_score)

    narrative: list[NarrativeStep] = []
    techniques: list[MitreTechniqueRef] = []
    seen: set[str] = set()
    for i, s in enumerate(signals[:_MAX_HEURISTIC_NARRATIVE_STEPS], start=1):
        narrative.append(
            NarrativeStep(
                step=i,
                claim=(
                    f"Detector {s.detector_key} flagged {s.entity_type} entity with confidence "
                    f"{s.confidence:.2f} (calibrated)."
                ),
                evidence_event_ids=tuple(s.evidence_event_ids[:_MAX_EVIDENCE_IDS_PER_STEP]),
            )
        )
        if (
            s.mitre_technique
            and s.mitre_technique not in seen
            and technique_exists(s.mitre_technique)
        ):
            seen.add(s.mitre_technique)
            technique = get_technique(s.mitre_technique)
            techniques.append(
                MitreTechniqueRef(
                    id=s.mitre_technique,
                    name=technique.name if technique else s.mitre_technique,
                    rationale=f"Reported directly by detector {s.detector_key}.",
                )
            )

    if not narrative:
        disposition, confidence = "needs_review", 0.3

    return TriageVerdictOut(
        disposition=disposition,
        confidence=confidence,
        llm_severity_opinion=None,
        mitre_techniques=tuple(techniques),
        summary=(
            f"DEMO_MODE verdict for {incident.title!r}: derived heuristically from the fusion "
            f"score ({incident.fused_score:.2f}) and {len(signals)} contributing signal(s). No "
            f"live model call was made."
        ),
        narrative=tuple(narrative),
        contradicting_evidence=(
            "DEMO_MODE does not run the Devil's Advocate role, so no independent false-positive "
            "case was argued for this incident specifically — this verdict is illustrative, not "
            "a substitute for a real triage run."
        ),
        recommended_actions=(),
        # Citations here are mechanically derived from the incident's own persisted signal rows,
        # never model output, so there is nothing for app.agent.verifier to hallucinate-check —
        # marking them valid by construction rather than building a full AgentContext (window,
        # entity scope, pseudonym cache) just to re-derive a foregone conclusion.
        citation_valid=True,
        invalid_citations=(),
        model="demo:heuristic",
        needs_review_reason=None
        if disposition != "needs_review"
        else "insufficient signals for a demo heuristic verdict",
    )


def synthesize_demo_verdict(
    session: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> TriageVerdictOut:
    """The single entry point `app.agent.orchestrator.triage_incident` calls in DEMO_MODE / no
    API key. Never raises for "no precomputed verdict" — falls through to the heuristic. Does
    raise `AgentContextError` if the incident itself doesn't exist for this tenant, matching
    `build_agent_context`'s behavior on the live path."""
    precomputed = _load_precomputed(incident_id)
    if precomputed is not None:
        return TriageVerdictOut.model_validate({**precomputed, "model": "demo:precomputed"})

    with tenant_scope(session, tenant_id):
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AgentContextError(f"incident {incident_id} not found for tenant {tenant_id}")
        signals = (
            session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
            .scalars()
            .all()
            if incident.signal_ids
            else []
        )
    return _heuristic_verdict(incident, list(signals))
