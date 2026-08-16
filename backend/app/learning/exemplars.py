"""Mechanism 10 — curated exemplar bank (change 21, gated). Distinct from mechanism 9
(`app.learning.memory`, dynamic pgvector retrieval, no approval needed): "a stable set of
analyst-corrected findings pinned into the prompt, covering the most frequent error modes ...
deliberate curriculum." An Override (a real correction, not a plain confirm/dismiss) is a
candidate exemplar; gated because pinning a finding into every future Analyst prompt changes what
the system is nudged to believe, per change 21's own line.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.exemplar_bank_entry import ExemplarBankEntry
from app.models.learning_proposal import LearningProposal
from app.models.triage_verdict import TriageVerdict

__all__ = ["accept_exemplar", "propose_exemplar"]

_SUPPORT_TOLERANCE = MetricTolerance("higher_is_better", 0.0)


def _error_mode(feedback: AnalystFeedback, verdict: TriageVerdict) -> str:
    if feedback.corrected_technique and feedback.corrected_technique != "NO_KNOWN_MAPPING":
        return "technique_misattribution"
    if feedback.corrected_disposition and feedback.corrected_disposition != verdict.disposition:
        return "disposition_misjudgment"
    return "general_correction"


def propose_exemplar(
    session: Session, tenant_id: uuid.UUID, feedback: AnalystFeedback, verdict: TriageVerdict
) -> LearningProposal | None:
    """Called on an Override. Not every override is worth a proposal -- one without a note or a
    corrected technique carries too little curriculum value to pin."""
    if feedback.agrees or not (feedback.corrected_technique or feedback.note):
        return None
    payload = {
        "incident_id": str(verdict.incident_id),
        "error_mode": _error_mode(feedback, verdict),
        "finding_summary": verdict.summary,
        "corrected_summary": feedback.note or f"corrected to {feedback.corrected_disposition}",
    }
    return create_proposal(
        session,
        tenant_id,
        mechanism=10,
        payload=payload,
        supporting_feedback_ids=[feedback.id],
        trigger_feedback_id=feedback.id,
    )


def _apply(session: Session, tenant_id: uuid.UUID, proposal: LearningProposal) -> dict[str, Any]:
    with tenant_scope(session, tenant_id):
        entry = ExemplarBankEntry(
            tenant_id=tenant_id,
            incident_id=uuid.UUID(proposal.payload["incident_id"]),
            feedback_id=proposal.supporting_feedback_ids[0],
            error_mode=proposal.payload["error_mode"],
            finding_summary=proposal.payload["finding_summary"],
            corrected_summary=proposal.payload["corrected_summary"],
        )
        session.add(entry)
        session.flush()
    return {"exemplar_bank_entry_id": entry.id, "error_mode": entry.error_mode}


def accept_exemplar(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    """A curated exemplar needs no held-out metric to gate against -- the "evidence" is the
    proposal's own supporting feedback (a real, human-reviewed correction). The gate here is a
    minimal support check: `evaluate_candidate` with a single-point comparison against nothing
    (`baseline_scores=None` -- "no incumbent of this kind yet," `app.learning.retrain.
    evaluate_candidate`'s own documented behavior) always passes; the human clicking Accept *is*
    the review this mechanism is gated on.
    """
    gate = evaluate_candidate({"support": 1.0}, None, tolerances={"support": _SUPPORT_TOLERANCE})
    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=gate.passed,
        metric_delta={},
        reason=gate.reason,
        user_id=user_id,
        apply_fn=_apply,
    )
