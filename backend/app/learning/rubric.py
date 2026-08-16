"""Mechanism 11 — judge rubric evolution (change 21, gated). "An analyst rejecting a finding the
judge PASSED is a judge miss. Cluster misses, propose new rubric items." `14 rejections ignored
known service accounts -> propose rubric item 11.'"

## What counts as "a finding the judge PASSED" here

`app/agent/` (the four-stage Analyst -> Judge -> Verifier -> Presenter pipeline, docs/07) is out
of this milestone's ownership, and `triage_verdicts` carries no separate judge-decision column --
every persisted verdict reached this table only after passing the judge (a REJECTed finding is
never persisted as a verdict at all, `docs/07` change 6). So **every** analyst disagreement
(`agrees=False`) on a persisted verdict is, by construction, a disagreement with a finding the
judge already passed -- exactly the "judge miss" this mechanism clusters. Clustering key is the
dismissal reason category (`app.learning.feedback.DISMISSAL_REASON_CATEGORIES`), the same
taxonomy change 22's Dismiss UI presents -- a real, bounded vocabulary rather than free-text
clustering.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.learning_proposal import LearningProposal
from app.models.triage_verdict import TriageVerdict

__all__ = ["MIN_CLUSTER_SIZE", "accept_rubric_item", "propose_rubric_item"]

MIN_CLUSTER_SIZE = 3
_SUPPORT_TOLERANCE = MetricTolerance("higher_is_better", 0.0)

_RUBRIC_ITEM_TEMPLATES: dict[str, str] = {
    "sanctioned_automation": "Before claiming maliciousness from volume or timing alone, check "
    "whether the source is a known service account or sanctioned automation.",
    "known_business_process": "Check evidence_that_weakens for a documented business process "
    "matching this pattern before treating the anomaly as unexplained.",
    "expected_for_this_entity": "Weight an entity's own historical baseline (baseline_status, "
    "n_windows) before treating a deviation as unexplained.",
    "insufficient_evidence": "Prefer NO_KNOWN_MAPPING or a lower threat_confidence when required "
    "evidence for a technique is marked missing rather than inferring it.",
    "other": "Re-examine benign_alternatives more thoroughly before finalizing threat_confidence.",
}


def _disagreements_by_reason(session: Session, tenant_id: uuid.UUID) -> dict[str, list[uuid.UUID]]:
    with tenant_scope(session, tenant_id):
        rows = session.execute(
            select(AnalystFeedback, TriageVerdict, Incident)
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
            .where(AnalystFeedback.agrees.is_(False))
        ).all()
    by_reason: dict[str, list[uuid.UUID]] = {}
    for feedback, _verdict, _incident in rows:
        reason = feedback.dismissal_reason or "other"
        by_reason.setdefault(reason, []).append(feedback.id)
    return by_reason


def propose_rubric_item(
    session: Session, tenant_id: uuid.UUID, *, trigger_feedback_id: uuid.UUID
) -> LearningProposal | None:
    by_reason = _disagreements_by_reason(session, tenant_id)
    # Only a reason that just crossed the cluster-size threshold with *this* call's feedback
    # proposes -- avoids re-proposing the same rubric item on every subsequent dismissal.
    candidates = {
        reason: ids
        for reason, ids in by_reason.items()
        if len(ids) >= MIN_CLUSTER_SIZE and trigger_feedback_id in ids
    }
    if not candidates:
        return None
    reason, ids = max(candidates.items(), key=lambda kv: len(kv[1]))
    if len(ids) != MIN_CLUSTER_SIZE:
        return None  # already proposed once this cluster crossed the threshold
    proposed_item = _RUBRIC_ITEM_TEMPLATES.get(reason, _RUBRIC_ITEM_TEMPLATES["other"])
    return create_proposal(
        session,
        tenant_id,
        mechanism=11,
        payload={"reason_category": reason, "proposed_item": proposed_item, "n_misses": len(ids)},
        supporting_feedback_ids=ids,
        trigger_feedback_id=trigger_feedback_id,
    )


def accept_rubric_item(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    """No live judge to re-run with the new item (`app/agent/`, out of scope) -- the applied
    state is the accepted rubric text itself, durable on the proposal/`learning_events` row, for
    a future judge-prompt integration to read. See `app.learning.mechanisms`'s module docstring
    for why the support-based comparator, not `evals.gate`, is the right tool here.
    """
    gate = evaluate_candidate({"support": 1.0}, None, tolerances={"support": _SUPPORT_TOLERANCE})
    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=gate.passed,
        metric_delta={"n_misses": proposal.payload["n_misses"]},
        reason=gate.reason,
        user_id=user_id,
        apply_fn=lambda s, t, p: {"rubric_item": p.payload["proposed_item"]},
    )
