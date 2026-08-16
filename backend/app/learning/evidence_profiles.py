"""Mechanism 15 — evidence profile widening (change 21). Counting is auto and unconditional
(a tally is not a belief change); the widening decision itself is gated (change 21: "changes what
the system detects or believes").

Source signal: the evidence relevance toggle (change 16/22, `app.models.
evidence_relevance_feedback`) -- see that model's own docstring for a documented reading of a
cross-reference discrepancy between change 16 (which names "mechanism 13") and change 21's own
mechanism table (13 is retrieval prior tuning over MITRE techniques, not evidence extractors).
Marking an evidence card **not relevant** is read here as "this extractor's bundle was not the
useful part of the picture for this window" -- change 21's own words, "the context window is too
narrow," for the one signal this milestone's data model actually carries per evidence card.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.base import tenant_scope
from app.models.evidence_profile_state import EvidenceProfileState
from app.models.learning_proposal import LearningProposal

__all__ = [
    "MIN_SAMPLES_TO_PROPOSE",
    "WIDEN_RATE_THRESHOLD",
    "accept_evidence_profile_widening",
    "record_evidence_relevance",
]

WIDEN_RATE_THRESHOLD = 0.4
MIN_SAMPLES_TO_PROPOSE = 5
_SUPPORT_TOLERANCE = MetricTolerance("higher_is_better", 0.0)


def record_evidence_relevance(
    session: Session, tenant_id: uuid.UUID, *, extractor: str, relevant: bool
) -> LearningProposal | None:
    """Auto counter bump, every call, no approval. Returns a new mechanism-15 proposal exactly
    once the not-relevant rate for this extractor crosses `WIDEN_RATE_THRESHOLD` (and stays
    `None` on every call before or after that single crossing, so widening is proposed once per
    threshold crossing, not on every subsequent low-relevance vote)."""
    with tenant_scope(session, tenant_id):
        row = session.execute(
            select(EvidenceProfileState).where(EvidenceProfileState.extractor == extractor)
        ).scalar_one_or_none()
        total_before = row.total_count if row else 0
        expand_before = row.expand_count if row else 0
        total_after = total_before + 1
        expand_after = expand_before + (0 if relevant else 1)
        already_widened = row.widened if row else False

        if row is None:
            row = EvidenceProfileState(
                tenant_id=tenant_id,
                extractor=extractor,
                total_count=total_after,
                expand_count=expand_after,
            )
            session.add(row)
        else:
            row.total_count = total_after
            row.expand_count = expand_after
            row.updated_at = datetime.now(UTC)
        session.flush()

    rate = expand_after / total_after
    # Proposes exactly once: at the call where `total_after` first reaches
    # `MIN_SAMPLES_TO_PROPOSE`, if the rate is already over threshold at that point. Keyed off
    # sample count rather than "the rate just crossed the line" (which a rate that is high from
    # the very first sample would never satisfy, since it starts and stays above the threshold)
    # -- the sample-count gate is itself what prevents re-proposing on every later call.
    just_reached_min_samples = total_before < MIN_SAMPLES_TO_PROPOSE <= total_after
    if already_widened or not just_reached_min_samples or rate < WIDEN_RATE_THRESHOLD:
        return None

    return create_proposal(
        session,
        tenant_id,
        mechanism=15,
        payload={"extractor": extractor, "rate": rate, "total_count": total_after},
        supporting_feedback_ids=[],
        trigger_feedback_id=None,
    )


def _apply(session: Session, tenant_id: uuid.UUID, proposal: LearningProposal) -> dict[str, Any]:
    with tenant_scope(session, tenant_id):
        row = session.execute(
            select(EvidenceProfileState).where(
                EvidenceProfileState.extractor == proposal.payload["extractor"]
            )
        ).scalar_one()
        row.widened = True
        row.updated_at = datetime.now(UTC)
        session.flush()
    return {"extractor": row.extractor, "widened": True}


def accept_evidence_profile_widening(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    gate = evaluate_candidate({"support": 1.0}, None, tolerances={"support": _SUPPORT_TOLERANCE})
    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=gate.passed,
        metric_delta={"rate": proposal.payload["rate"]},
        reason=gate.reason,
        user_id=user_id,
        apply_fn=_apply,
    )
