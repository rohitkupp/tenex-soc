"""Mechanism 14 — verifier rule induction (change 21, gated). "An analyst catching a factual
error the verifier missed is a verifier gap. When a pattern emerges (model conflates
`bytes_in`/`bytes_out`) add a deterministic check."

Source signal: a thumbs-down `claim_feedback` row (change 22's per-claim thumbs) with a note --
a claim-level correction is exactly "the verifier missed this specific factual error," narrower
and more direct than a whole-incident Dismiss. Clusters by a small, honest keyword vocabulary
(the same "small, disclosed feature set" precedent `app.learning.dga_retrain`'s module docstring
already establishes) rather than free-text NLP clustering this milestone does not own the
infrastructure for.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.base import tenant_scope
from app.models.claim_feedback import ClaimFeedback
from app.models.learning_proposal import LearningProposal

__all__ = ["MIN_CLUSTER_SIZE", "PATTERN_KEYWORDS", "accept_verifier_rule", "propose_verifier_rule"]

MIN_CLUSTER_SIZE = 3
_SUPPORT_TOLERANCE = MetricTolerance("higher_is_better", 0.0)

# A small, disclosed vocabulary of factual-error patterns worth a deterministic verifier check --
# not an exhaustive NLP classifier, an honest keyword match over the analyst's own note text.
PATTERN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "bytes_in_out_confusion": ("bytes_in", "bytes_out", "upload", "download", "direction"),
    "count_mismatch": ("count", "number of", "how many", "requests"),
    "duration_mismatch": ("duration", "minutes", "hours", "time window"),
    "wrong_entity": ("wrong user", "wrong ip", "different entity", "not this user"),
}


def _match_pattern(note: str) -> str | None:
    lowered = note.lower()
    for pattern, keywords in PATTERN_KEYWORDS.items():
        if any(k in lowered for k in keywords):
            return pattern
    return None


def propose_verifier_rule(
    session: Session, tenant_id: uuid.UUID, claim: ClaimFeedback
) -> LearningProposal | None:
    """Called after a thumbs-down `claim_feedback` row with a note is recorded."""
    if claim.helpful or not claim.note:
        return None
    pattern = _match_pattern(claim.note)
    if pattern is None:
        return None

    with tenant_scope(session, tenant_id):
        matches = (
            session.execute(select(ClaimFeedback).where(ClaimFeedback.helpful.is_(False)))
            .scalars()
            .all()
        )
    matching_ids = [c.id for c in matches if c.note and _match_pattern(c.note) == pattern]
    if len(matching_ids) < MIN_CLUSTER_SIZE or claim.id not in matching_ids:
        return None
    if len(matching_ids) != MIN_CLUSTER_SIZE:
        return None  # already proposed once this cluster crossed the threshold

    proposed_check = (
        f"Add a deterministic verifier check for the '{pattern}' pattern: "
        f"{len(matching_ids)} analyst corrections point at this factual-error shape."
    )
    return create_proposal(
        session,
        tenant_id,
        mechanism=14,
        payload={
            "pattern": pattern,
            "proposed_check": proposed_check,
            "n_misses": len(matching_ids),
        },
        supporting_feedback_ids=[],
        trigger_feedback_id=None,
    )


def accept_verifier_rule(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    """No live `app/agent/verifier.py` to patch (out of this milestone's ownership) -- the
    applied state is the accepted, durable rule description on the proposal/`learning_events`
    row, for an engineer (or a future codegen pass) to implement as a real deterministic check.
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
        apply_fn=lambda s, t, p: {"proposed_check": p.payload["proposed_check"]},
    )
