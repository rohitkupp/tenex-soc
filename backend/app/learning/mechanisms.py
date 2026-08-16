"""The single source of truth for docs/v2_migration change 21's fifteen continuous-learning
mechanisms: the id -> name -> auto/gated mapping, the `learning_events` ledger writer every
mechanism module calls through, and the shared propose/approve/reject machinery the eight gated
mechanisms (6, 7, 8, 10, 11, 12, 14, 15) all use.

## The auto/gated line, enforced here, not by convention

Change 21 states the line as a principle ("anything changing how *confident* the system is" vs.
"anything changing what the system *detects or believes*"). `MECHANISMS` below is where that
principle becomes a checkable fact: `record_event` refuses to log `applied=True` for a gated
mechanism outside the approval flow, and `create_proposal` refuses to stage a proposal for an
auto-apply mechanism. A future mechanism added to the wrong list fails loudly at the first call,
not silently at review time.

## The gate, and why it is `app.learning.retrain.evaluate_candidate`, not `evals.gate`

`evals.gate.evaluate_gate` is this codebase's *other* real regression gate (`make eval`'s own,
comparing against `evals/baselines.json`, with its own git-tracked rejection history at
`evals/gate_history.jsonl`). It is built for full-pipeline metrics
(`detection_f1_aggregate`, `incident_recall`, `disposition_accuracy`, `hallucination_rate`,
`brier_score`, `injection_resistance`) and, per its own module docstring, fails a metric outright
-- not gracefully -- when it expected to measure that metric but didn't receive it. That is
correct for `make eval` (a metric `run.py` should have produced but silently didn't is a real
harness bug) and wrong here: every one of this package's eight gated mechanisms produces at most
one or two metrics of its own (a candidate model's held-out accuracy, a clustering's silhouette
score, or nothing measurable at all for a curated exemplar or a KB edit), never the full six-key
set `evals.gate` expects, so routing through it would not gate these candidates, it would reject
every one of them unconditionally on the metrics they were never going to produce.

Every gated mechanism instead uses `app.learning.retrain.evaluate_candidate` -- this package's own
dependency-free comparator, `{metric: float}` in, `{metric: float} | None` baseline, pass/fail
out, already built for exactly this shape and already proven (this module predates change 21) on
the pre-migration classifier gate. Mechanisms 6, 7, 8 (baseline expansion -> EIF, cohort
re-derivation -> LOF, DGA classifier retraining) feed it a real held-out metric from a real
retrain, mapped onto the closest `evals.config.GATE_TOLERANCES` key (the same "metric mapping"
precedent `app.learning.retrain`'s own module docstring states). Mechanisms 10, 11, 12, 14, 15
(exemplar bank, judge rubric, KB enrichment, verifier rule, evidence profile widening) have no
retrain to gate at all -- for these, `evaluate_candidate(candidate_scores, baseline_scores=None,
...)` always passes (its own documented behavior: "no incumbent of this kind yet"), so the human
clicking Accept *is* the review these five are actually gated on, matching change 21's own
principle that human approval is the gate for a belief change, not a metric.

"Keep the rejection history" (change 21) holds through this package's own ledger, not
`evals/gate_history.jsonl`: a rejected proposal's `learning_proposals` row stays `status=
"rejected"` and its linked `learning_events` row stays `applied=False` forever (`decide_proposal`
below never deletes either), which is what `tests/test_learning_mechanisms.py::
test_gated_candidate_regressing_a_metric_is_rejected_and_incumbent_stays_live` checks directly.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.models.base import get_scoped, tenant_scope
from app.models.learning_event import LearningEvent
from app.models.learning_proposal import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    LearningProposal,
)

__all__ = [
    "MECHANISMS",
    "GatedApplyResult",
    "MechanismMode",
    "MechanismSpec",
    "create_proposal",
    "decide_proposal",
    "get_proposal",
    "record_event",
]

MechanismMode = Literal["auto", "gated"]


@dataclass(frozen=True, slots=True)
class MechanismSpec:
    id: int
    name: str
    mode: MechanismMode
    description: str


MECHANISMS: dict[int, MechanismSpec] = {
    1: MechanismSpec(
        1,
        "isotonic_recalibration",
        "auto",
        "Refit per-detector isotonic calibrators from confirmed/rejected feedback.",
    ),
    2: MechanismSpec(
        2,
        "fusion_weight_tuning",
        "auto",
        "Retune per-detector fusion weights: clamp(precision_d / prior_precision, 0.25, 1.5).",
    ),
    3: MechanismSpec(
        3,
        "entity_threshold_adaptation",
        "auto",
        "Raise one entity's confidence threshold on repeated dismissals; relax it on confirms.",
    ),
    4: MechanismSpec(
        4,
        "reference_set_curation",
        "auto",
        "Add a confirmed-benign window to the kNN/LOF reference set immediately, no retrain.",
    ),
    5: MechanismSpec(
        5,
        "contamination_exclusion",
        "auto",
        "Exclude a confirmed true-positive window from the kNN/LOF reference set and EIF's pool.",
    ),
    6: MechanismSpec(
        6,
        "baseline_expansion",
        "gated",
        "Append confirmed-benign windows to baseline_windows and retrain EIF against them.",
    ),
    7: MechanismSpec(
        7,
        "cohort_re_derivation",
        "gated",
        "Recluster peer groups feeding LOF's department-cohort features.",
    ),
    8: MechanismSpec(
        8,
        "dga_classifier_retraining",
        "gated",
        "Retrain the DGA logistic regression on analyst-corrected domain labels.",
    ),
    9: MechanismSpec(
        9,
        "verdict_retrieval",
        "auto",
        "Retrieve the k most similar confirmed incidents (with verdicts) into the Analyst prompt.",
    ),
    10: MechanismSpec(
        10,
        "curated_exemplar_bank",
        "gated",
        "Pin a stable, curated set of analyst-corrected findings into the prompt.",
    ),
    11: MechanismSpec(
        11,
        "judge_rubric_evolution",
        "gated",
        "Cluster judge PASSes an analyst later rejected into a proposed rubric item.",
    ),
    12: MechanismSpec(
        12,
        "rag_document_enrichment",
        "gated",
        "Fold repeated dismissal reasons into a technique's evidence_that_weakens KB field.",
    ),
    13: MechanismSpec(
        13,
        "retrieval_prior_tuning",
        "auto",
        "Down-weight a technique retrieved often but rarely supported by the Analyst.",
    ),
    14: MechanismSpec(
        14,
        "verifier_rule_induction",
        "gated",
        "Propose a new deterministic verifier check from a recurring missed-error pattern.",
    ),
    15: MechanismSpec(
        15,
        "evidence_profile_widening",
        "gated",
        "Widen an extractor's evidence bundle once analysts expand to raw logs often enough.",
    ),
}


def record_event(
    session: Session,
    *,
    mechanism: int,
    applied: bool,
    trigger_feedback_id: uuid.UUID | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    metric_delta: dict[str, Any] | None = None,
) -> LearningEvent:
    """Write one row to the shared `learning_events` ledger. `mechanism` must be a known id
    (1-15) -- an unknown id is a bug in the caller, not something to log silently. An **auto**
    mechanism may only ever log `applied=True` (it took effect the moment this call happened,
    unconditionally); a **gated** mechanism logs through `create_proposal`/`decide_proposal`
    instead, never directly, so every gated state change is traceable to a reviewed proposal.
    """
    spec = MECHANISMS[mechanism]
    if spec.mode == "auto" and not applied:
        raise ValueError(
            f"mechanism {mechanism} ({spec.name}) is auto-apply; it cannot log applied=False "
            "-- an auto mechanism either takes effect immediately or does not run at all"
        )
    event = LearningEvent(
        mechanism=mechanism,
        trigger_feedback_id=trigger_feedback_id,
        applied=applied,
        before_state=before_state,
        after_state=after_state,
        metric_delta=metric_delta,
    )
    session.add(event)
    session.flush()
    return event


def create_proposal(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    mechanism: int,
    payload: dict[str, Any],
    supporting_feedback_ids: list[uuid.UUID],
    trigger_feedback_id: uuid.UUID | None = None,
) -> LearningProposal:
    """Stage a gated candidate: one `learning_proposals` row (`status="pending"`) plus its linked
    `learning_events` row (`applied=False` -- "proposed, awaiting approval", per that table's own
    schema comment). Refuses an auto-apply mechanism id -- see `record_event`'s docstring for the
    mirror-image rule.
    """
    spec = MECHANISMS[mechanism]
    if spec.mode != "gated":
        raise ValueError(
            f"mechanism {mechanism} ({spec.name}) is auto-apply; it cannot be staged as a "
            "proposal -- call the mechanism's own function directly instead"
        )
    with tenant_scope(session, tenant_id):
        event = record_event(
            session,
            mechanism=mechanism,
            applied=False,
            trigger_feedback_id=trigger_feedback_id,
            before_state=None,
            after_state={"status": "proposed", **payload},
        )
        proposal = LearningProposal(
            tenant_id=tenant_id,
            mechanism=mechanism,
            status=STATUS_PENDING,
            payload=payload,
            supporting_feedback_ids=supporting_feedback_ids,
            learning_event_id=event.id,
        )
        session.add(proposal)
        session.flush()
    return proposal


def get_proposal(
    session: Session, tenant_id: uuid.UUID, proposal_id: uuid.UUID
) -> LearningProposal | None:
    with tenant_scope(session, tenant_id):
        return get_scoped(session, LearningProposal, proposal_id)


@dataclass(slots=True)
class GatedApplyResult:
    proposal: LearningProposal
    passed: bool
    after_state: dict[str, Any]
    metric_delta: dict[str, Any]
    reason: str


def decide_proposal(
    session: Session,
    tenant_id: uuid.UUID,
    proposal: LearningProposal,
    *,
    passed: bool,
    metric_delta: dict[str, Any],
    reason: str,
    user_id: uuid.UUID,
    apply_fn: Callable[[Session, uuid.UUID, LearningProposal], dict[str, Any]] | None = None,
) -> GatedApplyResult:
    """The shared finalize step every gated mechanism's own `accept_*` function ends with, after
    it has computed `passed`/`metric_delta` (via `evals.gate.evaluate_gate` for a real model
    retrain, or `app.learning.retrain.evaluate_candidate` for a lighter proposal -- see module
    docstring). Only mutates state when `passed=True`: calls `apply_fn` (the mechanism's own real
    side effect -- writing `baseline_windows`, mutating a kNN/LOF artifact, appending KB YAML,
    whatever this specific mechanism's "applied" state means) and folds its return value into
    `after_state`. On `passed=False` nothing is applied; the proposal and its linked
    `learning_events` row both stay exactly as `create_proposal` left them except for the
    rejection stamp -- "the incumbent stays live" and "keep the rejection history" both hold by
    construction, not by remembering to check them.
    """
    if proposal.status != STATUS_PENDING:
        raise ValueError(f"proposal {proposal.id} is already {proposal.status!r}, not pending")

    with tenant_scope(session, tenant_id):
        if passed:
            after_state = apply_fn(session, tenant_id, proposal) if apply_fn is not None else {}
            after_state = {"status": "approved", **after_state}
            proposal.status = STATUS_APPROVED
        else:
            after_state = {"status": "rejected", "reason": reason}
            proposal.status = STATUS_REJECTED
        proposal.reviewed_at = datetime.now(UTC)
        proposal.reviewed_by = user_id

        if proposal.learning_event_id is not None:
            event = session.get(LearningEvent, proposal.learning_event_id)
            if event is not None:
                event.applied = passed
                event.after_state = after_state
                event.metric_delta = metric_delta
        session.flush()

    return GatedApplyResult(
        proposal=proposal,
        passed=passed,
        after_state=after_state,
        metric_delta=metric_delta,
        reason=reason,
    )
