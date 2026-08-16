"""`POST /api/incidents/{id}/feedback`, `GET /api/learning/metrics`,
`GET /api/learning/suppressions`, `POST /api/learning/suppressions/{id}/accept` — docs/09's
"Models & learning" section, the M13 half (`app/api/models.py` covers the other two routes in
that table). Every route requires an authenticated, tenant-scoped caller (docs/06); POSTs are
covered by the existing `app.core.csrf.CSRFMiddleware`, which is wired globally in `app.main` —
nothing route-specific is needed here for that.

`POST /api/incidents/{id}/feedback` lives in this router rather than a would-be
`app/api/incidents.py` (which does not exist in this checkout — incident listing/detail routes
are M10/M11's ownership, not built yet) because feedback capture is the single entry point into
every consumer this milestone owns; keeping it here means the whole learning loop's HTTP surface
is in one file. Its URL path is `/api/incidents/{incident_id}/feedback`, matching docs/09 exactly,
even though the router module is named for what it *does* (learning), not the URL's first
segment.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.detection.sigma.rule import RuleLoadError, load_rule_file
from app.detection.sigma.runner import SUPPRESSIONS_DIR
from app.learning.baseline_expansion import accept_baseline_expansion
from app.learning.cohorts import accept_cohort_re_derivation
from app.learning.dga_retrain import accept_dga_retrain
from app.learning.evidence_profiles import accept_evidence_profile_widening
from app.learning.exemplars import accept_exemplar
from app.learning.feedback import (
    DomainLabelCorrection,
    FeedbackInput,
    IncidentNotFoundError,
    IncidentNotTriagedError,
    InvalidCorrectedTechniqueError,
    record_claim_feedback,
    record_evidence_relevance_toggle,
    record_feedback,
)
from app.learning.kb_enrichment import accept_kb_enrichment
from app.learning.mechanisms import MECHANISMS, GatedApplyResult
from app.learning.metrics import compute_learning_metrics
from app.learning.retrain import RetrainAttempt
from app.learning.rubric import accept_rubric_item
from app.learning.verifier_rules import accept_verifier_rule
from app.models.base import get_scoped, tenant_scope
from app.models.learning_event import LearningEvent
from app.models.learning_proposal import STATUS_PENDING as PROPOSAL_STATUS_PENDING
from app.models.learning_proposal import LearningProposal
from app.models.suppression_candidate import STATUS_ACCEPTED, STATUS_PENDING, SuppressionCandidate
from app.schemas.learning import (
    AlignmentPointOut,
    ClaimFeedbackRequest,
    ClaimFeedbackResponse,
    DetectorPrecisionPointOut,
    DetectorWeightChangeOut,
    EvidenceRelevanceRequest,
    EvidenceRelevanceResponse,
    FeedbackRequest,
    FeedbackResponse,
    LearningEventOut,
    LearningEventsResponse,
    LearningMetricsResponse,
    LearningProposalDecisionResponse,
    LearningProposalOut,
    LearningProposalsResponse,
    RetrainAttemptOut,
    RetrainGateComparisonOut,
    SuppressionAcceptResponse,
    SuppressionCandidateOut,
    SuppressionListResponse,
)

router = APIRouter()
log = get_logger(__name__)

# `written_path` is stored relative to `backend/`, so it reads as
# `app/detection/rules/suppressions/{id}.yml` — the path a reviewer can paste into an editor.
# SUPPRESSIONS_DIR is `.../backend/app/detection/rules/suppressions`, so counting up:
# parents[0]=rules, [1]=detection, [2]=app, [3]=backend. It must be [3]; [2] silently produced
# paths missing their leading `app/` segment.
_BACKEND_ROOT = SUPPRESSIONS_DIR.parents[3]


def _retrain_attempt_out(attempt: RetrainAttempt | None) -> RetrainAttemptOut | None:
    if attempt is None:
        return None
    gate = attempt.gate
    return RetrainAttemptOut(
        attempted_at=attempt.attempted_at,
        skipped=attempt.skipped,
        skip_reason=attempt.skip_reason,
        n_training_rows=attempt.n_training_rows,
        version=attempt.version,
        promoted=attempt.promoted,
        baseline_version=attempt.baseline_version,
        gate_passed=gate.passed if gate is not None else None,
        gate_reason=gate.reason if gate is not None else None,
        gate_comparisons=[
            RetrainGateComparisonOut(
                metric=c.metric,
                baseline=c.baseline,
                candidate=c.candidate,
                delta=c.delta,
                regressed=c.regressed,
            )
            for c in (gate.comparisons if gate is not None else [])
        ],
    )


@router.post("/incidents/{incident_id}/feedback", response_model=FeedbackResponse)
def submit_feedback(
    incident_id: uuid.UUID,
    body: FeedbackRequest,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> FeedbackResponse:
    try:
        outcome = record_feedback(
            db,
            current.tenant.id,
            user_id=current.user.id,
            incident_id=incident_id,
            data=FeedbackInput(
                agrees=body.agrees,
                corrected_disposition=body.corrected_disposition,
                corrected_technique=body.corrected_technique,
                dismissal_reason=body.dismissal_reason,
                mark_benign_baseline=body.mark_benign_baseline,
                note=body.note,
                corrected_domain_labels=tuple(
                    DomainLabelCorrection(domain=d.domain, is_dga=d.is_dga)
                    for d in body.corrected_domain_labels
                ),
            ),
        )
    except IncidentNotFoundError as exc:
        raise ApiError(status_code=404, code="not_found", detail="Incident not found.") from exc
    except IncidentNotTriagedError as exc:
        raise ApiError(
            status_code=409,
            code="incident_not_triaged",
            detail="This incident has no triage verdict yet; feedback needs a verdict to attach to.",
        ) from exc
    except InvalidCorrectedTechniqueError as exc:
        raise ApiError(
            status_code=422, code="invalid_corrected_technique", detail=str(exc)
        ) from exc

    log.info(
        "learning.feedback_recorded",
        incident_id=str(incident_id),
        feedback_id=str(outcome.feedback_id),
        agrees=body.agrees,
        calibration_refit_triggered=outcome.calibration_refit is not None,
        retrain_triggered=outcome.retrain_attempt is not None,
    )

    return FeedbackResponse(
        feedback_id=outcome.feedback_id,
        detector_weight_changes=[
            DetectorWeightChangeOut(
                detector_key=c.detector_key,
                true_positives=c.true_positives,
                false_positives=c.false_positives,
                precision=c.precision,
                weight_before=c.weight_before,
                weight_after=c.weight_after,
                changed=c.changed,
            )
            for c in outcome.weight_tuning.detectors
        ],
        calibration_refit_triggered=outcome.calibration_refit is not None,
        suppression_candidates_generated=[c.id for c in outcome.suppression_candidates],
        benign_baseline_entries_created=len(outcome.benign_baseline_entries),
        retrain_attempt=_retrain_attempt_out(outcome.retrain_attempt),
        reference_set_mechanism=outcome.reference_set_mechanism,
        baseline_expansion_proposed=outcome.baseline_expansion_proposal is not None,
        exemplar_proposed=outcome.exemplar_proposal is not None,
    )


@router.get("/learning/metrics", response_model=LearningMetricsResponse)
def get_learning_metrics(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> LearningMetricsResponse:
    metrics = compute_learning_metrics(db, current.tenant.id)
    return LearningMetricsResponse(
        computed_at=metrics.computed_at,
        n_feedback_events=metrics.n_feedback_events,
        n_synthetic_feedback_events=metrics.n_synthetic_feedback_events,
        synthetic=metrics.n_synthetic_feedback_events > 0,
        alignment_pct=metrics.alignment_pct,
        alignment_trend=[
            AlignmentPointOut(
                period_start=p.period_start,
                period_end=p.period_end,
                alignment_pct=p.alignment_pct,
                n=p.n,
                synthetic=p.synthetic,
            )
            for p in metrics.alignment_trend
        ],
        detector_precision_trend=[
            DetectorPrecisionPointOut(
                detector_key=p.detector_key,
                period_start=p.period_start,
                period_end=p.period_end,
                precision=p.precision,
                n=p.n,
                synthetic=p.synthetic,
            )
            for p in metrics.detector_precision_trend
        ],
    )


@router.get("/learning/suppressions", response_model=SuppressionListResponse)
def list_suppression_candidates(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    status_filter: str | None = None,
) -> SuppressionListResponse:
    """`status_filter` defaults to `pending` (docs/09: "pending candidates") — pass e.g.
    `?status_filter=accepted` to see the review history instead."""
    effective_status = status_filter or STATUS_PENDING
    with tenant_scope(db, current.tenant.id):
        rows = (
            db.execute(
                select(SuppressionCandidate)
                .where(SuppressionCandidate.status == effective_status)
                .order_by(SuppressionCandidate.created_at.desc())
            )
            .scalars()
            .all()
        )
    return SuppressionListResponse(items=[SuppressionCandidateOut.model_validate(r) for r in rows])


def _not_found_suppression() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Suppression candidate not found.")


@router.post(
    "/learning/suppressions/{candidate_id}/accept", response_model=SuppressionAcceptResponse
)
def accept_suppression_candidate(
    candidate_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> SuppressionAcceptResponse:
    """The **only** code path in this milestone that writes a `.yml` file under
    `app/detection/rules/suppressions/` — see `app.learning.suppression`'s module docstring for
    why that is a hard rule, not a convenience. Requires a human to hit this endpoint; there is
    no automated caller anywhere in this codebase.
    """
    with tenant_scope(db, current.tenant.id):
        candidate = get_scoped(db, SuppressionCandidate, candidate_id)
        if candidate is None:
            raise _not_found_suppression()
        if candidate.status == STATUS_ACCEPTED and candidate.written_path is not None:
            # Idempotent: re-accepting an already-accepted candidate just confirms the existing
            # file, rather than erroring or writing a second one.
            return SuppressionAcceptResponse(
                id=candidate.id, status=candidate.status, written_path=candidate.written_path
            )

        parsed = yaml.safe_load(candidate.rule_yaml)
        rule_id = parsed["id"]
        target_path = SUPPRESSIONS_DIR / f"{rule_id}.yml"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(candidate.rule_yaml, encoding="utf-8")

        try:
            load_rule_file(target_path)
        except RuleLoadError as exc:
            target_path.unlink(missing_ok=True)
            raise ApiError(
                status_code=500,
                code="invalid_generated_rule",
                detail=f"generated suppression failed validation and was not written: {exc}",
            ) from exc

        candidate.status = STATUS_ACCEPTED
        candidate.reviewed_at = datetime.now(UTC)
        candidate.reviewed_by = current.user.id
        candidate.written_path = str(target_path.relative_to(_BACKEND_ROOT))

    log.info(
        "learning.suppression_accepted",
        candidate_id=str(candidate_id),
        written_path=candidate.written_path,
        reviewed_by=str(current.user.id),
    )
    return SuppressionAcceptResponse(
        id=candidate.id, status=candidate.status, written_path=candidate.written_path
    )


# ------------------------------------------------------------------------------------------
# docs/v2_migration change 22 — per-claim thumbs, evidence relevance toggle
# ------------------------------------------------------------------------------------------


@router.post(
    "/incidents/{incident_id}/claims/{step}/feedback", response_model=ClaimFeedbackResponse
)
def submit_claim_feedback(
    incident_id: uuid.UUID,
    step: int,
    body: ClaimFeedbackRequest,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> ClaimFeedbackResponse:
    """Change 22: "Per-claim thumbs on narrative claims, hover-revealed." Independent of the
    primary Confirm/Override/Dismiss bar — feeds mechanism 14 (verifier rule induction)."""
    try:
        claim = record_claim_feedback(
            db,
            current.tenant.id,
            user_id=current.user.id,
            incident_id=incident_id,
            step=step,
            helpful=body.helpful,
            note=body.note,
        )
    except IncidentNotFoundError as exc:
        raise ApiError(status_code=404, code="not_found", detail="Incident not found.") from exc
    except IncidentNotTriagedError as exc:
        raise ApiError(
            status_code=409,
            code="incident_not_triaged",
            detail="This incident has no triage verdict yet.",
        ) from exc

    with tenant_scope(db, current.tenant.id):
        proposed = (
            db.execute(
                select(LearningProposal).where(
                    LearningProposal.mechanism == 14,
                    LearningProposal.created_at >= claim.created_at,
                )
            )
            .scalars()
            .first()
            is not None
        )
    return ClaimFeedbackResponse(
        id=claim.id,
        incident_id=claim.incident_id,
        step=claim.step,
        helpful=claim.helpful,
        verifier_rule_proposed=proposed,
    )


@router.post(
    "/incidents/{incident_id}/evidence/{evidence_id}/relevance",
    response_model=EvidenceRelevanceResponse,
)
def submit_evidence_relevance(
    incident_id: uuid.UUID,
    evidence_id: str,
    body: EvidenceRelevanceRequest,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> EvidenceRelevanceResponse:
    """Change 16/22's "per-evidence relevance toggle" — the seam the evidence section (rendered
    by a different milestone's frontend work, `app/api/incident_detail.py`'s
    `GET /incidents/{id}/evidence`) writes through. Feeds mechanism 15 (evidence profile
    widening); see `app.models.evidence_relevance_feedback`'s docstring for a documented reading
    of a cross-reference discrepancy in the migration doc itself.
    """
    row = record_evidence_relevance_toggle(
        db,
        current.tenant.id,
        user_id=current.user.id,
        incident_id=incident_id,
        evidence_id=evidence_id,
        extractor=body.extractor,
        relevant=body.relevant,
    )
    with tenant_scope(db, current.tenant.id):
        widening_proposed = (
            db.execute(
                select(LearningProposal).where(
                    LearningProposal.mechanism == 15,
                    LearningProposal.status == PROPOSAL_STATUS_PENDING,
                    LearningProposal.payload["extractor"].astext == body.extractor,
                )
            )
            .scalars()
            .first()
            is not None
        )
    return EvidenceRelevanceResponse(
        id=row.id,
        incident_id=row.incident_id,
        evidence_id=row.evidence_id,
        relevant=row.relevant,
        widening_proposed=widening_proposed,
    )


# ------------------------------------------------------------------------------------------
# docs/v2_migration change 21 — the learning_events ledger + gated-proposal review
# ------------------------------------------------------------------------------------------


def _learning_event_out(event: LearningEvent) -> LearningEventOut:
    spec = MECHANISMS.get(event.mechanism)
    return LearningEventOut(
        id=event.id,
        mechanism=event.mechanism,
        mechanism_name=spec.name if spec is not None else "unknown",
        trigger_feedback_id=event.trigger_feedback_id,
        applied=event.applied,
        before_state=event.before_state,
        after_state=event.after_state,
        metric_delta=event.metric_delta,
        created_at=event.created_at,
    )


@router.get("/learning/events", response_model=LearningEventsResponse)
def list_learning_events(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    mechanism: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> LearningEventsResponse:
    """docs/10 `/learning` section 5, "learning events" — the change-21 feed. Not tenant-scoped
    on the query (`learning_events` carries no `tenant_id`, per its own schema — change 23's
    shared single-tenant workspace), ordered newest first."""
    stmt = select(LearningEvent).order_by(LearningEvent.created_at.desc()).limit(limit)
    if mechanism is not None:
        stmt = stmt.where(LearningEvent.mechanism == mechanism)
    rows = db.execute(stmt).scalars().all()
    return LearningEventsResponse(items=[_learning_event_out(e) for e in rows])


def _proposal_out(proposal: LearningProposal) -> LearningProposalOut:
    spec = MECHANISMS.get(proposal.mechanism)
    return LearningProposalOut(
        id=proposal.id,
        mechanism=proposal.mechanism,
        mechanism_name=spec.name if spec is not None else "unknown",
        status=proposal.status,
        payload=proposal.payload,
        supporting_feedback_ids=list(proposal.supporting_feedback_ids),
        created_at=proposal.created_at,
        reviewed_at=proposal.reviewed_at,
    )


@router.get("/learning/proposals", response_model=LearningProposalsResponse)
def list_learning_proposals(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    status_filter: str | None = None,
    mechanism: int | None = None,
) -> LearningProposalsResponse:
    """docs/10 `/learning` section 6, "what your feedback changed" — `status_filter` defaults to
    `pending` (the review queue); pass `?status_filter=approved` or `?status_filter=rejected` for
    the change-21 "keep the rejection history" record."""
    effective_status = status_filter or PROPOSAL_STATUS_PENDING
    with tenant_scope(db, current.tenant.id):
        stmt = select(LearningProposal).where(LearningProposal.status == effective_status)
        if mechanism is not None:
            stmt = stmt.where(LearningProposal.mechanism == mechanism)
        rows = db.execute(stmt.order_by(LearningProposal.created_at.desc())).scalars().all()
    return LearningProposalsResponse(items=[_proposal_out(r) for r in rows])


# One dispatcher per gated mechanism (6, 7, 8, 10, 11, 12, 14, 15) — every `accept_*` function
# shares the same `(session, tenant_id, proposal, *, user_id) -> GatedApplyResult` shape
# (`app.learning.mechanisms.decide_proposal`'s own contract), so a single dict routes a proposal
# to the right one by `mechanism` without an `if/elif` chain that silently falls through for a
# mechanism nobody remembered to wire up.
_GATED_ACCEPT_HANDLERS: dict[
    int, Callable[[Session, uuid.UUID, LearningProposal, uuid.UUID], GatedApplyResult]
] = {
    6: lambda db, tid, p, uid: accept_baseline_expansion(db, tid, p, user_id=uid),
    7: lambda db, tid, p, uid: accept_cohort_re_derivation(db, tid, p, user_id=uid),
    8: lambda db, tid, p, uid: accept_dga_retrain(db, tid, p, user_id=uid),
    10: lambda db, tid, p, uid: accept_exemplar(db, tid, p, user_id=uid),
    11: lambda db, tid, p, uid: accept_rubric_item(db, tid, p, user_id=uid),
    12: lambda db, tid, p, uid: accept_kb_enrichment(db, tid, p, user_id=uid),
    14: lambda db, tid, p, uid: accept_verifier_rule(db, tid, p, user_id=uid),
    15: lambda db, tid, p, uid: accept_evidence_profile_widening(db, tid, p, user_id=uid),
}


def _not_found_proposal() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Learning proposal not found.")


@router.post(
    "/learning/proposals/{proposal_id}/accept", response_model=LearningProposalDecisionResponse
)
def accept_learning_proposal(
    proposal_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> LearningProposalDecisionResponse:
    """The human-approval gate for all eight gated mechanisms (change 21: "requires human
    approval ... auto-suppression is how you miss a breach"). Runs the mechanism's own
    golden-set (or support) gate; a regressing candidate is rejected and the incumbent stays
    live, with the rejection retained on this same row — see `app.learning.mechanisms.
    decide_proposal`'s module docstring.
    """
    with tenant_scope(db, current.tenant.id):
        proposal = get_scoped(db, LearningProposal, proposal_id)
    if proposal is None:
        raise _not_found_proposal()
    if proposal.status != PROPOSAL_STATUS_PENDING:
        raise ApiError(
            status_code=409,
            code="not_pending",
            detail=f"Proposal is already {proposal.status!r}.",
        )

    handler = _GATED_ACCEPT_HANDLERS.get(proposal.mechanism)
    if handler is None:
        raise ApiError(
            status_code=500,
            code="no_handler",
            detail=f"No accept handler wired for mechanism {proposal.mechanism}.",
        )
    result = handler(db, current.tenant.id, proposal, current.user.id)

    log.info(
        "learning.proposal_decided",
        proposal_id=str(proposal_id),
        mechanism=proposal.mechanism,
        passed=result.passed,
        reviewed_by=str(current.user.id),
    )
    return LearningProposalDecisionResponse(
        id=proposal.id,
        status=proposal.status,
        passed=result.passed,
        after_state=result.after_state,
        metric_delta=result.metric_delta,
        reason=result.reason,
    )


@router.post(
    "/learning/proposals/{proposal_id}/reject", response_model=LearningProposalDecisionResponse
)
def reject_learning_proposal(
    proposal_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> LearningProposalDecisionResponse:
    """A human declining a proposal outright, without running the gate — the analyst's own
    judgment is itself a sufficient reason not to apply a candidate. Distinct from a *gate*
    rejection (`accept_learning_proposal` when the candidate regresses a metric): both land the
    proposal in `STATUS_REJECTED` and keep the row (change 21: "keep the rejection history"),
    but this path never mutates anything the candidate would have changed.
    """
    from app.learning.mechanisms import decide_proposal

    with tenant_scope(db, current.tenant.id):
        proposal = get_scoped(db, LearningProposal, proposal_id)
    if proposal is None:
        raise _not_found_proposal()
    if proposal.status != PROPOSAL_STATUS_PENDING:
        raise ApiError(
            status_code=409,
            code="not_pending",
            detail=f"Proposal is already {proposal.status!r}.",
        )

    result = decide_proposal(
        db,
        current.tenant.id,
        proposal,
        passed=False,
        metric_delta={},
        reason="rejected by analyst review",
        user_id=current.user.id,
    )
    log.info(
        "learning.proposal_rejected_by_analyst",
        proposal_id=str(proposal_id),
        mechanism=proposal.mechanism,
        reviewed_by=str(current.user.id),
    )
    return LearningProposalDecisionResponse(
        id=proposal.id,
        status=proposal.status,
        passed=result.passed,
        after_state=result.after_state,
        metric_delta=result.metric_delta,
        reason=result.reason,
    )
