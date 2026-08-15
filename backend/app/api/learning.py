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
from datetime import UTC, datetime
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.detection.sigma.rule import RuleLoadError, load_rule_file
from app.detection.sigma.runner import SUPPRESSIONS_DIR
from app.learning.feedback import (
    FeedbackInput,
    IncidentNotFoundError,
    IncidentNotTriagedError,
    record_feedback,
)
from app.learning.metrics import compute_learning_metrics
from app.learning.retrain import RetrainAttempt
from app.models.base import get_scoped, tenant_scope
from app.models.suppression_candidate import STATUS_ACCEPTED, STATUS_PENDING, SuppressionCandidate
from app.schemas.learning import (
    AlignmentPointOut,
    ContainmentSummaryOut,
    DetectorPrecisionPointOut,
    DetectorWeightChangeOut,
    FeedbackRequest,
    FeedbackResponse,
    LearningMetricsResponse,
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
        containment=ContainmentSummaryOut(
            contained=metrics.containment.contained,
            partially_contained=metrics.containment.partially_contained,
            failed=metrics.containment.failed,
            total_with_outcome=metrics.containment.total_with_outcome,
            rate=metrics.containment.rate,
        ),
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
