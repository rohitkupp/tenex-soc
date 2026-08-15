"""`GET /api/models/calibration`, `GET /api/models/versions` — docs/09's "Models & learning"
section, the two routes this milestone owns (`GET /api/models`, the benchmark comparison tables,
is M16's — `evals/`, not built in this checkout; left for that milestone to add to this same
file rather than duplicating the router).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import CurrentUser, require_user
from app.learning.calibration import refit_calibrators
from app.learning.metrics import synthetic_feedback_ids
from app.models.model_version import ModelVersion
from app.schemas.learning import (
    CalibrationResponse,
    DetectorCalibrationOut,
    ModelVersionOut,
    ModelVersionsResponse,
    ReliabilityBinOut,
)

router = APIRouter()


@router.get("/models/calibration", response_model=CalibrationResponse)
def get_calibration(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> CalibrationResponse:
    """Refits live (docs/04's isotonic calibrator per detector, `app.learning.calibration`) and
    returns the reliability diagram plus Brier score for every detector with enough labeled
    feedback to fit — always current as of the latest `analyst_feedback` row, never a stale
    cached figure. `persist=True` (the default) also writes the calibrator artifacts this fetch
    just computed, so a page load doubles as a refit rather than only a read."""
    result = refit_calibrators(db, current.tenant.id)
    n_synthetic = len(synthetic_feedback_ids(db, current.tenant.id))

    return CalibrationResponse(
        refit_at=result.refit_at,
        n_feedback_events=result.n_feedback_events,
        n_synthetic_feedback_events=n_synthetic,
        synthetic=n_synthetic > 0,
        overall_brier_before=result.overall_brier_before,
        overall_brier_after=result.overall_brier_after,
        detectors=[
            DetectorCalibrationOut(
                detector_key=d.detector_key,
                n_samples=d.n_samples,
                n_positive=d.n_positive,
                fitted=d.fitted,
                skip_reason=d.skip_reason,
                brier_before=d.brier_before,
                brier_after=d.brier_after,
                brier_improvement=d.brier_improvement,
                reliability_before=[
                    ReliabilityBinOut(
                        bin_lo=b.bin_lo,
                        bin_hi=b.bin_hi,
                        predicted_mean=b.predicted_mean,
                        observed_precision=b.observed_precision,
                        n=b.n,
                    )
                    for b in d.reliability_before
                ],
                reliability_after=[
                    ReliabilityBinOut(
                        bin_lo=b.bin_lo,
                        bin_hi=b.bin_hi,
                        predicted_mean=b.predicted_mean,
                        observed_precision=b.observed_precision,
                        n=b.n,
                    )
                    for b in d.reliability_after
                ],
            )
            for d in result.detectors
        ],
    )


@router.get("/models/versions", response_model=ModelVersionsResponse)
def list_model_versions(
    db: Annotated[Session, Depends(get_db)],
    _current: Annotated[CurrentUser, Depends(require_user)],
) -> ModelVersionsResponse:
    """`model_versions` is not tenant-scoped (docs/02 — models are versioned globally, see
    `app.models.model_version`'s docstring); `require_user` still gates the route (every non-auth
    route does, docs/09), it just does not filter the query. Every attempt is included, promoted
    or not — docs/08's "Retrain gate": "Record every attempt, promoted or not — the rejection
    history is the evidence the gate works," which this endpoint is the one place that evidence
    surfaces.
    """
    rows = (
        db.execute(
            select(ModelVersion).order_by(ModelVersion.model_key.asc(), ModelVersion.version.desc())
        )
        .scalars()
        .all()
    )
    return ModelVersionsResponse(items=[ModelVersionOut.model_validate(r) for r in rows])
