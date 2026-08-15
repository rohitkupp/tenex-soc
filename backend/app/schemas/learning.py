"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's "Models & learning" section, as implemented
by `app/api/learning.py` and `app/api/models.py` (M13). Response shapes are this milestone's own
design where docs/09 gives only a one-line description ("alignment %, per-detector precision
trend, containment rate") and no field-level contract.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------- feedback


class FeedbackRequest(BaseModel):
    """`POST /api/incidents/{id}/feedback` body, docs/09 verbatim: `{agrees,
    corrected_disposition?, corrected_technique?, dismissal_reason?, mark_benign_baseline?,
    note?}`."""

    agrees: bool
    corrected_disposition: str | None = None
    corrected_technique: str | None = None
    dismissal_reason: str | None = None
    mark_benign_baseline: bool = False
    note: str | None = None


class DetectorWeightChangeOut(BaseModel):
    detector_key: str
    true_positives: int
    false_positives: int
    precision: float | None
    weight_before: float
    weight_after: float
    changed: bool


class RetrainGateComparisonOut(BaseModel):
    metric: str
    baseline: float
    candidate: float
    delta: float
    regressed: bool


class RetrainAttemptOut(BaseModel):
    attempted_at: datetime
    skipped: bool
    skip_reason: str | None
    n_training_rows: int
    version: int | None
    promoted: bool
    baseline_version: int | None
    gate_passed: bool | None
    gate_reason: str | None
    gate_comparisons: list[RetrainGateComparisonOut]


class FeedbackResponse(BaseModel):
    feedback_id: uuid.UUID
    detector_weight_changes: list[DetectorWeightChangeOut]
    calibration_refit_triggered: bool
    suppression_candidates_generated: list[uuid.UUID]
    benign_baseline_entries_created: int
    retrain_attempt: RetrainAttemptOut | None


# ---------------------------------------------------------------------------- learning metrics


class AlignmentPointOut(BaseModel):
    period_start: datetime
    period_end: datetime
    alignment_pct: float
    n: int
    synthetic: bool


class DetectorPrecisionPointOut(BaseModel):
    detector_key: str
    period_start: datetime
    period_end: datetime
    precision: float | None
    n: int
    synthetic: bool


class ContainmentSummaryOut(BaseModel):
    contained: int
    partially_contained: int
    failed: int
    total_with_outcome: int
    rate: float | None


class LearningMetricsResponse(BaseModel):
    computed_at: datetime
    n_feedback_events: int
    n_synthetic_feedback_events: int
    synthetic: bool  # true if ANY of the above feedback events are seeded, not real
    alignment_pct: float | None
    alignment_trend: list[AlignmentPointOut]
    detector_precision_trend: list[DetectorPrecisionPointOut]
    containment: ContainmentSummaryOut


# ---------------------------------------------------------------------------- suppressions


class SuppressionCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    detector_key: str
    entity_type: str
    entity_value: str
    reason: str
    rule_yaml: str
    status: str
    synthetic: bool
    created_at: datetime
    reviewed_at: datetime | None
    written_path: str | None


class SuppressionListResponse(BaseModel):
    items: list[SuppressionCandidateOut]


class SuppressionAcceptResponse(BaseModel):
    id: uuid.UUID
    status: str
    written_path: str


# ---------------------------------------------------------------------------- calibration


class ReliabilityBinOut(BaseModel):
    bin_lo: float
    bin_hi: float
    predicted_mean: float | None
    observed_precision: float | None
    n: int


class DetectorCalibrationOut(BaseModel):
    detector_key: str
    n_samples: int
    n_positive: int
    fitted: bool
    skip_reason: str | None
    brier_before: float | None
    brier_after: float | None
    brier_improvement: float | None
    reliability_before: list[ReliabilityBinOut]
    reliability_after: list[ReliabilityBinOut]


class CalibrationResponse(BaseModel):
    refit_at: datetime
    n_feedback_events: int
    n_synthetic_feedback_events: int
    synthetic: bool
    overall_brier_before: float | None
    overall_brier_after: float | None
    detectors: list[DetectorCalibrationOut]


# ---------------------------------------------------------------------------- model versions


class ModelVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    model_key: str
    version: int
    artifact_ref: str
    trained_at: datetime
    eval_scores: dict[str, Any]
    promoted: bool


class ModelVersionsResponse(BaseModel):
    items: list[ModelVersionOut]
