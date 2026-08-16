"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's "Models & learning" section, as implemented
by `app/api/learning.py` and `app/api/models.py` (M13). Response shapes are this milestone's own
design where docs/09 gives only a one-line description ("alignment %, per-detector precision
trend") and no field-level contract. Containment rate was removed along with the response
action graph in docs/v2_migration change 20.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------- feedback


class DomainLabelCorrectionIn(BaseModel):
    domain: str
    is_dga: bool


class FeedbackRequest(BaseModel):
    """`POST /api/incidents/{id}/feedback` body, docs/09 verbatim: `{agrees,
    corrected_disposition?, corrected_technique?, dismissal_reason?, mark_benign_baseline?,
    note?}`. `corrected_technique`, when set, must be one of the verdict's own retrieved
    candidates plus `NO_KNOWN_MAPPING` (change 22) — enforced server-side in
    `app.learning.feedback.record_feedback`. `dismissal_reason`, when set from the change-22
    Dismiss control, is one of `app.learning.feedback.DISMISSAL_REASON_CATEGORIES`; the column
    itself stays a plain string for backward compatibility with pre-migration callers.
    `corrected_domain_labels` is change 21 mechanism 8's input hook, optional and additive."""

    agrees: bool
    corrected_disposition: str | None = None
    corrected_technique: str | None = None
    dismissal_reason: str | None = None
    mark_benign_baseline: bool = False
    note: str | None = None
    corrected_domain_labels: list[DomainLabelCorrectionIn] = []


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
    # docs/v2_migration change 21/22 additions -- what the frontend's confirmation toast (change
    # 22: "naming the effect") names. `reference_set_mechanism` is `4` (added to the kNN/LOF
    # reference set), `5` (excluded as a confirmed true positive), or `None` (neither fired --
    # see `app.learning.feedback._reference_set_action`).
    reference_set_mechanism: int | None = None
    baseline_expansion_proposed: bool = False
    exemplar_proposed: bool = False


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


class LearningMetricsResponse(BaseModel):
    computed_at: datetime
    n_feedback_events: int
    n_synthetic_feedback_events: int
    synthetic: bool  # true if ANY of the above feedback events are seeded, not real
    alignment_pct: float | None
    alignment_trend: list[AlignmentPointOut]
    detector_precision_trend: list[DetectorPrecisionPointOut]


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


# ---------------------------------------------------------------------------- change 21/22 additions


class ClaimFeedbackRequest(BaseModel):
    helpful: bool
    note: str | None = None


class ClaimFeedbackResponse(BaseModel):
    id: int
    incident_id: uuid.UUID
    step: int
    helpful: bool
    verifier_rule_proposed: bool


class EvidenceRelevanceRequest(BaseModel):
    extractor: str
    relevant: bool


class EvidenceRelevanceResponse(BaseModel):
    id: int
    incident_id: uuid.UUID
    evidence_id: str
    relevant: bool
    widening_proposed: bool


class LearningEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mechanism: int
    mechanism_name: str
    trigger_feedback_id: uuid.UUID | None
    applied: bool
    before_state: dict[str, Any] | None
    after_state: dict[str, Any] | None
    metric_delta: dict[str, Any] | None
    created_at: datetime


class LearningEventsResponse(BaseModel):
    items: list[LearningEventOut]


class LearningProposalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    mechanism: int
    mechanism_name: str
    status: str
    payload: dict[str, Any]
    supporting_feedback_ids: list[uuid.UUID]
    created_at: datetime
    reviewed_at: datetime | None


class LearningProposalsResponse(BaseModel):
    items: list[LearningProposalOut]


class LearningProposalDecisionResponse(BaseModel):
    id: uuid.UUID
    status: str
    passed: bool
    after_state: dict[str, Any]
    metric_delta: dict[str, Any]
    reason: str
