"""`POST /api/incidents/{id}/feedback` (docs/09) is the single entry point into every "no
retrain" consumer this milestone builds, plus the trigger for the two retrain-triggering ones.
This module is that entry point's implementation, kept separate from `app/api/learning.py` so the
orchestration logic (which consumer runs when, in what order, on what cadence) is unit-testable
without going through FastAPI/HTTP at all.

## Order of operations, and why

1. Insert the `analyst_feedback` row itself — every consumer below reads from it, so it must
   exist and be flushed (not just added) before anything else runs.
2. **Detector weight tuning** (consumer 2) — always recomputed. Cheap at this data scale, and
   docs/08 gives no cadence for it (unlike calibration's explicit "every 50 events"), so the
   least surprising default is "reflects the very latest feedback."
3. **Calibration refit** (consumer 1) — gated on `app.learning.calibration.should_refit_now`,
   docs/08's own stated cadence ("nightly or on every 50 feedback events"). This process owns no
   scheduler, so "every 50" is enforced here, synchronously, rather than dropped.
4. **Suppression rule generation** (consumer 4) — attempted on every call; the function itself
   is a no-op unless `dismissal_reason` is set (docs/08 §4's actual trigger).
5. **Benign corpus expansion** (consumer 5) — same shape: attempted every call, no-op unless
   `mark_benign_baseline` is true.
6. **Classifier retraining** (consumer 6) — gated on the same "every 50" cadence as calibration
   (docs/08 §6 says only "a feedback-count threshold," not a specific number; reusing
   calibration's documented number rather than inventing a second one).

Every consumer call after step 1 is best-effort in the sense that none of them can invalidate the
feedback row itself — if a later consumer's query finds nothing to do (e.g. no dismissal reason),
it returns an empty result, not an error. The one thing that *can* fail before step 1 completes is
"no triage verdict exists for this incident yet," which is a real precondition (docs/09: feedback
is per-incident, but every column feedback carries — `corrected_disposition`, `mitre_techniques`
lookups, etc. — is relative to a specific verdict) and is raised loudly as
`IncidentNotTriagedError` rather than silently skipped.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.learning.benign_corpus import flag_benign_baseline
from app.learning.calibration import CalibrationRefitResult, refit_calibrators, should_refit_now
from app.learning.retrain import RetrainAttempt, run_classifier_retrain
from app.learning.suppression import generate_suppression_candidates
from app.learning.weights import WeightTuningResult, retune_detector_weights
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import get_scoped, tenant_scope
from app.models.benign_baseline_entry import BenignBaselineEntry
from app.models.incident import Incident
from app.models.suppression_candidate import SuppressionCandidate
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "FeedbackInput",
    "FeedbackOutcome",
    "IncidentNotFoundError",
    "IncidentNotTriagedError",
    "record_feedback",
]


class IncidentNotFoundError(Exception):
    """No incident with this id exists for this tenant."""


class IncidentNotTriagedError(Exception):
    """The incident exists but has no `triage_verdicts` row yet — feedback needs a verdict to
    attach to (docs/02: `analyst_feedback.verdict_id` is `NOT NULL`)."""


@dataclass(frozen=True, slots=True)
class FeedbackInput:
    agrees: bool
    corrected_disposition: str | None = None
    corrected_technique: str | None = None
    dismissal_reason: str | None = None
    mark_benign_baseline: bool = False
    note: str | None = None
    # Not part of docs/09's request body (never set by `app.schemas.learning.FeedbackRequest` /
    # the real API route) -- an override hook so `app/scripts/seed_feedback.py` can backdate
    # synthetic feedback across a multi-week synthetic history instead of every seeded row
    # landing at the moment `make seed` happened to run, which would flatten every trend this
    # milestone needs to demonstrate. `None` (the only value a real HTTP request can produce)
    # keeps `analyst_feedback.created_at`'s own `server_default=now()`.
    created_at: datetime | None = None


@dataclass(slots=True)
class FeedbackOutcome:
    feedback_id: uuid.UUID
    weight_tuning: WeightTuningResult
    calibration_refit: CalibrationRefitResult | None
    suppression_candidates: list[SuppressionCandidate]
    benign_baseline_entries: list[BenignBaselineEntry]
    retrain_attempt: RetrainAttempt | None


def _tenant_feedback_count(session: Session, tenant_id: uuid.UUID) -> int:
    with tenant_scope(session, tenant_id):
        return session.execute(
            select(func.count(AnalystFeedback.id))
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
        ).scalar_one()


def record_feedback(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    incident_id: uuid.UUID,
    data: FeedbackInput,
) -> FeedbackOutcome:
    with tenant_scope(session, tenant_id):
        incident = get_scoped(session, Incident, incident_id)
        if incident is None:
            raise IncidentNotFoundError(f"no incident {incident_id} for tenant {tenant_id}")

        verdict = session.execute(
            select(TriageVerdict)
            .where(TriageVerdict.incident_id == incident_id)
            .order_by(TriageVerdict.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if verdict is None:
            raise IncidentNotTriagedError(f"incident {incident_id} has no triage verdict yet")

        feedback_kwargs: dict[str, object] = {
            "verdict_id": verdict.id,
            "user_id": user_id,
            "agrees": data.agrees,
            "corrected_disposition": data.corrected_disposition,
            "corrected_technique": data.corrected_technique,
            "dismissal_reason": data.dismissal_reason,
            "mark_benign_baseline": data.mark_benign_baseline,
            "note": data.note,
        }
        if data.created_at is not None:
            feedback_kwargs["created_at"] = data.created_at
        feedback = AnalystFeedback(**feedback_kwargs)
        session.add(feedback)
        session.flush()  # assign feedback.id before any consumer reads it back

    # Consumer 2 -- always recomputed (see module docstring for cadence reasoning).
    weight_result = retune_detector_weights(session, tenant_id)

    # Consumer 1 -- docs/08's own "every 50 feedback events" cadence.
    total_feedback = _tenant_feedback_count(session, tenant_id)
    calibration_result = (
        refit_calibrators(session, tenant_id) if should_refit_now(total_feedback) else None
    )

    # Consumer 4 -- no-op internally unless `dismissal_reason` is set.
    suppression_candidates = generate_suppression_candidates(session, tenant_id, feedback)

    # Consumer 5 -- no-op internally unless `mark_benign_baseline` is true.
    benign_entries = flag_benign_baseline(session, tenant_id, feedback)

    # Consumer 6 -- same cadence as consumer 1 (docs/08 §6 states only "a feedback-count
    # threshold," not a specific number; reusing §1's documented one rather than inventing a
    # second, undocumented cadence).
    retrain_attempt = (
        run_classifier_retrain(session, tenant_id) if should_refit_now(total_feedback) else None
    )

    # No explicit commit here -- every write above only flushed. `app.api.learning`'s route
    # depends on `app.core.db.get_db`, whose request-scoped session commits once, atomically, at
    # end of request (or rolls every write in this function back together on any exception).
    # `app/scripts/seed_feedback.py`, which does not go through `get_db`, commits explicitly on
    # its own schedule instead.

    return FeedbackOutcome(
        feedback_id=feedback.id,
        weight_tuning=weight_result,
        calibration_refit=calibration_result,
        suppression_candidates=suppression_candidates,
        benign_baseline_entries=benign_entries,
        retrain_attempt=retrain_attempt,
    )
