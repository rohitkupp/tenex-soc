"""Mechanism 3 — entity threshold adaptation (change 21, auto-apply).

"Raise for one service account, not globally." Detector weight tuning (mechanism 2) already
adjusts fusion globally per detector; this mechanism is the narrower, per-entity complement: an
entity a real analyst dismisses repeatedly gets a *higher* confidence bar before a future window
for that same entity is even considered a candidate, while an entity that keeps getting confirmed
gets its bar relaxed back toward the system default. Scoped to `(entity_type, entity_value)`,
optionally further scoped to one `detector_key` when a feedback event's incident carries exactly
one contributing detector (a dismissal that clearly indicts one detector should not raise the bar
for every detector this entity happens to trip); `ALL_DETECTORS` otherwise.

Recomputed from full history on every call (mirrors `app.learning.weights.
retune_detector_weights`'s own "recomputed from scratch, not incrementally drifted" convention),
which is what keeps this reversible: a run of dismissals raises the threshold, a later run of
confirms lowers it back, with no path-dependent drift.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.ml.detect import SIGNAL_CONFIDENCE_THRESHOLD
from app.learning.mechanisms import record_event
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.entity_threshold_override import ALL_DETECTORS, EntityThresholdOverride
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "MAX_THRESHOLD",
    "MIN_DISMISSALS_TO_RAISE",
    "MIN_THRESHOLD",
    "STEP",
    "EntityThresholdChange",
    "adapt_entity_threshold",
]

MIN_THRESHOLD = SIGNAL_CONFIDENCE_THRESHOLD  # never relax below the system-wide default
MAX_THRESHOLD = 0.9995  # never require near-impossible certainty
STEP = 0.001
# A single dismissal is normal SOC noise; a *pattern* (this many dismissals for the same entity)
# is what earns a threshold raise -- mirrors `app.learning.weights`'s own precedent of acting on
# accumulated history, not a single event.
MIN_DISMISSALS_TO_RAISE = 2


@dataclass(frozen=True, slots=True)
class EntityThresholdChange:
    entity_type: str
    entity_value: str
    detector_key: str
    confirm_count: int
    dismiss_count: int
    threshold_before: float
    threshold_after: float
    changed: bool


def _detector_scope(session: Session, incident: Incident) -> str:
    """`ALL_DETECTORS` unless every contributing signal shares exactly one `detector_key` --
    see module docstring."""
    if not incident.signal_ids:
        return ALL_DETECTORS
    keys = {
        row[0]
        for row in session.execute(
            select(Signal.detector_key).where(Signal.id.in_(incident.signal_ids))
        ).all()
    }
    return keys.pop() if len(keys) == 1 else ALL_DETECTORS


def adapt_entity_threshold(
    session: Session,
    tenant_id: uuid.UUID,
    feedback: AnalystFeedback,
    *,
    trigger_feedback_id: uuid.UUID,
) -> EntityThresholdChange | None:
    """Mechanism 3, run on every feedback event. Returns `None` (no-op, no `learning_events` row)
    when the incident carries no signals to key an entity off of. Otherwise always recomputes and
    upserts `entity_threshold_overrides` for every distinct entity the incident's signals touch,
    and always logs a `learning_events` row (mechanism 3, `applied=True`) -- auto mechanisms take
    effect unconditionally, per change 21's own line.
    """
    with tenant_scope(session, tenant_id):
        verdict = session.get(TriageVerdict, feedback.verdict_id)
        if verdict is None:
            return None
        incident = session.get(Incident, verdict.incident_id)
        if incident is None or not incident.signal_ids:
            return None

        signals = (
            session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
            .scalars()
            .all()
        )
        if not signals:
            return None

        detector_key = _detector_scope(session, incident)
        entities = {(s.entity_type, s.entity_value) for s in signals}

        # Only ever one entity per real incident in this codebase's fixtures/UI (an incident
        # carries multiple signals *about* the same entity, not several entities); iterate anyway
        # so a correlated multi-entity incident is handled rather than silently narrowed to one.
        last_change: EntityThresholdChange | None = None
        for entity_type, entity_value in sorted(entities):
            row = session.execute(
                select(EntityThresholdOverride).where(
                    EntityThresholdOverride.entity_type == entity_type,
                    EntityThresholdOverride.entity_value == entity_value,
                    EntityThresholdOverride.detector_key == detector_key,
                )
            ).scalar_one_or_none()

            confirm_count = (row.confirm_count if row else 0) + (1 if feedback.agrees else 0)
            dismiss_count = (row.dismiss_count if row else 0) + (0 if feedback.agrees else 1)
            threshold_before = row.threshold_percentile if row else MIN_THRESHOLD

            if dismiss_count >= MIN_DISMISSALS_TO_RAISE and not feedback.agrees:
                threshold_after = min(MAX_THRESHOLD, threshold_before + STEP)
                reason = f"{dismiss_count} dismissals recorded for this entity"
            elif feedback.agrees:
                threshold_after = max(MIN_THRESHOLD, threshold_before - STEP)
                reason = f"{confirm_count} confirmations recorded for this entity"
            else:
                threshold_after = threshold_before
                reason = "below the dismissal pattern threshold; no change yet"

            if row is None:
                row = EntityThresholdOverride(
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    detector_key=detector_key,
                    threshold_percentile=threshold_after,
                    confirm_count=confirm_count,
                    dismiss_count=dismiss_count,
                    reason=reason,
                )
                session.add(row)
            else:
                row.threshold_percentile = threshold_after
                row.confirm_count = confirm_count
                row.dismiss_count = dismiss_count
                row.reason = reason
                row.updated_at = datetime.now(UTC)
            session.flush()

            last_change = EntityThresholdChange(
                entity_type=entity_type,
                entity_value=entity_value,
                detector_key=detector_key,
                confirm_count=confirm_count,
                dismiss_count=dismiss_count,
                threshold_before=threshold_before,
                threshold_after=threshold_after,
                changed=abs(threshold_after - threshold_before) > 1e-9,
            )

        if last_change is None:
            return None

        record_event(
            session,
            mechanism=3,
            applied=True,
            trigger_feedback_id=trigger_feedback_id,
            before_state={"threshold_percentile": last_change.threshold_before},
            after_state={
                "entity_type": last_change.entity_type,
                "entity_value": last_change.entity_value,
                "detector_key": last_change.detector_key,
                "threshold_percentile": last_change.threshold_after,
                "confirm_count": last_change.confirm_count,
                "dismiss_count": last_change.dismiss_count,
            },
            metric_delta={
                "threshold_percentile": last_change.threshold_after - last_change.threshold_before
            },
        )
        return last_change
