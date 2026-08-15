"""Shared label derivation over `analyst_feedback` -> `triage_verdicts` -> `incidents` ->
`signals`, used by both consumer 1 (`app/learning/calibration.py`) and consumer 2
(`app/learning/weights.py`) — factored out once both needed the same join and the same
confirmed/rejected -> label rule, rather than drifting into two slightly different copies.

docs/08 §1 and §2 both start from the same primitive: "confirmed and rejected dispositions
become labels." What differs downstream is only what each consumer *does* with the label
(fit an isotonic calibrator vs. accumulate TP/FP counts), not how the label is derived.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

__all__ = ["POSITIVE_DISPOSITION", "LabeledExample", "effective_label", "labeled_examples"]

POSITIVE_DISPOSITION = "true_positive"


@dataclass(frozen=True, slots=True)
class LabeledExample:
    detector_key: str
    detector_layer: str
    raw_score: float
    stated_confidence: float
    label: int  # 1 = confirmed/corrected true positive, 0 = confirmed/corrected false positive
    feedback_id: uuid.UUID
    incident_id: uuid.UUID
    signal_id: int
    created_at: datetime


def effective_label(verdict_disposition: str, feedback: AnalystFeedback) -> int:
    """A `corrected_disposition` overrides the verdict's own disposition (the analyst is saying
    the model got it wrong); plain confirm/reject needs no override -- the verdict's disposition
    already reflects analyst agreement or the caller wouldn't have `agrees=True`."""
    effective = feedback.corrected_disposition or verdict_disposition
    return 1 if effective == POSITIVE_DISPOSITION else 0


def labeled_examples(session: Session, tenant_id: uuid.UUID) -> list[LabeledExample]:
    """One row per (feedback event, contributing signal): every signal listed in
    `incidents.signal_ids` for the feedback's incident inherits that incident's outcome label.
    Fusion does not attribute credit to individual signals below the incident level, so this is
    the same attribution docs/08's weight-tuning formula (`precision_d = TP_d / (TP_d + FP_d)`)
    already assumes."""
    with tenant_scope(session, tenant_id):
        rows = session.execute(
            select(AnalystFeedback, TriageVerdict, Incident)
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
            .order_by(AnalystFeedback.created_at.asc())
        ).all()

        examples: list[LabeledExample] = []
        for feedback, verdict, incident in rows:
            if not incident.signal_ids:
                continue
            label = effective_label(verdict.disposition, feedback)
            signals = (
                session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
                .scalars()
                .all()
            )
            for sig in signals:
                examples.append(
                    LabeledExample(
                        detector_key=sig.detector_key,
                        detector_layer=sig.detector_layer,
                        raw_score=sig.raw_score,
                        stated_confidence=sig.confidence,
                        label=label,
                        feedback_id=feedback.id,
                        incident_id=incident.id,
                        signal_id=sig.id,
                        created_at=feedback.created_at,
                    )
                )
    return examples
