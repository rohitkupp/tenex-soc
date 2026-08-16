"""Mechanism 13 — retrieval prior tuning (change 21, auto-apply).

"Track which retrieved techniques the Analyst supports vs. ignores. Retrieved 40 times and never
supported for an evidence pattern -> down-weight for that pattern." This package's own data gives
a technique-level (not pattern-level) view: `triage_verdicts.mitre_techniques` is the retrieved
candidate set a verdict's Analyst stage evaluated (docs/v2_migration change 5, "hypothesis
evaluation"); `analyst_feedback.corrected_technique` is the strongest possible "supported" signal
(an analyst explicitly agreeing the technique was right) and a plain `agrees=True` confirmation of
a verdict that already names a technique counts as support too. A technique appearing in
`mitre_techniques` that a feedback event neither confirms nor corrects *to* counts as "retrieved,
not supported" -- see `record_retrieval_outcome`.

`weight` is recomputed from full history every call (same "recompute from scratch, don't drift
incrementally" convention `app.learning.weights`/`app.learning.entity_thresholds` both use):
`clamp(supported / max(retrieved, 1), floor=0.25, ceiling=1.0)`, capped at `1.0` since a
technique's retrieval weight is a *down*-weighting-only signal here (unlike fusion weight tuning,
nothing in this milestone's data justifies a retrieval prior *above* neutral).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import record_event
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.retrieval_prior import RetrievalPrior
from app.models.triage_verdict import TriageVerdict

__all__ = ["MIN_WEIGHT", "RetrievalPriorChange", "record_retrieval_outcome"]

MIN_WEIGHT = 0.25
_NEUTRAL_WEIGHT = 1.0


@dataclass(frozen=True, slots=True)
class RetrievalPriorChange:
    technique_id: str
    retrieved_count: int
    supported_count: int
    weight_before: float
    weight_after: float
    changed: bool


def _extract_technique_ids(mitre_techniques: object) -> list[str]:
    if not isinstance(mitre_techniques, list):
        return []
    out: list[str] = []
    for item in mitre_techniques:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            tid = item.get("technique") or item.get("id") or item.get("mitre_technique")
            if isinstance(tid, str):
                out.append(tid)
    return out


def record_retrieval_outcome(
    session: Session,
    tenant_id: uuid.UUID,
    verdict: TriageVerdict,
    feedback: AnalystFeedback,
    *,
    trigger_feedback_id: uuid.UUID,
) -> list[RetrievalPriorChange]:
    """Run on every feedback event whose verdict named at least one technique. Every technique in
    `verdict.mitre_techniques` is "retrieved"; `feedback.corrected_technique`, or (when the
    analyst simply agreed) the verdict's own first-listed technique, is "supported." Returns `[]`
    (no `learning_events` row) when the verdict named no techniques -- nothing to tune a prior
    for.
    """
    retrieved = _extract_technique_ids(verdict.mitre_techniques)
    if not retrieved:
        return []

    supported: set[str] = set()
    if feedback.corrected_technique:
        supported.add(feedback.corrected_technique)
    elif feedback.agrees and retrieved:
        supported.add(retrieved[0])

    changes: list[RetrievalPriorChange] = []
    with tenant_scope(session, tenant_id):
        for technique_id in sorted(set(retrieved)):
            row = session.execute(
                select(RetrievalPrior).where(RetrievalPrior.technique_id == technique_id)
            ).scalar_one_or_none()
            weight_before = row.weight if row else _NEUTRAL_WEIGHT
            retrieved_count = (row.retrieved_count if row else 0) + 1
            supported_count = (row.supported_count if row else 0) + (
                1 if technique_id in supported else 0
            )
            weight_after = max(MIN_WEIGHT, min(_NEUTRAL_WEIGHT, supported_count / retrieved_count))

            if row is None:
                row = RetrievalPrior(
                    tenant_id=tenant_id,
                    technique_id=technique_id,
                    retrieved_count=retrieved_count,
                    supported_count=supported_count,
                    weight=weight_after,
                )
                session.add(row)
            else:
                row.retrieved_count = retrieved_count
                row.supported_count = supported_count
                row.weight = weight_after
                row.updated_at = datetime.now(UTC)
            session.flush()

            changes.append(
                RetrievalPriorChange(
                    technique_id=technique_id,
                    retrieved_count=retrieved_count,
                    supported_count=supported_count,
                    weight_before=weight_before,
                    weight_after=weight_after,
                    changed=abs(weight_after - weight_before) > 1e-9,
                )
            )

        record_event(
            session,
            mechanism=13,
            applied=True,
            trigger_feedback_id=trigger_feedback_id,
            before_state={c.technique_id: c.weight_before for c in changes},
            after_state={c.technique_id: c.weight_after for c in changes},
            metric_delta={c.technique_id: c.weight_after - c.weight_before for c in changes},
        )

    return changes
