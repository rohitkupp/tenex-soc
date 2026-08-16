"""Consumer 5 — Benign corpus expansion (docs/08 Part 2, §5). Retrain-triggering.

`mark_benign_baseline=true` (`analyst_feedback`, docs/02) flags the incident's entity-windows for
inclusion in the next benign training corpus — "highest-fidelity loop for UEBA, because most
false positives are weird but sanctioned, and the fix is teaching the model that this shape of
weird is normal" (docs/08). Triggers retraining for the corpus-fitted L3 models (Isolation Forest,
Mahalanobis, ECOD, LOF — docs/04 §L3; the autoencoder that used to be in this list was removed,
migration change 19, `docs/v2_migration/MIGRATION-01-evidence-first.md`).

## Scope boundary

This module flags and exports; it does not itself retrain the L3 models or touch `datagen`'s
corpus builder (`app/detection/**` and `datagen/**` are both out of this milestone's ownership —
see `CLAUDE.md`'s task brief). `export_benign_baseline` is the handoff point: a future L3
retraining pipeline reads `benign_baseline_entries` and folds the flagged entity-windows into its
benign corpus. What "entity-window" means here is exactly docs/04 §L3's grain
(`entity_type`, `entity_value`, `window_start`, `window_end`) — sourced directly from the
dismissed incident's own `signals` rows (same source `app.learning.suppression` uses), not from
`entities` (no window information there).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.benign_baseline_entry import BenignBaselineEntry
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

__all__ = ["BenignWindowExport", "export_benign_baseline", "flag_benign_baseline"]


def flag_benign_baseline(
    session: Session, tenant_id: uuid.UUID, feedback: AnalystFeedback, *, synthetic: bool = False
) -> list[BenignBaselineEntry]:
    """docs/08 §5 trigger: `feedback.mark_benign_baseline is True`. Inserts one
    `benign_baseline_entries` row per distinct `(entity_type, entity_value, window)` the
    feedback's incident touched (deduplicated the same way `app.learning.suppression.
    _targets_for_incident` dedupes suppression targets, but keeping window bounds here since
    that is exactly the information a corpus rebuild needs and a suppression candidate does not).
    """
    if not feedback.mark_benign_baseline:
        return []

    with tenant_scope(session, tenant_id):
        verdict = session.get(TriageVerdict, feedback.verdict_id)
        if verdict is None:
            return []
        incident = session.get(Incident, verdict.incident_id)
        if incident is None or not incident.signal_ids:
            return []

        signals = (
            session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
            .scalars()
            .all()
        )

        seen: set[tuple[str, str, datetime | None, datetime | None]] = set()
        entries: list[BenignBaselineEntry] = []
        for sig in signals:
            key = (sig.entity_type, sig.entity_value, sig.window_start, sig.window_end)
            if key in seen:
                continue
            seen.add(key)
            entry = BenignBaselineEntry(
                tenant_id=tenant_id,
                feedback_id=feedback.id,
                incident_id=incident.id,
                entity_type=sig.entity_type,
                entity_value=sig.entity_value,
                window_start=sig.window_start,
                window_end=sig.window_end,
                synthetic=synthetic,
            )
            session.add(entry)
            entries.append(entry)
        session.flush()

    return entries


@dataclass(frozen=True, slots=True)
class BenignWindowExport:
    entity_type: str
    entity_value: str
    window_start: datetime | None
    window_end: datetime | None
    flagged_at: datetime
    synthetic: bool


def export_benign_baseline(
    session: Session, tenant_id: uuid.UUID, *, only_unconsumed: bool = True
) -> list[BenignWindowExport]:
    """Read side for a future L3 retraining pipeline (out of this milestone's ownership — see
    module docstring). `only_unconsumed=True` (the default) returns only entries whose
    `included_in_training_at` is still `NULL`, i.e. flagged but not yet folded into a corpus
    build; the caller is responsible for marking rows consumed once it actually uses them (not
    done here, since this module has no way to know a training run succeeded)."""
    with tenant_scope(session, tenant_id):
        stmt = select(BenignBaselineEntry)
        if only_unconsumed:
            stmt = stmt.where(BenignBaselineEntry.included_in_training_at.is_(None))
        rows = session.execute(stmt.order_by(BenignBaselineEntry.created_at.asc())).scalars().all()

    return [
        BenignWindowExport(
            entity_type=r.entity_type,
            entity_value=r.entity_value,
            window_start=r.window_start,
            window_end=r.window_end,
            flagged_at=r.created_at,
            synthetic=r.synthetic,
        )
        for r in rows
    ]
