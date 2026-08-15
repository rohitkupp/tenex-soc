"""Orchestration entrypoint for the whole L2 signal layer (docs/04 §L2).

`run_signal_layer` is the one function a future pipeline worker (`app/workers/**`, not this
milestone's to build or wire up) would call once L1 has run: fetch an analysis's events once,
run all four detectors over the same row set, persist every resulting `Signal` row in one
transaction. Each detector already tolerates an empty or detector-irrelevant row set (an all-
identity-source analysis with no `domain` values simply produces zero beaconing/DGA/rarity
drafts), so there is no branching here on which sources are present.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.detection.signal.beaconing import detect_beaconing
from app.detection.signal.burst import detect_burst
from app.detection.signal.constants import SIGNAL_BEACONING, SIGNAL_BURST, SIGNAL_DGA, SIGNAL_RARITY
from app.detection.signal.dga import DGAArtifact, detect_dga, load_artifact
from app.detection.signal.events_dao import fetch_event_rows, persist_signals
from app.detection.signal.rarity import detect_rarity
from app.models.base import tenant_scope
from app.models.signal import Signal

__all__ = ["SignalRunSummary", "run_signal_layer"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SignalRunSummary:
    analysis_id: uuid.UUID
    n_events: int
    counts_by_detector: dict[str, int]

    @property
    def total_signals(self) -> int:
        return sum(self.counts_by_detector.values())


def run_signal_layer(
    session: Session,
    *,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    dga_artifact: DGAArtifact | None = None,
) -> SignalRunSummary:
    """Run all four L2 detectors against `analysis_id`'s events and persist the resulting
    `signals` rows on `session` (flushed, not committed -- see `events_dao.persist_signals`).

    `session` must already be usable for `analysis_id`'s tenant; this function binds it to
    `tenant_id` for its own duration via `tenant_scope` rather than assuming the caller already
    did, restoring whatever scope (if any) was active before it returns.
    """
    with tenant_scope(session, tenant_id):
        rows = fetch_event_rows(session, analysis_id)

        artifact = dga_artifact if dga_artifact is not None else load_artifact()

        drafts = [
            *detect_beaconing(rows),
            *detect_dga(rows, artifact=artifact),
            *detect_burst(rows),
            *detect_rarity(rows),
        ]

        signals: list[Signal] = persist_signals(
            session, analysis_id=analysis_id, tenant_id=tenant_id, drafts=drafts
        )

    counts_by_detector = dict.fromkeys(
        (SIGNAL_BEACONING, SIGNAL_DGA, SIGNAL_BURST, SIGNAL_RARITY), 0
    )
    for s in signals:
        counts_by_detector[s.detector_key] = counts_by_detector.get(s.detector_key, 0) + 1

    summary = SignalRunSummary(
        analysis_id=analysis_id, n_events=len(rows), counts_by_detector=counts_by_detector
    )
    log.info(
        "signal_layer.done",
        analysis_id=str(analysis_id),
        n_events=summary.n_events,
        counts=summary.counts_by_detector,
        total=summary.total_signals,
    )
    return summary
