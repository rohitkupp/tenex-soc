"""Orchestration entrypoint for the whole evidence layer (docs/04 §L2; docs/v2_migration change
2, "L2 -> deterministic evidence extractors").

`run_evidence_layer` is the one function a future pipeline worker (`app/workers/**`, not this
milestone's to build or wire up) would call once L1 has run: fetch an analysis's events once, run
all six extractors over the same row set, persist every resulting `Signal` row in one transaction
**and** return the `EvidencePayload` list for the analysis. Each extractor already tolerates an
empty or detector-irrelevant row set (an all-identity-source analysis with no `domain` values
simply produces zero beaconing/DGA/rarity/url-path drafts), so there is no branching here on
which sources are present.

## Two outputs, one pass over the rows

`signals` rows and the existing detection pipeline still exist (fusion, correlation, the incident
path) -- this phase changes what the extractors *emit*, not the whole downstream (the migration's
own instruction). So this function still does exactly what `run_signal_layer` used to: call every
`detect_*`, persist `Signal` rows, return counts. It now *also* calls every `raw_evidence_*`,
resolves each against the baseline store (`resolve_evidence.py`), and finalizes the result
(`payload.finalize_evidence`) into the `EvidencePayload` list `EvidenceRunSummary.evidence`
carries. `EvidencePayload`s are not persisted to a table -- change 2 does not add one (unlike
change 1's `baseline_*` tables), so they are a return value for now, consumed by whatever
downstream phase (RAG retrieval / the Analyst LLM, docs/07, out of this package's ownership)
needs them next.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.detection.evidence.beaconing import detect_beaconing, raw_evidence_beaconing
from app.detection.evidence.burst import detect_burst, raw_evidence_burst
from app.detection.evidence.constants import (
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
    SIGNAL_STL_RESIDUAL,
    SIGNAL_URL_PATH,
)
from app.detection.evidence.dga import DGAArtifact, detect_dga, load_artifact, raw_evidence_dga
from app.detection.evidence.events_dao import fetch_event_rows, persist_signals
from app.detection.evidence.payload import EvidencePayload, RawEvidence, finalize_evidence
from app.detection.evidence.rarity import detect_rarity, raw_evidence_rarity
from app.detection.evidence.resolve_evidence import resolve_evidence
from app.detection.evidence.stl import detect_stl_residual, raw_evidence_stl
from app.detection.evidence.url_path import detect_url_path, raw_evidence_url_entropy
from app.models.base import tenant_scope
from app.models.signal import Signal

__all__ = ["EvidenceRunSummary", "run_evidence_layer"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EvidenceRunSummary:
    analysis_id: uuid.UUID
    n_events: int
    counts_by_detector: dict[str, int]
    evidence: list[EvidencePayload]

    @property
    def total_signals(self) -> int:
        return sum(self.counts_by_detector.values())


def run_evidence_layer(
    session: Session,
    *,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    dga_artifact: DGAArtifact | None = None,
) -> EvidenceRunSummary:
    """Run every extractor against `analysis_id`'s events, persist the resulting `signals` rows
    on `session` (flushed, not committed -- see `events_dao.persist_signals`), and return the
    finalized `EvidencePayload` list alongside the same signal counts `run_signal_layer` used to
    report.

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
            *detect_stl_residual(rows),
            *detect_url_path(rows),
        ]

        signals: list[Signal] = persist_signals(
            session, analysis_id=analysis_id, tenant_id=tenant_id, drafts=drafts
        )

        # Fixed order matching `payload.EXTRACTOR_ORDER` -- not load-bearing for correctness
        # (`finalize_evidence` re-sorts), but keeps this list's construction order legible next to
        # the `EXTRACTOR_ORDER` docstring it mirrors.
        raw_evidence: list[RawEvidence] = [
            *raw_evidence_beaconing(rows),
            *raw_evidence_dga(rows, artifact=artifact),
            *raw_evidence_burst(rows),
            *raw_evidence_rarity(rows),
            *raw_evidence_stl(rows),
            *raw_evidence_url_entropy(rows),
        ]
        evidence_drafts = resolve_evidence(session, tenant_id, raw_evidence)
        evidence_payloads = finalize_evidence(evidence_drafts)

    counts_by_detector = dict.fromkeys(
        (
            SIGNAL_BEACONING,
            SIGNAL_DGA,
            SIGNAL_BURST,
            SIGNAL_RARITY,
            SIGNAL_STL_RESIDUAL,
            SIGNAL_URL_PATH,
        ),
        0,
    )
    for s in signals:
        counts_by_detector[s.detector_key] = counts_by_detector.get(s.detector_key, 0) + 1

    summary = EvidenceRunSummary(
        analysis_id=analysis_id,
        n_events=len(rows),
        counts_by_detector=counts_by_detector,
        evidence=evidence_payloads,
    )
    log.info(
        "evidence_layer.done",
        analysis_id=str(analysis_id),
        n_events=summary.n_events,
        counts=summary.counts_by_detector,
        total_signals=summary.total_signals,
        n_evidence=len(evidence_payloads),
        n_nominated=sum(1 for e in evidence_payloads if e.nominates_candidate),
    )
    return summary
