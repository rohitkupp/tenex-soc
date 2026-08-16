"""Deterministic evidence extractors (docs/04 §L2; docs/v2_migration/MIGRATION-01-evidence-first.md
change 2): beaconing (CV/jitter + FFT periodicity), DGA/domain-entropy, volumetric burst,
rarity/first-seen, STL seasonal residual, and URL path entropy. "Not ML. The right tool for the
job" -- every extractor here is closed-form statistics over `(analysis_id, entity)`-scoped event
rows, run after L1's Sigma rules and before L3's entity-window ML models.

## Two output contracts, side by side

Each extractor still produces a `SignalDraft` (a calibrated-ish score for the `signals` table --
fusion, correlation, and the incident path are unchanged, per the migration's own instruction) via
its `detect_*` function, **and** an `EvidencePayload` (raw measurements plus historical baseline
context, for the LLM) via its `raw_evidence_*` function. See `payload.py`'s module docstring for
the full three-stage pipeline (`RawEvidence -> EvidenceDraft -> EvidencePayload`) and why it takes
three stages instead of one.

Public surface: `run_evidence_layer` (`run.py`) is the one entrypoint a pipeline worker needs --
it runs both output contracts in one pass over the same fetched rows. Each extractor is also
independently importable and DB-free (`beaconing.detect_beaconing`/`raw_evidence_beaconing`,
`dga.detect_dga`/`raw_evidence_dga`, `burst.detect_burst`/`raw_evidence_burst`,
`rarity.detect_rarity`/`raw_evidence_rarity`, `stl.detect_stl_residual`/`raw_evidence_stl`,
`url_path.detect_url_path`/`raw_evidence_url_entropy`) for anything that wants to score a
pre-fetched row set without touching Postgres -- exactly what `tests/test_evidence_*.py` does.
Only `resolve_evidence.py` (baseline lookups) and `events_dao.py` (event fetch / signal persist)
touch the database.
"""

from __future__ import annotations

from app.detection.evidence.beaconing import detect_beaconing, raw_evidence_beaconing
from app.detection.evidence.burst import detect_burst, raw_evidence_burst
from app.detection.evidence.constants import (
    DETECTOR_LAYER,
    ENTITY_DOMAIN,
    ENTITY_SRC_IP,
    ENTITY_USER,
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
    SIGNAL_STL_RESIDUAL,
    SIGNAL_URL_PATH,
)
from app.detection.evidence.dga import detect_dga, raw_evidence_dga
from app.detection.evidence.payload import EvidencePayload
from app.detection.evidence.rarity import detect_rarity, raw_evidence_rarity
from app.detection.evidence.run import EvidenceRunSummary, run_evidence_layer
from app.detection.evidence.stl import detect_stl_residual, raw_evidence_stl
from app.detection.evidence.url_path import detect_url_path, raw_evidence_url_entropy

__all__ = [
    "DETECTOR_LAYER",
    "ENTITY_DOMAIN",
    "ENTITY_SRC_IP",
    "ENTITY_USER",
    "EXTRACTOR_BEACONING",
    "EXTRACTOR_BURST",
    "EXTRACTOR_DGA",
    "EXTRACTOR_RARITY",
    "EXTRACTOR_STL",
    "EXTRACTOR_URL_ENTROPY",
    "SIGNAL_BEACONING",
    "SIGNAL_BURST",
    "SIGNAL_DGA",
    "SIGNAL_RARITY",
    "SIGNAL_STL_RESIDUAL",
    "SIGNAL_URL_PATH",
    "EvidencePayload",
    "EvidenceRunSummary",
    "detect_beaconing",
    "detect_burst",
    "detect_dga",
    "detect_rarity",
    "detect_stl_residual",
    "detect_url_path",
    "raw_evidence_beaconing",
    "raw_evidence_burst",
    "raw_evidence_dga",
    "raw_evidence_rarity",
    "raw_evidence_stl",
    "raw_evidence_url_entropy",
    "run_evidence_layer",
]
