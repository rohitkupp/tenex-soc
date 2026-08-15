"""L2 signal processing (docs/04 §L2): beaconing (CV/jitter + FFT periodicity), DGA/domain-
entropy, volumetric burst, rarity/first-seen, STL seasonal residual, and URL path analysis. "Not
ML. The right tool for the job" -- every detector here is closed-form statistics over
`(analysis_id, entity)`-scoped event rows, run after L1's Sigma rules and before L3's
entity-window ML models.

Public surface: `run_signal_layer` (`run.py`) is the one entrypoint a pipeline worker needs.
Each detector is also independently importable and DB-free (`beaconing.detect_beaconing`,
`dga.detect_dga`, `burst.detect_burst`, `rarity.detect_rarity`, `stl.detect_stl_residual`,
`url_path.detect_url_path`) for anything that wants to score a pre-fetched row set without
touching Postgres -- exactly what `tests/test_signal_*.py` does.
"""

from __future__ import annotations

from app.detection.signal.beaconing import detect_beaconing
from app.detection.signal.burst import detect_burst
from app.detection.signal.constants import (
    DETECTOR_LAYER,
    ENTITY_DOMAIN,
    ENTITY_SRC_IP,
    ENTITY_USER,
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
    SIGNAL_STL_RESIDUAL,
    SIGNAL_URL_PATH,
)
from app.detection.signal.dga import detect_dga
from app.detection.signal.rarity import detect_rarity
from app.detection.signal.run import SignalRunSummary, run_signal_layer
from app.detection.signal.stl import detect_stl_residual
from app.detection.signal.url_path import detect_url_path

__all__ = [
    "DETECTOR_LAYER",
    "ENTITY_DOMAIN",
    "ENTITY_SRC_IP",
    "ENTITY_USER",
    "SIGNAL_BEACONING",
    "SIGNAL_BURST",
    "SIGNAL_DGA",
    "SIGNAL_RARITY",
    "SIGNAL_STL_RESIDUAL",
    "SIGNAL_URL_PATH",
    "SignalRunSummary",
    "detect_beaconing",
    "detect_burst",
    "detect_dga",
    "detect_rarity",
    "detect_stl_residual",
    "detect_url_path",
    "run_signal_layer",
]
