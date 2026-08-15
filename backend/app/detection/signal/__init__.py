"""L2 signal processing (docs/04 §L2): beaconing, DGA/domain-entropy, volumetric burst, and
rarity/first-seen. "Not ML. The right tool for the job" -- every detector here is closed-form
statistics over `(analysis_id, entity)`-scoped event rows, run after L1's Sigma rules and before
L3's entity-window ML models.

Public surface: `run_signal_layer` (`run.py`) is the one entrypoint a pipeline worker needs.
Each detector is also independently importable and DB-free (`beaconing.detect_beaconing`,
`dga.detect_dga`, `burst.detect_burst`, `rarity.detect_rarity`) for anything that wants to score
a pre-fetched row set without touching Postgres -- exactly what `tests/test_signal_*.py` does.
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
)
from app.detection.signal.dga import detect_dga
from app.detection.signal.rarity import detect_rarity
from app.detection.signal.run import SignalRunSummary, run_signal_layer

__all__ = [
    "DETECTOR_LAYER",
    "ENTITY_DOMAIN",
    "ENTITY_SRC_IP",
    "ENTITY_USER",
    "SIGNAL_BEACONING",
    "SIGNAL_BURST",
    "SIGNAL_DGA",
    "SIGNAL_RARITY",
    "SignalRunSummary",
    "detect_beaconing",
    "detect_burst",
    "detect_dga",
    "detect_rarity",
    "run_signal_layer",
]
