"""`app.detection.signal.constants`'s `detector_key` literals must stay byte-identical to
`datagen.types`'s `SIGNAL_*` constants, even though `app/detection/signal/**` deliberately does
not import `datagen` at runtime (see `constants.py`'s module docstring for why they are declared
independently rather than shared via import). This is the one test in the suite that legitimately
imports both sides of that boundary, specifically to audit that the boundary hasn't let the two
drift -- the same shape of cross-boundary audit `tests/test_datagen_s08_marginals.py` already
does for `app.detection.features`.
"""

from __future__ import annotations

from app.detection.signal.constants import (
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
)
from datagen.types import SIGNAL_BEACONING as GEN_BEACONING
from datagen.types import SIGNAL_BURST as GEN_BURST
from datagen.types import SIGNAL_DGA as GEN_DGA
from datagen.types import SIGNAL_RARITY as GEN_RARITY


def test_detector_keys_match_datagen_ground_truth_labels() -> None:
    assert SIGNAL_BEACONING == GEN_BEACONING
    assert SIGNAL_DGA == GEN_DGA
    assert SIGNAL_BURST == GEN_BURST
    assert SIGNAL_RARITY == GEN_RARITY


def test_detector_keys_use_the_signal_dot_prefix() -> None:
    for key in (SIGNAL_BEACONING, SIGNAL_DGA, SIGNAL_BURST, SIGNAL_RARITY):
        assert key.startswith("signal.")
