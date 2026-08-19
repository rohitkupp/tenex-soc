"""`EXTRACTOR_FOR_DETECTOR` must stay closed over the two vocabularies it joins.

The map lets the evidence route answer "show me this detector's evidence" without any caller
deriving extractor names by string surgery (`signal.stl_residual` → `stl` is not a prefix
strip). Both sides are constants in the same module; this asserts the join never references a
name that stops existing, and that every L2 signal detector keeps an evidence extractor —
losing one would silently empty the Signals tab's evidence expansion for that detector.
"""

from __future__ import annotations

from app.detection.evidence import constants as c


def test_every_map_entry_references_declared_constants() -> None:
    signal_keys = {v for k, v in vars(c).items() if k.startswith("SIGNAL_")}
    extractor_labels = {v for k, v in vars(c).items() if k.startswith("EXTRACTOR_") and isinstance(v, str)}
    assert set(c.EXTRACTOR_FOR_DETECTOR) <= signal_keys
    assert set(c.EXTRACTOR_FOR_DETECTOR.values()) <= extractor_labels


def test_every_l2_signal_detector_has_an_extractor() -> None:
    signal_keys = {v for k, v in vars(c).items() if k.startswith("SIGNAL_")}
    unmapped = signal_keys - set(c.EXTRACTOR_FOR_DETECTOR)
    assert not unmapped, (
        f"L2 detector(s) {sorted(unmapped)} have no evidence extractor mapping — the Signals "
        "tab's evidence expansion would silently show nothing for them"
    )
