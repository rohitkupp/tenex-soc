"""Unit tests for `app.detection.calibration` (docs/04 §Fusion "Per-detector calibration").
Synthetic `DetectorSample` fixtures; no DB, no trained ml artifacts required."""

from __future__ import annotations

import random

import pytest

from app.detection.calibration import (
    MIN_SAMPLES_TO_FIT,
    CalibratorStore,
    DetectorSample,
    clamp01,
    fit_calibrator,
    fit_calibrators,
    reliability_diagram,
)


def _separable_samples(n: int = 200, seed: int = 0) -> list[DetectorSample]:
    """Raw scores where higher genuinely means "more likely positive" -- benign scores drawn
    low, attack scores drawn high, with overlap, so isotonic regression has real work to do
    (not a degenerate step function)."""
    rng = random.Random(seed)
    samples = []
    for _ in range(n):
        is_attack = rng.random() < 0.2
        raw = rng.gauss(6.0, 1.5) if is_attack else rng.gauss(2.0, 1.5)
        samples.append(
            DetectorSample(detector_key="test.detector", raw_score=raw, label=int(is_attack))
        )
    return samples


def test_clamp01_bounds_and_nan() -> None:
    assert clamp01(-5.0) == 0.0
    assert clamp01(5.0) == 1.0
    assert clamp01(0.5) == 0.5
    assert clamp01(float("nan")) == 0.0


def test_fit_calibrator_returns_none_below_minimum_samples() -> None:
    samples = [
        DetectorSample("d", raw_score=float(i), label=i % 2) for i in range(MIN_SAMPLES_TO_FIT - 1)
    ]
    assert fit_calibrator("d", samples) is None


def test_fit_calibrator_returns_none_for_single_class() -> None:
    samples = [DetectorSample("d", raw_score=float(i), label=0) for i in range(20)]
    assert fit_calibrator("d", samples) is None


def test_fit_calibrator_is_monotonically_increasing() -> None:
    samples = _separable_samples()
    calibrator = fit_calibrator("test.detector", samples)
    assert calibrator is not None
    low = calibrator.calibrate(0.0)
    mid = calibrator.calibrate(4.0)
    high = calibrator.calibrate(10.0)
    assert low <= mid <= high


def test_fit_calibrator_output_is_a_probability() -> None:
    samples = _separable_samples()
    calibrator = fit_calibrator("test.detector", samples)
    assert calibrator is not None
    for raw in (-10.0, 0.0, 3.0, 6.0, 20.0):
        conf = calibrator.calibrate(raw)
        assert 0.0 <= conf <= 1.0


def test_fit_calibrator_learns_a_real_separation() -> None:
    """The whole point of calibration: a raw score typical of the attack population should
    calibrate meaningfully higher than one typical of the benign population."""
    samples = _separable_samples()
    calibrator = fit_calibrator("test.detector", samples)
    assert calibrator is not None
    benign_typical = calibrator.calibrate(2.0)
    attack_typical = calibrator.calibrate(6.0)
    assert attack_typical > benign_typical
    assert attack_typical > 0.5
    assert benign_typical < 0.5


def test_fit_calibrators_groups_by_detector_key() -> None:
    samples = _separable_samples()
    other_key_samples = [
        DetectorSample("other.detector", raw_score=s.raw_score, label=s.label) for s in samples
    ]
    calibrators = fit_calibrators(samples + other_key_samples)
    assert set(calibrators) == {"test.detector", "other.detector"}


def test_calibrator_store_falls_back_to_clamp01_for_unknown_detector(tmp_path: object) -> None:
    from pathlib import Path

    store = CalibratorStore(directory=Path(str(tmp_path)) / "empty")
    assert store.calibrate("nonexistent.detector", 0.7) == clamp01(0.7)
    assert store.calibrate("nonexistent.detector", 5.0) == 1.0


def test_calibrator_store_save_and_reload_round_trips(tmp_path: object) -> None:
    from pathlib import Path

    directory = Path(str(tmp_path)) / "calibrators"
    store = CalibratorStore(directory=directory)
    calibrator = fit_calibrator("test.detector", _separable_samples())
    assert calibrator is not None
    store.save(calibrator)

    reloaded = CalibratorStore(directory=directory)
    assert reloaded.has("test.detector")
    assert reloaded.calibrate("test.detector", 6.0) == pytest.approx(
        store.calibrate("test.detector", 6.0)
    )


def test_reliability_diagram_perfect_calibration_has_zero_brier_score() -> None:
    import numpy as np

    confidences = np.array([0.0, 0.0, 1.0, 1.0], dtype=np.float64)
    labels = np.array([0, 0, 1, 1], dtype=np.int64)
    report = reliability_diagram(confidences, labels, n_bins=10)
    assert report.brier_score == pytest.approx(0.0)


def test_reliability_diagram_bins_cover_the_full_range() -> None:
    import numpy as np

    rng = np.random.default_rng(0)
    confidences = rng.random(500)
    labels = (rng.random(500) < confidences).astype(np.int64)
    report = reliability_diagram(confidences, labels, n_bins=10)
    assert len(report.bins) == 10
    assert sum(b.n for b in report.bins) == 500
    assert 0.0 <= report.brier_score <= 1.0
