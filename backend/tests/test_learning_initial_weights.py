"""`app.learning.initial_weights` — docs/12 change 4 ("Audit and set initial fusion weights").
Pure math + file round-trip, no DB.
"""

from __future__ import annotations

import math
from pathlib import Path

from app.detection.ml.detect import SHIPPED_MODEL_FIELDS
from app.learning.initial_weights import (
    compute_shipped_initial_weights,
    derive_initial_weights,
    load_initial_fusion_weights,
    save_initial_fusion_weights,
)
from app.learning.weights import MAX_FUSION_WEIGHT, MIN_FUSION_WEIGHT


def test_low_precision_detector_seeds_below_a_high_precision_one() -> None:
    """The motivating example from docs/12 change 4 itself: LOF (measured precision ~0.003 on
    this corpus) must not enter fusion with the same authority as EIF (~0.2) just because neither
    has analyst feedback yet."""
    counts = {
        "ml.eif": (33, 127),  # precision ~0.206
        "ml.kth_nn": (44, 4441),  # precision ~0.0098
        "ml.peer_group": (43, 13785),  # precision ~0.0031 (LOF)
    }
    weights = derive_initial_weights(counts)
    assert weights["ml.peer_group"] < weights["ml.eif"]
    assert weights["ml.peer_group"] < weights["ml.kth_nn"]


def test_weights_stay_within_mechanism_2s_clamp() -> None:
    """Same bounds mechanism 2 (`app.learning.weights.retune_detector_weights`) clamps its own
    learned weights to -- so a seeded value and a later analyst-feedback-learned value are always
    comparable on one scale, never a seeded value mechanism 2 could not itself have produced."""
    counts = {
        "ml.a": (100, 0),  # perfect precision -- would blow past 1.5x without the clamp
        "ml.b": (1, 10_000),  # near-zero precision -- would fall far below 0.25x without it
        "ml.c": (5, 5),
    }
    weights = derive_initial_weights(counts)
    for w in weights.values():
        assert MIN_FUSION_WEIGHT <= w <= MAX_FUSION_WEIGHT
    assert math.isclose(weights["ml.a"], MAX_FUSION_WEIGHT)
    assert math.isclose(weights["ml.b"], MIN_FUSION_WEIGHT)


def test_detector_at_the_pooled_average_precision_seeds_at_1_0() -> None:
    """Mechanism 2's own documented convention (`retune_detector_weights`'s docstring): a
    detector performing exactly at the pooled/prior precision gets no adjustment."""
    counts = {"ml.a": (10, 10), "ml.b": (10, 10)}  # identical precision -> both == the prior
    weights = derive_initial_weights(counts)
    assert math.isclose(weights["ml.a"], 1.0)
    assert math.isclose(weights["ml.b"], 1.0)


def test_never_fired_detector_stays_neutral() -> None:
    counts = {"ml.never_fired": (0, 0), "ml.other": (5, 5)}
    weights = derive_initial_weights(counts)
    assert weights["ml.never_fired"] == 1.0


def test_compute_shipped_initial_weights_narrows_to_shipped_models_only() -> None:
    """Benchmark-only baselines (iForest/Mahalanobis/ECOD) must not receive a seeded weight --
    they never write a live `Signal` row (migration change 19), so seeding one would be inert,
    and folding their precision into the pooled prior would distort it for the three that do."""
    pooled = {
        "ml.iforest": {"tp": 6, "fp": 8},
        "ml.mahalanobis": {"tp": 6, "fp": 55},
        "ml.ecod": {"tp": 12, "fp": 0},
        "ml.peer_group": {"tp": 43, "fp": 13785},
        "ml.eif": {"tp": 33, "fp": 127},
        "ml.kth_nn": {"tp": 44, "fp": 4441},
    }
    weights = compute_shipped_initial_weights(pooled)
    assert set(weights) == set(SHIPPED_MODEL_FIELDS)
    assert weights["ml.peer_group"] < weights["ml.eif"]


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    weights = {"ml.eif": 1.5, "ml.kth_nn": 1.2, "ml.peer_group": 0.4}
    save_initial_fusion_weights(weights, source={"eval_seed": 7}, models_dir=tmp_path)
    loaded = load_initial_fusion_weights(models_dir=tmp_path)
    assert loaded == weights


def test_load_missing_artifact_returns_empty_dict_not_an_error(tmp_path: Path) -> None:
    assert load_initial_fusion_weights(models_dir=tmp_path / "does-not-exist") == {}
