"""Sanity checks on `evals.config` — every constant docs/12 pins a specific value to (tolerances,
scenario count) is asserted here so a typo'd tolerance can't silently drift from the spec.
"""

from __future__ import annotations

from evals import config


def test_eight_golden_scenarios() -> None:
    assert len(config.SCENARIO_KEYS) == 8


def test_fp_control_and_canary_excluded_from_attack_scenarios() -> None:
    assert config.FP_CONTROL_SCENARIO not in config.ATTACK_SCENARIO_KEYS
    assert config.CANARY_SCENARIO not in config.ATTACK_SCENARIO_KEYS
    assert len(config.ATTACK_SCENARIO_KEYS) == 6


def test_correlation_scenarios_are_a_subset_of_all_scenarios() -> None:
    assert set(config.CORRELATION_SCENARIO_KEYS) <= set(config.SCENARIO_KEYS)
    assert len(config.CORRELATION_SCENARIO_KEYS) == 4


def test_gate_tolerances_match_docs12_verbatim() -> None:
    assert config.GATE_TOLERANCES == {
        "detection_f1_aggregate": -0.02,
        "incident_recall": -0.02,
        "disposition_accuracy": -0.05,
        "hallucination_rate": 0.01,
        "brier_score": 0.02,
    }


def test_three_distinct_seeds_for_golden_calibration_and_benign_pure() -> None:
    """Same discipline docs/11 requires between training/eval corpora: distinct seeds so a
    calibrator can never be fit on the exact data it is later measured against."""
    seeds = {config.EVAL_SEED, config.CALIBRATION_SEED, config.BENIGN_PURE_SEED}
    assert len(seeds) == 3


def test_eval_calibrators_dir_is_isolated_from_shared_production_dir() -> None:
    from app.detection.calibration import CALIBRATORS_DIR

    assert config.EVAL_CALIBRATORS_DIR != CALIBRATORS_DIR
