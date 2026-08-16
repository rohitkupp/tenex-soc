"""Unit tests for `app.detection.fusion` (docs/04 §Fusion, docs/05 "Incident scoring")."""

from __future__ import annotations

import math

import pytest

from app.detection.fusion import (
    FusionInput,
    apply_graph_bonus,
    fuse_signals,
    score_incident,
    severity_for_score,
)


def test_fuse_signals_empty_list_is_zero() -> None:
    assert fuse_signals([], []) == 0.0


def test_fuse_signals_single_signal_equals_weight_times_confidence() -> None:
    assert fuse_signals([0.8], [1.0]) == pytest.approx(0.8)
    assert fuse_signals([0.8], [0.5]) == pytest.approx(0.4)


def test_fuse_signals_matches_the_docs_formula() -> None:
    confidences = [0.9, 0.6, 0.3]
    weights = [1.0, 0.8, 1.2]
    expected = 1 - math.prod(1 - w * c for w, c in zip(weights, confidences, strict=True))
    assert fuse_signals(confidences, weights) == pytest.approx(expected)


def test_fuse_signals_is_monotonically_increasing_with_more_evidence() -> None:
    one = fuse_signals([0.5], [1.0])
    two = fuse_signals([0.5, 0.5], [1.0, 1.0])
    assert two > one


def test_fuse_signals_never_goes_negative_even_with_an_inflated_weight() -> None:
    """A `w*c` term is clamped to [0, 1] before multiplying -- an analyst-inflated weight above
    `1/c` must not push `1 - w*c` negative and make the fused score fall as evidence accumulates
    (see `fuse_signals`'s own docstring)."""
    base = fuse_signals([0.9], [1.0])
    with_extreme_weight = fuse_signals([0.9, 0.1], [1.0, 50.0])
    assert with_extreme_weight >= base
    assert 0.0 <= with_extreme_weight <= 1.0


def test_fuse_signals_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        fuse_signals([0.5, 0.5], [1.0])


def test_apply_graph_bonus_matches_docs_formula() -> None:
    base = 0.5
    n_layers = 3
    density = 0.6
    expected_bonus = 1 + 0.15 * math.log1p(n_layers) + 0.10 * min(density, 1.0)
    expected = min(base * expected_bonus, 0.99)
    assert apply_graph_bonus(
        base, n_distinct_detector_layers=n_layers, community_signal_density=density
    ) == pytest.approx(expected)


def test_apply_graph_bonus_caps_at_max_fused_score() -> None:
    result = apply_graph_bonus(0.95, n_distinct_detector_layers=10, community_signal_density=1.0)
    assert result <= 0.99


def test_apply_graph_bonus_zero_layers_still_applies_density_term() -> None:
    result = apply_graph_bonus(0.5, n_distinct_detector_layers=0, community_signal_density=1.0)
    assert result == pytest.approx(min(0.5 * 1.10, 0.99))


def test_severity_thresholds() -> None:
    assert severity_for_score(0.85) == "critical"
    assert severity_for_score(0.90) == "critical"
    assert severity_for_score(0.65) == "high"
    assert severity_for_score(0.84) == "high"
    assert severity_for_score(0.40) == "medium"
    assert severity_for_score(0.64) == "medium"
    assert severity_for_score(0.39) == "low"
    assert severity_for_score(0.0) == "low"


def test_score_incident_end_to_end() -> None:
    signals = [
        FusionInput(detector_key="signal.beaconing", detector_layer="signal", confidence=0.9),
        FusionInput(detector_key="sigma.large_post", detector_layer="rule", confidence=0.8),
        FusionInput(detector_key="ml.mahalanobis", detector_layer="ml", confidence=0.7),
    ]
    result = score_incident(signals, community_signal_density=0.5)
    assert result.n_distinct_detector_layers == 3
    expected_base = fuse_signals([0.9, 0.8, 0.7], [1.0, 1.0, 1.0])
    assert result.base_score == pytest.approx(expected_base)
    expected_fused = apply_graph_bonus(
        expected_base, n_distinct_detector_layers=3, community_signal_density=0.5
    )
    assert result.fused_score == pytest.approx(expected_fused)
    assert result.severity == severity_for_score(expected_fused)


def test_score_incident_graph_bonus_rewards_cross_layer_corroboration() -> None:
    """Two signals from the SAME layer should fuse to a lower score than two signals with
    identical confidence from DIFFERENT layers, once the graph bonus is applied -- this is the
    concrete behavior docs/05's `n_distinct_detector_layers` term is supposed to produce."""
    # Low enough confidences that neither case saturates the 0.99 fused-score cap -- otherwise
    # both would clip to the same value and the comparison below would be vacuous.
    same_layer = [
        FusionInput(detector_key="signal.beaconing", detector_layer="signal", confidence=0.4),
        FusionInput(detector_key="signal.dga", detector_layer="signal", confidence=0.4),
    ]
    diff_layer = [
        FusionInput(detector_key="signal.beaconing", detector_layer="signal", confidence=0.4),
        FusionInput(detector_key="ml.mahalanobis", detector_layer="ml", confidence=0.4),
    ]
    same_result = score_incident(same_layer, community_signal_density=0.5)
    diff_result = score_incident(diff_layer, community_signal_density=0.5)
    # base_score is identical (fusion doesn't know about layers); fused_score differs only
    # because of the graph bonus's layer-diversity term.
    assert same_result.base_score == pytest.approx(diff_result.base_score)
    assert diff_result.fused_score > same_result.fused_score
