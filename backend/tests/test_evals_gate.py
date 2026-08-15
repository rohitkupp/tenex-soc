"""Unit tests for `evals.gate`'s regression-detection math (docs/12 "Regression gate") — pure,
no DB, no pipeline run. Monkeypatches `evals.gate.BASELINES_PATH`/`GATE_HISTORY_PATH` to a
`tmp_path` so these tests never touch the real committed `evals/baselines.json`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evals import gate


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "BASELINES_PATH", tmp_path / "baselines.json")
    monkeypatch.setattr(gate, "GATE_HISTORY_PATH", tmp_path / "gate_history.jsonl")


def test_no_baseline_always_passes() -> None:
    """First-ever run: nothing to regress against, every check passes."""
    _passed, checks = gate.evaluate_gate({"detection_f1_aggregate": 0.5})
    f1_check = next(c for c in checks if c.metric == "detection_f1_aggregate")
    assert f1_check.passed is True
    assert "no baseline" in f1_check.reason


def test_detection_f1_regression_beyond_tolerance_fails() -> None:
    gate.save_baselines({"detection_f1_aggregate": 0.50})
    passed, checks = gate.evaluate_gate({"detection_f1_aggregate": 0.47})  # -0.03, tolerance -0.02
    f1_check = next(c for c in checks if c.metric == "detection_f1_aggregate")
    assert f1_check.passed is False
    assert passed is False


def test_detection_f1_within_tolerance_passes() -> None:
    gate.save_baselines({"detection_f1_aggregate": 0.50})
    _passed, checks = gate.evaluate_gate({"detection_f1_aggregate": 0.49})  # -0.01, within -0.02
    f1_check = next(c for c in checks if c.metric == "detection_f1_aggregate")
    assert f1_check.passed is True


def test_hallucination_rate_rise_beyond_tolerance_fails() -> None:
    """A *rise* is bad for hallucination_rate — the opposite sign convention from F1/recall."""
    gate.save_baselines({"hallucination_rate": 0.02})
    _passed, checks = gate.evaluate_gate({"hallucination_rate": 0.05})  # +0.03, tolerance +0.01
    check = next(c for c in checks if c.metric == "hallucination_rate")
    assert check.passed is False


def test_brier_score_improvement_always_passes() -> None:
    """A brier score *drop* (better calibration) never fails the gate, however large."""
    gate.save_baselines({"brier_score": 0.20})
    _passed, checks = gate.evaluate_gate({"brier_score": 0.01})
    check = next(c for c in checks if c.metric == "brier_score")
    assert check.passed is True


def test_agent_dependent_metric_not_measured_does_not_fail_gate() -> None:
    """disposition_accuracy/hallucination_rate missing (app/agent/ incomplete) must not fail the
    overall gate — that is a disclosed, expected state per this milestone's brief, not a
    regression."""
    gate.save_baselines({"disposition_accuracy": 0.9, "hallucination_rate": 0.0})
    _passed, checks = gate.evaluate_gate(
        {"detection_f1_aggregate": None, "disposition_accuracy": None, "hallucination_rate": None}
    )
    disp_check = next(c for c in checks if c.metric == "disposition_accuracy")
    hall_check = next(c for c in checks if c.metric == "hallucination_rate")
    assert disp_check.passed is True
    assert hall_check.passed is True
    # detection_f1_aggregate is NOT agent-dependent -- a None there is a real harness bug and
    # must fail (no baseline recorded in this test, so it passes for a *different* reason —
    # covered by test_no_baseline_always_passes above).


def test_non_agent_metric_missing_when_baseline_exists_fails() -> None:
    """A metric this harness fully owns (detection_f1_aggregate) coming back `None` when a
    baseline already exists is a bug in the harness itself, and must fail the gate."""
    gate.save_baselines({"detection_f1_aggregate": 0.5})
    _passed, checks = gate.evaluate_gate({"detection_f1_aggregate": None})
    check = next(c for c in checks if c.metric == "detection_f1_aggregate")
    assert check.passed is False


def test_injection_resistance_below_one_fails() -> None:
    passed, checks = gate.evaluate_gate({"injection_resistance": 0.9})
    check = next(c for c in checks if c.metric == "injection_resistance")
    assert check.passed is False
    assert passed is False


def test_injection_resistance_exactly_one_passes() -> None:
    _passed, checks = gate.evaluate_gate({"injection_resistance": 1.0})
    check = next(c for c in checks if c.metric == "injection_resistance")
    assert check.passed is True


def test_injection_resistance_not_measured_does_not_fail_gate() -> None:
    _passed, checks = gate.evaluate_gate({"injection_resistance": None})
    check = next(c for c in checks if c.metric == "injection_resistance")
    assert check.passed is True
    assert "not measured" in check.reason


def test_record_history_appends_jsonl() -> None:
    _passed, checks = gate.evaluate_gate({"detection_f1_aggregate": 0.5})
    gate.record_history(passed=True, checks=checks, notes="test run 1")
    gate.record_history(passed=False, checks=checks, notes="test run 2")
    lines = gate.GATE_HISTORY_PATH.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_save_and_load_baselines_roundtrip() -> None:
    gate.save_baselines({"detection_f1_aggregate": 0.42, "incident_recall": 0.95})
    loaded = gate.load_baselines()
    assert loaded["metrics"]["detection_f1_aggregate"] == 0.42
    assert loaded["metrics"]["incident_recall"] == 0.95
    assert "git_sha" in loaded
    assert "recorded_at" in loaded
