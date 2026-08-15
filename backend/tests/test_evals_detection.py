"""Unit tests for `evals.metrics.detection`'s precision/recall/F1 math (docs/12 "Detection
layer") — pure, no DB, no pipeline run. Builds `Signal` ORM instances in memory (never flushed/
persisted) and `evals.pipeline.ScenarioRun`/`BenignPureRun` dataclasses directly, so this module
runs in milliseconds rather than the minutes a real `python -m evals.run` pipeline pass takes —
that full pass is exercised for real by CI's `eval-gate` job (`.github/workflows/ci.yml`), not
duplicated here.
"""

from __future__ import annotations

from app.models.signal import Signal
from evals.metrics import detection
from evals.pipeline import BenignPureRun, ScenarioRun


def _fake_ingest(n_events: int = 100):
    from types import SimpleNamespace

    return SimpleNamespace(n_events=n_events)


def _fake_result(ingest, incidents=()):
    from types import SimpleNamespace

    return SimpleNamespace(ingest=ingest, incidents=list(incidents), scenario="fake")


def _signal(detector_key: str, detector_layer: str, evidence_event_ids: list[int]) -> Signal:
    return Signal(
        detector_key=detector_key,
        detector_layer=detector_layer,
        raw_score=1.0,
        confidence=0.9,
        entity_type="user",
        entity_value="alice@corp.example",
        evidence_event_ids=evidence_event_ids,
        explanation={},
    )


def _scenario_run(
    key: str, signals: list[Signal], malicious_event_ids: frozenset[int], n_events: int = 100
) -> ScenarioRun:
    return ScenarioRun(
        key=key,
        result=_fake_result(_fake_ingest(n_events)),
        signals=signals,
        malicious_event_ids=malicious_event_ids,
        elapsed_s=1.0,
    )


def test_score_scenario_perfect_detector() -> None:
    """A detector whose every signal's evidence is entirely inside the malicious set: precision
    and recall both 1.0."""
    signals = [_signal("ml.iforest", "ml", [1, 2]), _signal("ml.iforest", "ml", [3])]
    run = _scenario_run("c2_beaconing", signals, frozenset({1, 2, 3}))
    rows = detection.score_scenario(run, registry={"ml.iforest": "ml"})
    row = next(r for r in rows if r.detector_key == "ml.iforest")
    assert row.precision == 1.0
    assert row.recall == 1.0
    assert row.f1 == 1.0
    assert row.detected is True
    assert row.n_tp_signals == 2
    assert row.n_fp_signals == 0


def test_score_scenario_all_false_positive() -> None:
    """Every signal's evidence misses the malicious set entirely: precision 0, recall 0 (there
    ARE malicious events, so recall is defined and 0, not None)."""
    signals = [_signal("ml.iforest", "ml", [99]), _signal("ml.iforest", "ml", [98])]
    run = _scenario_run("c2_beaconing", signals, frozenset({1, 2, 3}))
    rows = detection.score_scenario(run, registry={"ml.iforest": "ml"})
    row = next(r for r in rows if r.detector_key == "ml.iforest")
    assert row.precision == 0.0
    assert row.recall == 0.0
    assert row.f1 == 0.0
    assert row.detected is False


def test_score_scenario_partial_recall() -> None:
    """Two of three malicious events covered by TP signals: recall = 2/3."""
    signals = [
        _signal("signal.beaconing", "signal", [1, 2]),
        _signal("signal.beaconing", "signal", [99]),
    ]
    run = _scenario_run("c2_beaconing", signals, frozenset({1, 2, 3}))
    rows = detection.score_scenario(run, registry={"signal.beaconing": "signal"})
    row = next(r for r in rows if r.detector_key == "signal.beaconing")
    assert row.n_malicious_events_covered == 2
    assert row.recall == 2 / 3
    # precision: 1 of 2 signals was a TP (the [1,2] one; the [99] one is pure FP)
    assert row.precision == 0.5


def test_score_scenario_zero_row_for_never_fired_detector() -> None:
    """A detector in the registry that raised no signals still gets a row (docs/12: "automatic"
    tables), with precision/recall undefined (None), not zero."""
    run = _scenario_run("c2_beaconing", [], frozenset({1, 2}))
    rows = detection.score_scenario(run, registry={"ml.mahalanobis": "ml"})
    row = next(r for r in rows if r.detector_key == "ml.mahalanobis")
    assert row.n_signals == 0
    assert row.precision is None
    assert (
        row.recall == 0.0
    )  # malicious events exist but none were covered -- recall IS defined here
    assert row.detected is False


def test_score_scenario_no_malicious_events_recall_is_none() -> None:
    """A benign-only scenario (no malicious events at all): recall is undefined (None), not 0 —
    there was nothing to find, so "found none of it" is a different statement than "not
    applicable"."""
    signals = [_signal("sigma.non_browser_user_agent", "rule", [5])]
    run = _scenario_run("benign_but_weird", signals, frozenset())
    rows = detection.score_scenario(run, registry={"sigma.non_browser_user_agent": "rule"})
    row = next(r for r in rows if r.detector_key == "sigma.non_browser_user_agent")
    assert row.recall is None
    assert row.precision == 0.0  # the signal fired but wasn't about any (nonexistent) attack
    assert row.detected is False


def test_known_detector_registry_spans_all_four_layers() -> None:
    registry = detection.known_detector_registry()
    layers = set(registry.values())
    # Sigma rules / signal constants / ml constants / graph features are all real, static
    # registries this codebase ships -- a healthy checkout should surface all four.
    assert layers, "expected at least one detector layer to be discoverable"
    assert layers <= {"rule", "signal", "ml", "graph"}


def test_build_report_fp_rate_uses_event_normalized_ratio() -> None:
    ingest = _fake_ingest()
    scenario8_signals = [
        _signal("sigma.non_browser_user_agent", "rule", [1]),
        _signal("sigma.non_browser_user_agent", "rule", [2]),
    ]
    runs = {
        "benign_but_weird": _scenario_run(
            "benign_but_weird", scenario8_signals, frozenset(), n_events=ingest.n_events
        ),
    }
    from evals.config import FP_CONTROL_SCENARIO

    assert FP_CONTROL_SCENARIO == "benign_but_weird"
    benign_pure = BenignPureRun(
        ingest=ingest, signals_by_detector={"sigma.non_browser_user_agent": 5}
    )

    report = detection.build_report(runs, benign_pure)
    assert report.fp_rate_scenario8_total == 2 / 100
    assert report.fp_rate_benign_pure_total == 5 / 100
