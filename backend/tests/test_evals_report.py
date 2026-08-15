"""Unit tests for `evals.report`'s markdown rendering — pure, no DB. The most important behavior
under test is `_legacy_appendix`: the historical L4 section (and everything else that predates
`evals/run.py`) must survive every regeneration, and the appendix must not grow across repeated
runs.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from evals import report
from evals.gate import GateCheck


def _minimal_render_kwargs() -> dict:
    detection_report = SimpleNamespace(
        per_scenario_detector=[],
        per_detector_aggregate={},
        per_layer_aggregate={},
        detection_f1_aggregate=0.42,
        fp_rate_scenario8={},
        fp_rate_benign_pure={},
        fp_rate_scenario8_total=0.0,
        fp_rate_benign_pure_total=0.0,
    )
    return {
        "git_sha": "deadbeef",
        "gate_passed": True,
        "gate_checks": [GateCheck("detection_f1_aggregate", 0.4, 0.42, -0.02, True, "ok")],
        "detection_report": detection_report,
        "correlation": {
            "incident_recall": 1.0,
            "fragmentation": 1.0,
            "per_scenario": [],
            "scenarios_missing": [],
        },
        "predictions": {},
        "l3_result": {
            "aggregate": {
                "ml.iforest": {
                    "mean_f1": 0.1,
                    "mean_auc_pr": 0.2,
                    "mean_recall": 0.1,
                    "mean_precision": 0.1,
                    "n_scenarios_detected": 1,
                    "n_scenarios": 6,
                }
            },
            "winner": "ml.iforest",
            "baseline": "ml.iforest",
            "per_scenario": [],
        },
        "calibration": {"brier_score": 0.05, "n_samples": 100, "n_positive": 10, "bins": []},
        "cost": {
            "pipeline_latency_p50_s": 1.0,
            "pipeline_latency_p95_s": 2.0,
            "pipeline_latency_per_scenario_s": {},
            "funnel": {
                "events": 100,
                "signals": 10,
                "incidents": 2,
                "triaged": None,
                "events_to_signals_reduction": 0.1,
                "signals_to_incidents_reduction": 0.2,
                "triaged_reduction": None,
            },
        },
        "agent": {"measured": False, "reason": "app/agent/ incomplete"},
        "injection_resistance": None,
        "injection_detail": "not measured",
        "sweep": None,
        "extra_weaknesses": [],
    }


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report, "RESULTS_MD_PATH", tmp_path / "results.md")


def test_render_produces_all_seven_docs12_sections() -> None:
    md = report.render(**_minimal_render_kwargs())
    for heading in (
        "## 1. Summary",
        "## 2. Model comparison",
        "## 3. Per-scenario detection breakdown",
        "## 4. Detection curve",
        "## 5. Calibration",
        "## 6. Cost and latency",
        "## 7. Known weaknesses",
    ):
        assert heading in md, f"missing section: {heading}"


def test_agent_not_measured_is_stated_plainly_not_hidden() -> None:
    md = report.render(**_minimal_render_kwargs())
    assert "Not measured" in md
    assert "app/agent/ incomplete" in md


def test_first_run_freezes_entire_existing_file_as_appendix() -> None:
    report.RESULTS_MD_PATH.write_text(
        "# Old Report\n\nsome historical content\n\n## L4 sequence models\n\nhistorical L4 text\n",
        encoding="utf-8",
    )
    md = report.render(**_minimal_render_kwargs())
    assert "historical L4 text" in md
    assert report._APPENDIX_MARKER in md


def test_appendix_does_not_grow_across_repeated_runs() -> None:
    report.RESULTS_MD_PATH.write_text(
        "# Old Report\n\n## L4 sequence models\n\nhistorical L4 text\n", encoding="utf-8"
    )
    first = report.render(**_minimal_render_kwargs())
    report.RESULTS_MD_PATH.write_text(first, encoding="utf-8")
    second = report.render(**_minimal_render_kwargs())
    # The appendix marker (and the frozen legacy text) appears exactly once even after two
    # regenerations -- not duplicated, not re-wrapped.
    assert second.count(report._APPENDIX_MARKER) == 1
    assert second.count("historical L4 text") == 1


def test_no_prior_file_omits_appendix() -> None:
    md = report.render(**_minimal_render_kwargs())
    assert report._APPENDIX_MARKER not in md
