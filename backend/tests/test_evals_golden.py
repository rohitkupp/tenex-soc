"""Tests for `evals.golden`'s generation orchestration. `test_generate_scenario_writes_real_files`
is the one real (slow-ish, ~1-2s) subprocess call in this file — everything else monkeypatches
`_run_datagen` to test the skip-if-already-populated logic without paying for a real generation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evals import golden


def test_generate_scenario_skips_if_already_populated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(golden, "_run_datagen", lambda args: calls.append(args))
    out_dir = tmp_path / "c2_beaconing"
    out_dir.mkdir()
    (out_dir / "scenario_c2_beaconing.log").write_text("already here", encoding="utf-8")

    golden.generate_scenario("c2_beaconing", seed=7, out_dir=out_dir, events=1000)

    assert calls == []


def test_generate_scenario_invokes_datagen_when_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(golden, "_run_datagen", lambda args: calls.append(args))
    out_dir = tmp_path / "c2_beaconing"

    golden.generate_scenario("c2_beaconing", seed=7, out_dir=out_dir, events=1000)

    assert len(calls) == 1
    args = calls[0]
    assert "scenario" in args
    assert "--name" in args and "c2_beaconing" in args
    assert "--seed" in args and "7" in args
    assert "--events" in args and "1000" in args


def test_ensure_golden_set_writes_nine_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(golden, "GOLDEN_DIR", tmp_path)
    calls: list[list[str]] = []
    monkeypatch.setattr(golden, "_run_datagen", lambda args: calls.append(args))

    written = golden.ensure_golden_set(seed=7, events=1000)

    assert len(written) == 8  # docs/11's eight scenarios
    # one "scenario" call per key, plus one "benign" call for the pure-benign FP corpus
    assert sum(1 for c in calls if c[0] == "scenario") == 8
    assert sum(1 for c in calls if c[0] == "benign") == 1


def test_generate_scenario_writes_real_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "c2_beaconing"
    golden.generate_scenario("c2_beaconing", seed=4242, out_dir=out_dir, events=2000)

    logs = list(out_dir.glob("*.log"))
    labels = list(out_dir.glob("*.labels.json"))
    assert len(logs) == 1
    assert len(labels) == 1

    import json

    payload = json.loads(labels[0].read_text(encoding="utf-8"))
    assert payload["seed"] == 4242
    assert payload["scenarios"][0]["technique"] == "T1071.001"
    assert payload["scenarios"][0]["malicious_line_numbers"]
