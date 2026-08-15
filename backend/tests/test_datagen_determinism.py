"""Adversarial reproducibility checks for `datagen` (docs/11).

The milestone's core claim is that everything is seeded and reproducible. This exercises that
claim through `datagen.corpus`'s own public API (no datagen source was modified to write this
test).

Two regression tests that used to live here (`test_run_demo_background_is_independent_of_other_
scenarios`, `test_run_demo_scenario_stream_is_independent_of_list_position`) proved a real
cross-source reproducibility hole in `datagen.corpus.run_demo`: adding an Okta-only scenario to
the demo cast perturbed the ZScaler benign background's own RNG draws, and removing an earlier
Okta-only scenario re-randomized a later, unrelated one. Both bugs were about *cross-source*
interaction specifically — one source's benign volume, and therefore its RNG draws, depending on
which other scenarios (touching a different source) happened to be in the cast. Okta was removed,
narrowing this project to ZScaler web proxy logs only, so there is no second source left for that
failure mode to occur between; the regression coverage went with it rather than being kept as a
now-untestable claim.
"""

from __future__ import annotations

import json
from pathlib import Path

from datagen import corpus

_ORG_SPEC = corpus.OrgSpec(n_users=25, n_departments=3, offices=("US-CA",), n_service_accounts=2)


def test_same_seed_same_command_is_byte_identical(tmp_path: Path) -> None:
    """Baseline sanity check: identical invocations must produce identical bytes."""
    out_a, out_b = tmp_path / "a", tmp_path / "b"
    written_a = corpus.run_scenario("c2_beaconing", 7, out_a, total_events=2000, org_spec=_ORG_SPEC)
    written_b = corpus.run_scenario("c2_beaconing", 7, out_b, total_events=2000, org_spec=_ORG_SPEC)
    log_a = next(p for p in written_a if p.suffix == ".log")
    log_b = next(p for p in written_b if p.suffix == ".log")
    assert log_a.read_bytes() == log_b.read_bytes()


def test_run_demo_scenario_stream_is_independent_of_list_position(tmp_path: Path) -> None:
    """Removing an earlier scenario from the demo cast must not re-randomize a later scenario's
    injected attack, even with only one source registered.

    `run_demo` derives both `scenario_id` and the scenario's entire RNG sub-stream from *how many
    times this key has appeared so far* (`key_counts`), not from position in the caller's
    `scenarios` list — this is the guarantee that survived the cross-source bug described in the
    module docstring; it was never source-specific.
    """
    out_x, out_y = tmp_path / "x", tmp_path / "y"

    written_x = corpus.run_demo(
        42,
        out_x,
        total_events=3000,
        scenarios=[("c2_beaconing", {}), ("data_exfiltration", {})],
        org_spec=_ORG_SPEC,
    )
    written_y = corpus.run_demo(
        42,
        out_y,
        total_events=3000,
        scenarios=[("data_exfiltration", {})],
        org_spec=_ORG_SPEC,
    )

    labels_x = next(p for p in written_x if p.suffix == ".json")
    labels_y = next(p for p in written_y if p.suffix == ".json")
    scenarios_x = json.loads(labels_x.read_text())["scenarios"]
    scenarios_y = json.loads(labels_y.read_text())["scenarios"]

    exfil_x = next(s for s in scenarios_x if s["scenario_id"].startswith("data_exfiltration"))
    exfil_y = next(s for s in scenarios_y if s["scenario_id"].startswith("data_exfiltration"))

    # Same seed, same org, same background, same knobs -- the only difference is whether an
    # unrelated scenario precedes this one in the list. The injected attack (victim, timing, line
    # numbers) must not change.
    assert exfil_x["notes"] == exfil_y["notes"], (
        "data_exfiltration's injected attack changed when an unrelated scenario "
        "was removed from an earlier position in the demo scenario list"
    )
