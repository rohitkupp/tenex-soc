"""Adversarial reproducibility checks for `datagen` (docs/11).

The milestone's core claim is that everything is seeded and reproducible, and specifically that
adding or removing a scenario must not perturb the benign background stream. These tests exercise
that claim through `datagen.corpus`'s own public API (no datagen source was modified to write
these). At the time this file was written, `test_run_demo_background_is_independent_of_other_
scenarios` and `test_run_demo_scenario_stream_is_independent_of_list_position` FAIL, documenting
two real reproducibility holes in `datagen.corpus.run_demo` (see corpus.py `sources = sorted({...
for inst in instances ...})` and `scenario_rng = root.substream(f"scenario:{key}:{i}")`).
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


def test_run_demo_background_is_independent_of_other_scenarios(tmp_path: Path) -> None:
    """Adding a scenario that touches a new log source must not perturb an unrelated source's
    benign background (docs/11: benign corpus generation must be robust to which scenarios are
    injected).

    `run_demo` pools `sources = sorted({s for inst in instances for s in inst.sources})` across
    every scenario in the mix and renormalizes `_SOURCE_WEIGHTS` over whatever is "present"
    (`corpus.split_volume`). That makes one source's benign event *count* — and therefore every
    RNG draw consumed while generating it — depend on which other scenarios happen to be in the
    demo cast, even though those scenarios inject into a different source entirely.
    """
    out_only_zscaler, out_plus_okta = tmp_path / "only_zscaler", tmp_path / "plus_okta"

    written_a = corpus.run_demo(
        42,
        out_only_zscaler,
        total_events=3000,
        scenarios=[("c2_beaconing", {})],
        org_spec=_ORG_SPEC,
    )
    written_b = corpus.run_demo(
        42,
        out_plus_okta,
        total_events=3000,
        scenarios=[("c2_beaconing", {}), ("account_takeover_chain", {})],
        org_spec=_ORG_SPEC,
    )

    zscaler_a = next(p for p in written_a if p.name.endswith(".log"))
    zscaler_b = next(p for p in written_b if p.name.endswith("_zscaler.log"))

    lines_a = zscaler_a.read_text().splitlines()
    lines_b = zscaler_b.read_text().splitlines()

    # The zscaler benign backdrop (everything but the header) should be identical regardless of
    # whether an okta-only scenario also happens to be in the demo cast.
    assert lines_a[1:] == lines_b[1:], (
        "adding an okta-only scenario to the demo mix changed the zscaler benign background"
    )


def test_run_demo_scenario_stream_is_independent_of_list_position(tmp_path: Path) -> None:
    """Removing an earlier scenario from the demo cast must not re-randomize a later, unrelated
    scenario's injected attack.

    `run_demo` derives both `scenario_id` and the scenario's entire RNG sub-stream from its
    position in the caller's `scenarios` list (`inst.instance_id(i)` /
    `root.substream(f"scenario:{key}:{i}")`, `i` from `enumerate(..., start=1)`), not from a
    stable per-scenario key. Both scenarios below inject into OKTA only, so the shared background
    is identical in both runs; only list position differs.
    """
    out_x, out_y = tmp_path / "x", tmp_path / "y"

    written_x = corpus.run_demo(
        42,
        out_x,
        total_events=3000,
        scenarios=[("impossible_travel", {}), ("account_takeover_chain", {})],
        org_spec=_ORG_SPEC,
    )
    written_y = corpus.run_demo(
        42,
        out_y,
        total_events=3000,
        scenarios=[("account_takeover_chain", {})],
        org_spec=_ORG_SPEC,
    )

    labels_x = json.loads(next(p for p in written_x if p.suffix == ".json").read_text())
    labels_y = json.loads(next(p for p in written_y if p.suffix == ".json").read_text())

    ato_x = next(
        s for s in labels_x["scenarios"] if s["scenario_id"].startswith("account_takeover")
    )
    ato_y = next(
        s for s in labels_y["scenarios"] if s["scenario_id"].startswith("account_takeover")
    )

    # Same seed, same org, same background, same knobs -- the only difference is whether an
    # unrelated okta-only scenario precedes this one in the list. The injected attack (victim,
    # timing, line numbers) must not change.
    assert ato_x["notes"] == ato_y["notes"], (
        "account_takeover_chain's injected attack changed when an unrelated scenario "
        "was removed from an earlier position in the demo scenario list"
    )
