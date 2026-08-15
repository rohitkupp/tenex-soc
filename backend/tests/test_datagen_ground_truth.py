"""Adversarial ground-truth verification for `datagen` eval scenarios (docs/11 "Ground truth
format", docs/12's whole premise: every metric is computed against `malicious_line_numbers`).

These tests run the real scenario/corpus generators (no datagen source modified to write them)
and cross-check the emitted `.labels.json` against the emitted log content by an independent
signal a scenario itself reports in its own ground-truth notes (a DGA/NRD domain, a hostile
`src_ip`) rather than by trusting `finalize_ground_truth`'s own bookkeeping. A generator that
mislabels its own output would still pass a test that only re-derives the answer from the same
code path; grepping the physical file for a fact the scenario asserts about itself is what makes
this an independent check.

`test_low_and_slow_exfil_notes_overclaim_working_hours` is expected to fail at the time this file
was written. It documents a real defect: scenario 4's ground-truth notes assert "every upload
inside the victim's own working hours" and "no single feature out of range", but
`RealismModels.diurnal.sample_timestamps` draws from a curve with a non-zero night floor
(`DiurnalCurve.night_floor = 0.03`), so some fraction of a real run's timestamps genuinely fall in
nocturnal, off-hours territory. At seed 7 / the default 250-user org, 3 of the 30 injected uploads
land at diurnal weight <= 0.03 (curve.weight ~ night floor), including local timestamps of 01:37
and 00:42 -- not "working hours" under any definition. This does not corrupt
`malicious_line_numbers` (still exactly correct), but the notes field overclaims a guarantee the
code does not enforce, and it partly undermines the scenario's own stated design goal that no
single feature (here, off-hours ratio) should be out of range for this campaign.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from datagen import corpus
from datagen.scenarios import scenario_keys
from datagen.types import DETECTOR_KEYS

# Small-ish org so the whole scenario sweep still runs in well under a second per scenario for
# most scenarios; none of the *structural* checks below depend on organization size as such.
# Sized larger than the original 30-user/4-department/4000-event config specifically for
# scenarios 5 and 6 (`s05_peer_group_deviation.py`, `s06_seasonal_deviation.py`): both resample
# against population statistics (org-wide/cohort feature populations for 5, the victim's own
# daily-history and hourly-residual populations for 6) that are too noisy to satisfy their
# acceptance gates reliably below roughly this scale (verified empirically -- the original
# 30-user config left scenario 5's home-department cohort as thin as 3 Marketing members, and
# scenario 6's daily-volume/off-hours-share baselines need several pre-campaign days of a single
# human's own history, which a very small event budget does not supply). 120 users / 6
# departments / 18000 events reproducibly clears both scenarios' gates at `seed=7` (this file's
# default) while still finishing in well under a second per scenario.
_ORG_SPEC = corpus.OrgSpec(n_users=120, n_departments=6, offices=("US-CA", "US-NY", "IE-DU"))
_DEFAULT_TOTAL_EVENTS = 18_000


def _write(
    key: str, out: Path, *, seed: int = 7, total_events: int = _DEFAULT_TOTAL_EVENTS
) -> list[Path]:
    return corpus.run_scenario(key, seed, out, total_events=total_events, org_spec=_ORG_SPEC)


# ---------------------------------------------------------------------------- structural invariants


def test_ground_truth_is_structurally_well_formed_for_every_scenario(tmp_path: Path) -> None:
    """Sorted, unique, in-bounds line numbers and only known detector keys, for all ten scenarios.

    A typo'd detector key silently zeroes out that detector's recall in the eval harness (it would
    never match a real `signals.detector_key`), and an out-of-bounds or unsorted line number is
    exactly the off-by-one docs/11 flags as the thing that "silently corrupts every
    precision/recall number" -- both fail loudly here instead.
    """
    for key in scenario_keys():
        written = _write(key, tmp_path / key)
        for labels_path in (p for p in written if p.suffix == ".json"):
            labels = json.loads(labels_path.read_text())
            log_path = labels_path.with_name(labels["log_file"])
            n_physical_lines = len(log_path.read_text().splitlines())
            assert n_physical_lines == labels["total_lines"], (
                f"{key}/{labels_path.name}: total_lines={labels['total_lines']} but file has "
                f"{n_physical_lines} lines"
            )
            for scenario in labels["scenarios"]:
                mln = scenario["malicious_line_numbers"]
                assert mln == sorted(mln), f"{key}: malicious_line_numbers not sorted: {mln}"
                assert len(set(mln)) == len(mln), f"{key}: duplicate line numbers: {mln}"
                if mln:
                    assert mln[0] >= 1, f"{key}: line number below 1: {mln[0]}"
                    assert mln[-1] <= labels["total_lines"], (
                        f"{key}: line number {mln[-1]} exceeds total_lines={labels['total_lines']}"
                    )
                unknown = [d for d in scenario["expected_detectors"] if d not in DETECTOR_KEYS]
                assert not unknown, f"{key}: expected_detectors has unknown keys: {unknown}"


# ---------------------------------------------------------------------------- content cross-checks
# For scenarios whose injected traffic carries a unique string (a generated DGA/NRD domain, a
# hostile IP), independently re-derive which physical lines contain it and diff against
# `malicious_line_numbers`. This is the check that would catch a real off-by-one: if the driver's
# line-numbering start offset were wrong for one source, this diff would be non-empty rather than
# merely "the code agrees with itself".


def _malicious_lines_containing(log_path: Path, needle: str) -> set[int]:
    return {
        i for i, line in enumerate(log_path.read_text().splitlines(), start=1) if needle in line
    }


def test_c2_beaconing_line_numbers_match_the_domain_the_scenario_reports(tmp_path: Path) -> None:
    written = _write("c2_beaconing", tmp_path)
    labels_path = next(p for p in written if p.suffix == ".json")
    log_path = next(p for p in written if p.suffix == ".log")
    labels = json.loads(labels_path.read_text())
    scenario = labels["scenarios"][0]

    # The DGA domain is embedded in `notes` as "... jitter, Xh duration, dga domain <host>; ...".
    notes = scenario["notes"]
    marker = "domain "
    start = notes.index(marker) + len(marker)
    host = notes[start:].split()[0].rstrip(";")

    found = _malicious_lines_containing(log_path, host)
    assert found == set(scenario["malicious_line_numbers"]), (
        "lines containing the scenario's own reported C2 domain do not match "
        "malicious_line_numbers exactly"
    )
    assert len(found) > 0, "sanity: the domain must appear somewhere in the file"


# `test_impossible_travel_hostile_ip_only_appears_on_labelled_lines` and `test_password_spray_
# primary_entity_ip_matches_both_source_files` used to live here. Both scenarios were Okta-only
# (password_spray was also the cross-source scenario, joining Okta and ZScaler on a shared
# src_ip) and were deleted along with that source -- this project is narrowed to ZScaler web
# proxy logs only.


# ---------------------------------------------------------------------------- the two controls


def test_benign_but_weird_is_the_false_positive_control(tmp_path: Path) -> None:
    """docs/11 scenario 8: must not fire. Empty labels, empty detectors, disposition
    false_positive, and explicitly not required to correlate into one incident."""
    written = _write("benign_but_weird", tmp_path)
    labels_paths = [p for p in written if p.suffix == ".json"]
    assert len(labels_paths) == 1, "benign_but_weird is ZScaler-only now that Okta is removed"
    for labels_path in labels_paths:
        labels = json.loads(labels_path.read_text())
        scenario = labels["scenarios"][0]
        assert scenario["malicious_line_numbers"] == []
        assert scenario["expected_detectors"] == []
        assert scenario["expected_disposition"] == "false_positive"
        assert scenario["must_correlate_into_one_incident"] is False


def test_prompt_injection_canary_and_control_differ_only_in_the_three_carrier_fields(
    tmp_path: Path,
) -> None:
    """docs/11 scenario 7's entire premise: the injected payload changes nothing except the three
    attacker-controlled string fields. If line numbers, hosts, or any other column drifted between
    `canary=True` and `canary=False`, the eval's injection_resistance gate (docs/12) would be
    comparing two different attacks rather than one attack with/without a payload."""
    canary = _write("prompt_injection_canary", tmp_path / "canary")
    control = corpus.run_scenario(
        "prompt_injection_canary",
        7,
        tmp_path / "control",
        total_events=_DEFAULT_TOTAL_EVENTS,
        org_spec=_ORG_SPEC,
        knobs={"canary": False},
    )

    canary_labels = json.loads(next(p for p in canary if p.suffix == ".json").read_text())
    control_labels = json.loads(next(p for p in control if p.suffix == ".json").read_text())
    canary_mln = canary_labels["scenarios"][0]["malicious_line_numbers"]
    control_mln = control_labels["scenarios"][0]["malicious_line_numbers"]
    assert canary_mln == control_mln, "canary/control must inject on identical line numbers"

    canary_lines = next(p for p in canary if p.suffix == ".log").read_text().splitlines()
    control_lines = next(p for p in control if p.suffix == ".log").read_text().splitlines()
    assert len(canary_lines) == len(control_lines)

    differing = [i for i in range(len(canary_lines)) if canary_lines[i] != control_lines[i]]
    # 0-indexed list positions vs 1-indexed line numbers.
    assert {i + 1 for i in differing} == set(canary_mln), (
        "canary and control differ on lines outside malicious_line_numbers, or agree on a "
        "line that should carry the payload"
    )


# ---------------------------------------------------------------------------- known defect


def test_low_and_slow_exfil_notes_overclaim_working_hours(tmp_path: Path) -> None:
    """Documents a real defect (see module docstring): scenario 4's ground-truth notes assert
    every injected upload lands inside the victim's own working hours. `DiurnalCurve` has a
    non-zero `night_floor`, so `diurnal.sample_timestamps` can and does draw genuinely nocturnal
    timestamps. This test uses the *default* 250-user org and seed 7 (matching the exact
    reproduction used in the manual audit), because the phenomenon is a property of the specific
    seeded run, not of every possible run.
    """
    written = corpus.run_scenario(
        "low_and_slow_exfil", 7, tmp_path, total_events=50_000, org_spec=corpus.OrgSpec()
    )
    labels_path = next(p for p in written if p.suffix == ".json")
    log_path = next(p for p in written if p.suffix == ".log")
    labels = json.loads(labels_path.read_text())
    scenario = labels["scenarios"][0]
    victim = scenario["primary_entity"]["value"].split("@")[0]

    org = corpus.build_org(7, corpus.ROLE_EVAL)
    user = next(u for u in org.users if u.username == victim)
    hours = user.work_hours
    curve = org.models.diurnal

    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx_dt = header.index("datetime")

    weights = []
    for ln in scenario["malicious_line_numbers"]:
        raw_ts = lines[ln - 1].split("\t")[idx_dt]
        ts = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        weights.append(curve.weight(ts, hours))

    night_floor_events = [w for w in weights if w <= 0.05]

    assert not night_floor_events, (
        "scenario 4's notes claim 'every upload inside the victim's own working hours', but "
        f"{len(night_floor_events)}/{len(weights)} injected uploads landed at diurnal weight "
        f"<= 0.05 (essentially the night floor): {night_floor_events}. The notes field overclaims "
        "a guarantee the diurnal sampler does not enforce."
    )
