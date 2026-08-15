"""Regression tests for scenario 6's docs/11 row 6 acceptance gate
(`datagen/scenarios/s06_seasonal_deviation.py`).

Independent audit, in the same spirit as `test_datagen_s04_marginals.py` and
`test_datagen_s05_peer_group.py`: re-derives every feature straight from the *emitted* TSV and
`malicious_line_numbers`, and does not import `s06_seasonal_deviation`'s own daily-bucketing,
two-proportion-z, or residual-decomposition helpers. A bug in the generator's in-memory gate would
not be self-confirming here.

What *is* shared with the scenario under audit: `app.detection.features.is_off_hours`/`robust_z`
(the two canonical docs/04 primitives).
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

from app.detection.features import is_off_hours, robust_z
from datagen import corpus
from datagen.scenarios.s06_seasonal_deviation import SeasonalDeviationScenario
from datagen.types import TimeWindow

_TOTAL_EVENTS = 50_000
_ORG_SPEC = corpus.OrgSpec()

_ACCEPT_DAILY_Z_THRESHOLD = 3.5
_ACCEPT_SHARE_Z_MIN = 4.0
_ACCEPT_RESIDUAL_MIN_SEPARATION = 0.70

# A representative handful of seeds, not an exhaustive sweep -- see the same note in
# `test_datagen_s05_peer_group.py` / `test_datagen_s04_marginals.py`.
_S06_SEEDS = (3, 17, 33, 55, 77)

# The scenario's default knobs, used to reconstruct the *exact* campaign window boundary
# independently rather than approximate it from the earliest malicious timestamp (which can sit
# hours after the true `campaign.start`, since the first campaign day's session lands at a random
# hour within that day -- verified against real generated output: at that approximation, the
# residual-separation audit below landed right on the 70% boundary, sometimes a single hour under
# it, purely from a handful of hours drifting across the pre/post split). Hardcoded here rather
# than imported from the scenario, per this file's independence discipline; guarded by
# `test_default_knobs_match_the_scenario_under_audit` so the two cannot silently drift.
_PRE_CAMPAIGN_DAYS = 7.0
_CAMPAIGN_DAYS = 6.5
_START_FRACTION = 0.5


def _default_campaign_window() -> TimeWindow:
    window = TimeWindow.of_days(corpus.DEFAULT_WINDOW_DAYS)
    return window.subwindow(start_fraction=_START_FRACTION, hours=_CAMPAIGN_DAYS * 24.0)


def test_default_knobs_match_the_scenario_under_audit() -> None:
    """Guards this file's independence claim (module docstring): if
    `s06_seasonal_deviation.py`'s own default knobs ever change, this file must be updated
    deliberately, not silently start auditing against the wrong window."""
    defaults = SeasonalDeviationScenario()
    assert defaults.pre_campaign_days == _PRE_CAMPAIGN_DAYS
    assert defaults.campaign_days == _CAMPAIGN_DAYS
    assert defaults.start_fraction == _START_FRACTION


def _generate(seed: int, tmp_path: Path) -> Path:
    written = corpus.run_scenario(
        "seasonal_deviation", seed, tmp_path, total_events=_TOTAL_EVENTS, org_spec=_ORG_SPEC
    )
    return next(p for p in written if p.suffix == ".log")


def _load(log_path: Path) -> tuple[dict, list[list[str]], dict[str, int], set[int]]:
    labels_path = log_path.with_name(f"{log_path.stem}.labels.json")
    labels = json.loads(labels_path.read_text())
    scenario = labels["scenarios"][0]
    malicious = set(scenario["malicious_line_numbers"])

    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {name: i for i, name in enumerate(header)}
    rows = [line.split("\t") for line in lines[1:]]
    return scenario, rows, idx, malicious


def _is_weekend(ts: datetime, tz_offset_h: float) -> bool:
    return (ts + timedelta(hours=tz_offset_h)).weekday() >= 5


def _local_date(ts: datetime, tz_offset_h: float):
    return (ts + timedelta(hours=tz_offset_h)).date()


def _parse_ts(p: list[str], idx: dict[str, int]) -> datetime:
    return datetime.strptime(p[idx["datetime"]], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _off_share(
    rows_: list[tuple[int, list[str]]], idx: dict[str, int], hours, tz: float
) -> tuple[int, int]:
    n = len(rows_)
    off = sum(
        1
        for _i, p in rows_
        if is_off_hours(_parse_ts(p, idx), hours) or _is_weekend(_parse_ts(p, idx), tz)
    )
    return off, n


def test_s06_daily_volume_normal_but_off_hours_weekend_share_far_outside_baseline(
    tmp_path: Path,
) -> None:
    """docs/11 row 6 / docs/12 prediction 3, re-measured independently from the emitted file:
    the victim's own campaign-period daily totals stay inside their own pre-campaign robust-z
    range, but the pooled off-hours-or-weekend share moves far outside the pre-campaign baseline
    (two-proportion z-test)."""
    for seed in _S06_SEEDS:
        log_path = _generate(seed, tmp_path / f"s06-{seed}")
        scenario, rows, idx, malicious = _load(log_path)
        victim = scenario["primary_entity"]["value"]

        org = corpus.build_org(seed, corpus.ROLE_EVAL, _ORG_SPEC)
        user = org.get(victim)
        hours, tz = user.work_hours, user.tz_offset_h

        victim_rows = [(i, p) for i, p in enumerate(rows, start=2) if p[idx["user"]] == victim]
        assert victim_rows, f"seed={seed}: no rows found for victim {victim}"
        attack_ts = [_parse_ts(p, idx) for i, p in victim_rows if i in malicious]
        assert attack_ts, f"seed={seed}: no malicious rows for victim {victim}"

        # Split the same way the scenario itself does (`natural` vs `[*campaign_natural,
        # *injected]`), not purely by comparing timestamps to `campaign.start`: a handful of
        # off-hours sessions on the campaign's first local calendar day can carry a UTC
        # timestamp technically *before* `campaign.start` when `tz_offset_h` is negative (that
        # local day's own midnight precedes the UTC campaign boundary) -- clamped to the overall
        # window, not to the campaign window specifically. Splitting purely on timestamp would
        # count those malicious events as "pre-campaign natural" baseline, contaminating the
        # population; verified against real generated output while writing this test (seed=3
        # showed exactly this, inflating an unrelated day's z-score from 2.19 to 3.51 because the
        # contaminating value happened to sit close to the true median and shrank the MAD).
        campaign = _default_campaign_window()
        pre_rows = [
            (i, p)
            for i, p in victim_rows
            if i not in malicious and _parse_ts(p, idx) < campaign.start
        ]
        post_rows = [
            (i, p)
            for i, p in victim_rows
            if i in malicious or (campaign.start <= _parse_ts(p, idx) < campaign.end)
        ]
        assert len(pre_rows) >= 20, f"seed={seed}: too little pre-campaign history to audit"

        # (a) daily volume: campaign-period days stay within the victim's own pre-campaign range.
        pre_daily: dict = {}
        for _i, p in pre_rows:
            d = _local_date(_parse_ts(p, idx), tz)
            pre_daily[d] = pre_daily.get(d, 0) + 1
        post_daily: dict = {}
        for _i, p in post_rows:
            d = _local_date(_parse_ts(p, idx), tz)
            post_daily[d] = post_daily.get(d, 0) + 1

        pre_counts = list(pre_daily.values())
        offenders = [
            f"{d.isoformat()} (z={z:.2f})"
            for d, count in post_daily.items()
            if abs(z := robust_z(pre_counts, float(count))) > _ACCEPT_DAILY_Z_THRESHOLD
        ]
        assert not offenders, f"seed={seed} victim={victim}: daily volume out of range: {offenders}"

        # (b) off-hours/weekend share: two-proportion z-test, pooled over each period.
        pre_off, pre_n = _off_share(pre_rows, idx, hours, tz)
        post_off, post_n = _off_share(post_rows, idx, hours, tz)
        p_pre, p_post = pre_off / pre_n, post_off / post_n
        p_pool = (pre_off + post_off) / (pre_n + post_n)
        se = math.sqrt(p_pool * (1.0 - p_pool) * (1.0 / pre_n + 1.0 / post_n))
        share_z = (p_post - p_pre) / se if se > 0 else math.inf

        assert share_z >= _ACCEPT_SHARE_Z_MIN, (
            f"seed={seed} victim={victim}: off-hours/weekend share z={share_z:.2f} below "
            f"{_ACCEPT_SHARE_Z_MIN} (pre={p_pre:.1%}, post={p_post:.1%})"
        )
        assert p_post > p_pre, "campaign period share must exceed the pre-campaign baseline"


def test_s06_residual_decomposition_separates_touched_hours(tmp_path: Path) -> None:
    """The positive-proof criterion (c): an independently-computed trend/seasonal/residual
    decomposition (24h moving-average trend, hour-of-day seasonal fit on pre-campaign data only)
    scores the specific hours the campaign touched as residual outliers against the victim's own
    pre-campaign residual distribution."""
    for seed in _S06_SEEDS[:3]:
        log_path = _generate(seed, tmp_path / f"s06-resid-{seed}")
        scenario, rows, idx, malicious = _load(log_path)
        victim = scenario["primary_entity"]["value"]

        victim_rows = [(i, p) for i, p in enumerate(rows, start=2) if p[idx["user"]] == victim]

        all_ts = [_parse_ts(p, idx) for _i, p in victim_rows]
        attack_hours = {
            _parse_ts(p, idx).replace(minute=0, second=0, microsecond=0)
            for i, p in victim_rows
            if i in malicious
        }
        # The exact window boundary (module docstring), not an approximation from the earliest
        # malicious timestamp -- that approximation lands hours late (the first campaign day's
        # session can fall anywhere in that day) and was enough to flip a borderline hour across
        # the pre/post split, verified against real generated output.
        campaign_start = _default_campaign_window().start

        start = min(all_ts).replace(minute=0, second=0, microsecond=0)
        end = max(all_ts).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        hourly: dict[datetime, int] = {}
        ts = start
        while ts < end:
            hourly[ts] = 0
            ts += timedelta(hours=1)
        for t in all_ts:
            hourly[t.replace(minute=0, second=0, microsecond=0)] += 1

        hours_sorted = sorted(hourly)
        counts = np.array([hourly[h] for h in hours_sorted], dtype=np.float64)
        n = counts.size
        half = 12
        cumsum = np.concatenate(([0.0], np.cumsum(counts)))
        trend = np.array(
            [
                (cumsum[min(n, i + half + 1)] - cumsum[max(0, i - half)])
                / (min(n, i + half + 1) - max(0, i - half))
                for i in range(n)
            ]
        )
        detrended = counts - trend
        # Excludes touched hours from "pre" regardless of their exact chronological position, for
        # the same reason `pre_rows` in the daily-volume test above excludes malicious rows
        # outright rather than splitting purely on `campaign.start`: a touched hour's timestamp
        # can technically precede `campaign.start` (module docstring of the previous test) and
        # must never contaminate the seasonal-fit / p95 baseline population.
        pre_mask = np.array([h < campaign_start and h not in attack_hours for h in hours_sorted])
        seasonal_by_phase = {
            phase: float(
                np.median(detrended[pre_mask & np.array([h.hour == phase for h in hours_sorted])])
            )
            if np.any(pre_mask & np.array([h.hour == phase for h in hours_sorted]))
            else 0.0
            for phase in range(24)
        }
        seasonal = np.array([seasonal_by_phase[h.hour] for h in hours_sorted])
        residual = detrended - seasonal

        pre_residual = residual[pre_mask]
        assert pre_residual.size >= 100, f"seed={seed}: too little pre-campaign hourly history"
        p95 = float(np.percentile(pre_residual, 95))

        index_by_hour = {h: i for i, h in enumerate(hours_sorted)}
        touched = [index_by_hour[h] for h in attack_hours if h in index_by_hour]
        assert touched, f"seed={seed}: no touched hours resolved"
        separation = sum(1 for i in touched if residual[i] > p95) / len(touched)

        assert separation >= _ACCEPT_RESIDUAL_MIN_SEPARATION, (
            f"seed={seed} victim={victim}: residual separation {separation:.0%} below "
            f"{_ACCEPT_RESIDUAL_MIN_SEPARATION:.0%} (p95={p95:.2f})"
        )


def test_s06_ground_truth_verified_against_emitted_lines(tmp_path: Path) -> None:
    """Sanity check in the `test_datagen_ground_truth.py` spirit: every malicious line is the
    victim's own principal, and every malicious line is genuinely off-hours or weekend for that
    victim's own work hours."""
    log_path = _generate(_S06_SEEDS[0], tmp_path)
    scenario, rows, idx, malicious = _load(log_path)
    victim = scenario["primary_entity"]["value"]

    org = corpus.build_org(_S06_SEEDS[0], corpus.ROLE_EVAL, _ORG_SPEC)
    user = org.get(victim)

    for line_no in sorted(malicious):
        parts = rows[line_no - 2]
        assert parts[idx["user"]] == victim, f"line {line_no} is not the victim's own principal"
        ts = datetime.strptime(parts[idx["datetime"]], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        assert is_off_hours(ts, user.work_hours) or _is_weekend(ts, user.tz_offset_h), (
            f"line {line_no} at {ts.isoformat()} is neither off-hours nor weekend for {victim}"
        )

    assert scenario["expected_detectors"] == ["signal.stl_residual"]
    assert scenario["expected_disposition"] == "true_positive"
    assert scenario["must_correlate_into_one_incident"] is True
