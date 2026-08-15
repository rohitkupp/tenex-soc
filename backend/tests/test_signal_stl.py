"""Unit tests for `app.detection.signal.stl.detect_stl_residual` -- CLAUDE.md's "every detector
needs a synthetic fixture that must fire and one that must not," against pure `EventRow` lists.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from app.detection.signal.constants import (
    SIGNAL_STL_RESIDUAL,
    STL_MIN_HOURS_FOR_DAILY_SEASONAL,
    STL_MIN_HOURS_FOR_WEEKLY_SEASONAL,
)
from app.detection.signal.events_dao import EventRow
from app.detection.signal.stl import detect_stl_residual

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _seasonal_rows(
    *, n_days: int, seed: int = 1, extra_hours: dict[tuple[int, int], int] | None = None
) -> list[EventRow]:
    """`n_days` of a clean daily 9-17 business-hours pattern (3-6 events/hour on-hours, 0-1
    off-hours), one entity, plus any `{(day, hour): n_events}` overrides layered on top --
    exactly `s06_seasonal_deviation.py`'s own premise (docs/11 row 6): a seasonal profile the
    detector has to learn before an off-profile hour can stand out against it.
    """
    rng = random.Random(seed)
    rows: list[EventRow] = []
    eid = 0
    extra_hours = extra_hours or {}
    for day in range(n_days):
        for hour in range(24):
            base_n = rng.randint(3, 6) if 9 <= hour <= 17 else rng.randint(0, 1)
            n = extra_hours.get((day, hour), base_n)
            hour_start = _T0 + timedelta(days=day, hours=hour)
            for i in range(n):
                rows.append(
                    EventRow(
                        id=eid,
                        ts=hour_start + timedelta(minutes=i),
                        src_ip="10.0.0.1",
                        domain="corp-tools.example",
                        principal="alice@corp.example",
                    )
                )
                eid += 1
    return rows


def test_sustained_off_hours_burst_fires_after_a_learned_seasonal_profile() -> None:
    # 40 days of clean daily rhythm (> STL_MIN_HOURS_FOR_WEEKLY_SEASONAL) with a sustained
    # off-hours (01:00-04:00) burst injected on day 35 -- the exact shape docs/11 scenario 6
    # describes: "sustained off-hours and weekend volume that is unremarkable in daily aggregate."
    assert STL_MIN_HOURS_FOR_WEEKLY_SEASONAL <= 40 * 24
    extra = {(35, h): 20 for h in (1, 2, 3, 4)}
    rows = _seasonal_rows(n_days=40, extra_hours=extra)

    drafts = detect_stl_residual(rows)
    stl_drafts = [d for d in drafts if d.explanation["model"] == "stl_daily_weekly"]
    assert stl_drafts  # the full daily+weekly STL path was actually exercised

    flagged_hours = {
        d.window_start for d in stl_drafts if d.entity_type == "user" and d.window_start is not None
    }
    for h in (1, 2, 3, 4):
        injected_hour = _T0 + timedelta(days=35, hours=h)
        assert injected_hour in flagged_hours, f"hour {h} of the injected burst was not flagged"


def test_ordinary_seasonal_pattern_does_not_fire_on_its_own_learned_rhythm() -> None:
    # No injected anomaly -- an entity that only ever does exactly what its own seasonal profile
    # predicts should not generate a flood of false positives against itself.
    rows = _seasonal_rows(n_days=40, seed=2)

    drafts = detect_stl_residual(rows)
    stl_drafts = [d for d in drafts if d.explanation["model"] == "stl_daily_weekly"]
    user_hours_scored = 40 * 24
    # A robust-z threshold at 3.5 on a real (noisy) residual distribution can still legitimately
    # flag a small handful of genuinely extreme-tailed hours by chance; this asserts the false
    # positive rate stays low (not literally zero) rather than the detector is silent by
    # construction.
    user_flags = [d for d in stl_drafts if d.entity_type == "user"]
    assert len(user_flags) / user_hours_scored < 0.05


def test_short_history_entity_falls_back_to_plain_robust_z() -> None:
    # Only a day and a half of history -- below STL_MIN_HOURS_FOR_DAILY_SEASONAL -- must use the
    # fallback path (docs/04: "short-lived entities fall back to the plain robust z-score above"),
    # not attempt (and silently misuse) a seasonal decomposition with no real seasonal signal to
    # fit.
    assert STL_MIN_HOURS_FOR_DAILY_SEASONAL > 36
    rows = _seasonal_rows(n_days=2, seed=3)
    rows = [r for r in rows if r.ts < _T0 + timedelta(hours=36)]
    # A sharp spike on one active hour.
    spike_hour = _T0 + timedelta(hours=20)
    eid = 100_000
    for i in range(40):
        rows.append(
            EventRow(
                id=eid + i,
                ts=spike_hour + timedelta(seconds=i * 10),
                src_ip="10.0.0.1",
                domain="corp-tools.example",
                principal="alice@corp.example",
            )
        )

    drafts = detect_stl_residual(rows)
    assert drafts  # something fired
    assert all(d.explanation["model"] == "fallback_robust_z" for d in drafts)
    assert all(d.explanation["trend"] is None for d in drafts)


def test_medium_history_entity_uses_daily_only_stl() -> None:
    # Enough history for a daily profile but short of a full weekly cycle -- the middle tier.
    n_days = 10
    assert STL_MIN_HOURS_FOR_DAILY_SEASONAL <= n_days * 24 < STL_MIN_HOURS_FOR_WEEKLY_SEASONAL
    extra = {(8, h): 20 for h in (1, 2, 3, 4)}
    rows = _seasonal_rows(n_days=n_days, seed=4, extra_hours=extra)

    drafts = detect_stl_residual(rows)
    stl_drafts = [d for d in drafts if d.explanation["model"] == "stl_daily_only"]
    assert stl_drafts
    assert all(d.explanation["seasonal_weekly"] is None for d in stl_drafts)
    assert all(d.explanation["period_used"] == [24] for d in stl_drafts)


def test_detector_key_and_entity_dimensions() -> None:
    extra = {(35, h): 20 for h in (1, 2, 3, 4)}
    rows = _seasonal_rows(n_days=40, extra_hours=extra)
    drafts = detect_stl_residual(rows)
    assert drafts
    assert {d.detector_key for d in drafts} == {SIGNAL_STL_RESIDUAL}
    assert {d.entity_type for d in drafts} <= {"user", "src_ip"}


def test_flat_zero_variance_series_produces_no_stl_drafts() -> None:
    # A perfectly constant hourly count has nothing to decompose and nothing to flag --
    # `stl.py`'s own guard against calling MSTL on a degenerate zero-variance series.
    rows = []
    eid = 0
    for day in range(40):
        for hour in range(24):
            hour_start = _T0 + timedelta(days=day, hours=hour)
            for i in range(3):  # exactly 3 events, every single hour, no variation at all
                rows.append(
                    EventRow(
                        id=eid,
                        ts=hour_start + timedelta(minutes=i),
                        src_ip="10.0.0.5",
                        domain="corp-tools.example",
                        principal="flat@corp.example",
                    )
                )
                eid += 1

    drafts = detect_stl_residual(rows)
    assert [d for d in drafts if d.entity_value == "flat@corp.example"] == []
