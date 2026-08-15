"""Unit tests for `app/detection/features.py` — the canonical `is_off_hours`/`robust_z`
definitions `datagen/scenarios/s08_low_and_slow_exfil.py` and
`tests/test_datagen_s08_marginals.py` both import rather than redefine (docs/04's L3 feature
list, "canonical definitions" note).

This module is deliberately decoupled from `datagen`: `is_off_hours` takes anything with
`start_h`/`end_h`/`tz_offset_h` attributes (`WorkHoursLike`), not `datagen.realism.WorkHours`
itself, so these tests build a minimal local stand-in rather than importing the generator.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from app.detection.features import (
    ENTITY_WINDOW_FEATURES,
    FEATURE_BYTES_IN,
    FEATURE_BYTES_OUT,
    FEATURE_N_EVENTS,
    FEATURE_N_LARGE_UPLOADS,
    FEATURE_OFF_HOURS_RATIO,
    FEATURE_OUT_IN_RATIO,
    FEATURE_POST_RATIO,
    is_off_hours,
    robust_z,
)


@dataclass(frozen=True, slots=True)
class _WorkHours:
    """Minimal `WorkHoursLike` stand-in — exactly the three fields `is_off_hours` needs, nothing
    from `datagen.realism.WorkHours` beyond that shape.
    """

    start_h: float
    end_h: float
    tz_offset_h: float


# ---------------------------------------------------------------------------- is_off_hours


def test_is_off_hours_boundaries_are_inclusive() -> None:
    """`[start_h, end_h]` is a closed interval: exactly at either edge counts as on-hours."""
    hours = _WorkHours(start_h=9.0, end_h=17.5, tz_offset_h=0.0)
    start_edge = datetime(2026, 3, 2, 9, 0, tzinfo=UTC)  # a Monday
    end_edge = datetime(2026, 3, 2, 17, 30, tzinfo=UTC)

    assert is_off_hours(start_edge, hours) is False
    assert is_off_hours(end_edge, hours) is False


def test_is_off_hours_midday_is_on_hours_and_midnight_is_off_hours() -> None:
    hours = _WorkHours(start_h=9.0, end_h=17.5, tz_offset_h=0.0)
    midday = datetime(2026, 3, 2, 13, 0, tzinfo=UTC)
    midnight = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)

    assert is_off_hours(midday, hours) is False
    assert is_off_hours(midnight, hours) is True


def test_is_off_hours_uses_per_user_local_time_not_fixed_utc() -> None:
    """The concrete bug this module exists to prevent (module docstring): a fixed UTC
    business-hours window misclassifies a US-CA 9-to-5 as off-hours. The same UTC instant must
    read differently for a US-CA worker (UTC-8) than a UTC worker with identical local hours.
    """
    us_ca = _WorkHours(start_h=9.0, end_h=17.5, tz_offset_h=-8.0)
    utc = _WorkHours(start_h=9.0, end_h=17.5, tz_offset_h=0.0)

    # 18:00 UTC is 10:00 local for a US-CA worker (on hours) but 18:00 local for a UTC worker
    # (past end_h=17.5, off hours) -- the same instant, opposite verdicts.
    ts = datetime(2026, 3, 2, 18, 0, tzinfo=UTC)
    assert is_off_hours(ts, us_ca) is False
    assert is_off_hours(ts, utc) is True


def test_is_off_hours_wraps_across_the_utc_day_boundary() -> None:
    """A positive `tz_offset_h` (e.g. IE-DU-like or further east) can push local time past
    midnight UTC; the `% 24.0` wrap must still land the right side of the boundary.
    """
    hours = _WorkHours(start_h=9.0, end_h=17.5, tz_offset_h=10.0)
    # 23:30 UTC + 10h = local hour 33.5 % 24 = 9.5 -> on hours.
    ts = datetime(2026, 3, 2, 23, 30, tzinfo=UTC)
    assert is_off_hours(ts, hours) is False


# ---------------------------------------------------------------------------- robust_z


def test_robust_z_matches_docs_04_formula_on_a_spread_population() -> None:
    """A concrete literal expectation, not a recomputation of the same formula under test --
    `median([1..7]) == 4`, `MAD == median(|v-4|) == 2`, so `z(10) == 0.6745 * (10-4)/2 ==
    2.0235`. A typo in the `0.6745` constant would not be caught by re-deriving the expected
    value with the same expression.
    """
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]
    assert robust_z(values, 10.0) == pytest.approx(2.0235)
    assert robust_z(values, -2.0) == pytest.approx(-2.0235)


def test_robust_z_at_median_is_zero() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert robust_z(values, float(statistics.median(values))) == 0.0


def test_robust_z_mad_zero_at_population_value_is_zero_not_inf() -> None:
    """A degenerate (zero-spread) population scored against its own value has no deviation to
    report -- the explicit MAD==0 policy's first branch.
    """
    values = [0.0, 0.0, 0.0, 0.0]
    assert robust_z(values, 0.0) == 0.0


def test_robust_z_mad_zero_elsewhere_is_unbounded_not_epsilon_divided() -> None:
    """The explicit MAD==0 policy's second branch, and the whole reason it exists (module
    docstring): a degenerate population scored against *any other* value is an unbounded outlier
    by construction, not a small, epsilon-divided z-score that would read as "safe". This is
    exactly the seed=33 scenario-8 failure mode the acceptance gate (docs/11 row 8) exists to
    reject rather than silently pass.
    """
    values = [0.0, 0.0, 0.0]
    assert robust_z(values, 0.25) == math.inf
    # Sign of the deviation does not change the policy -- still an unbounded outlier either way.
    assert robust_z(values, -0.25) == math.inf


def test_robust_z_empty_population_raises() -> None:
    """No baseline to score against is a caller bug, not a silently-tolerated zero."""
    with pytest.raises(statistics.StatisticsError):
        robust_z([], 1.0)


# ---------------------------------------------------------------------------- feature names


def test_entity_window_features_are_the_seven_docs_04_names_no_duplicates() -> None:
    expected = {
        FEATURE_N_EVENTS,
        FEATURE_BYTES_OUT,
        FEATURE_BYTES_IN,
        FEATURE_OUT_IN_RATIO,
        FEATURE_POST_RATIO,
        FEATURE_OFF_HOURS_RATIO,
        FEATURE_N_LARGE_UPLOADS,
    }
    assert len(expected) == 7, "one of the FEATURE_* constants collides with another"
    assert set(ENTITY_WINDOW_FEATURES) == expected
    assert len(ENTITY_WINDOW_FEATURES) == len(set(ENTITY_WINDOW_FEATURES)), (
        "ENTITY_WINDOW_FEATURES must not repeat a feature name"
    )


def test_feature_constants_are_plain_strings() -> None:
    """These are dict keys and DataFrame-style column names downstream (the generator's gate,
    the regression test's per-hour feature dicts) -- anything but `str` would break both silently.
    """
    for name in ENTITY_WINDOW_FEATURES:
        assert isinstance(name, str)
        assert name  # non-empty
