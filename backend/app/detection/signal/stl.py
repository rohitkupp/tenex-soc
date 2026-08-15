"""STL seasonal residuals (docs/04 §L2 "Seasonal residuals (STL)", REWRITTEN section, ATT&CK
T1029).

```
Per entity, decompose the hourly request-volume series with STL (period=24 daily, period=168
weekly where there is enough history):
  volume(t) = trend(t) + seasonal_daily(t) + seasonal_weekly(t) + residual(t)
Flag entities whose residual is a robust-z outlier (|z| > 3.5) against its own residual
distribution.
```

## Why this detector exists (restated from docs/04, because it is the point of it)

`burst.py`'s robust z-score has no model of seasonality — every 5-minute bucket is scored as if
drawn from the same distribution, so "unusual" and "off-hours" are indistinguishable without a
separate hardcoded business-hours rule. This detector instead learns each entity's own daily and
weekly rhythm and flags a deviation *from that entity's own learned rhythm* — a user who
legitimately works evenings gets a seasonal profile that expects evening volume, so only activity
that departs from *that* profile fires, not activity that merely happens after 5pm UTC. Scenario 6
(`docs/11`, seasonal deviation) exists to test exactly this against pre-registered prediction #3
(`docs/12`): STL should catch sustained off-hours/weekend volume that is unremarkable in daily
aggregate; the L3 per-window feature-vector models should not, because the signal lives in the
*shape of a time series*, not in any single window's snapshot.

## `MSTL`, not two manually-chained `STL` passes

docs/04 describes the decomposition as "STL ... period=24 for daily; a second pass at period=168
for weekly." `statsmodels.tsa.seasonal.MSTL` (Multiple STL, the same `tsa.seasonal` module docs/04
names) is that two-pass decomposition already implemented and validated by statsmodels itself —
manually chaining two `STL.fit()` calls (fit daily, re-decompose the daily residual for weekly)
reimplements what `MSTL` already does, with more surface area for a subtle bug (e.g. accidentally
feeding the weekly pass the wrong intermediate series). `MSTL(series, periods=(STL_PERIOD_DAILY,
STL_PERIOD_WEEKLY)).fit()` returns `.trend`, `.seasonal` (a `(n, 2)` frame, columns
`seasonal_24`/`seasonal_168`), and `.resid` — exactly docs/04's `trend`/`seasonal_daily`/
`seasonal_weekly`/`residual` decomposition, additively: `endog == trend + seasonal_24 +
seasonal_168 + resid` (verified directly against a synthetic series while building this module).

## Dense grid for decomposition, active-only population for scoring

`burst.py`'s own docstring explains why *that* detector scores only an entity's active
(nonzero-count) buckets: a dense zero-filled grid would make almost every active period an
unbounded `robust_z` outlier, because the *idle* time would dominate and define "normal." STL's
*decomposition* step needs the opposite — a seasonal fit is only meaningful over a *regular,
gap-free* hourly grid, so this module zero-fills every hour in an entity's own first-to-last-event
span before handing it to `MSTL`, unlike `burst.py`.

But `burst.py`'s own concern turns out to still apply to the *scoring* step, one layer downstream
of where that module raised it — caught directly against real `s06_seasonal_deviation.py` output,
not anticipated in the abstract: a mostly-idle entity's dense residual series is dominated by
correctly-predicted-near-zero idle hours, so the residual *population* `robust_z` would score
against is artificially tight (small MAD), and an entirely ordinary active hour's residual reads
as a huge outlier purely because it is being compared to a population that idle time was allowed
to define as "normal" — the identical failure mode `burst.py` already named for a different
detector, now reproduced one step later for this one. The fix is the same one `burst.py` already
uses: the *decomposition* runs on the dense grid (needed for a correct seasonal fit), but the
`robust_z` *population*, and every hour actually scored/flagged, is restricted to this entity's
own active (nonzero-count) hours only.

## Three scoring paths, not two

docs/04 qualifies the weekly pass specifically -- "period=168 for weekly *where there is enough
history*" -- which is a different, looser bar than "enough history for a seasonal profile at
all." This module therefore has three tiers, gated by span (`STL_MIN_HOURS_FOR_WEEKLY_SEASONAL`,
`STL_MIN_HOURS_FOR_DAILY_SEASONAL`; see `constants.py`'s own docstring for the concrete hour
counts and why they are `MSTL`'s own technical minimums for each period rather than docs/04's
"~3 weeks" production-guidance figure): daily+weekly `MSTL`, daily-only `MSTL`, or (below even
that) a plain robust z-score over the entity's own *active* hourly counts with no decomposition
at all — `burst.py`'s own population choice, at hourly instead of 5-minute granularity, for the
identical MAD==0-degeneracy reason. `explanation.model` distinguishes all three
(`"stl_daily_weekly"` / `"stl_daily_only"` / `"fallback_robust_z"`) so a human reading a signal
never mistakes one for another; the fallback path's `trend`/`seasonal_component`/`residual`
fields are `None` rather than a fabricated decomposition that never ran, and the daily-only
path's `seasonal_weekly` is `None` for the same reason.

`explanation`: `{trend, seasonal_component, residual, residual_z, period_used}` (docs/04's exact
shape) plus `model`, `seasonal_daily`, `seasonal_weekly` (the breakdown `seasonal_component` sums)
for additional context.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from statsmodels.tsa.seasonal import MSTL

from app.detection.features import robust_z
from app.detection.signal.constants import (
    BURST_Z_THRESHOLD,
    ENTITY_SRC_IP,
    ENTITY_USER,
    SIGNAL_STL_RESIDUAL,
    STL_MIN_ACTIVE_HOURS_FALLBACK,
    STL_MIN_HOURS_FOR_DAILY_SEASONAL,
    STL_MIN_HOURS_FOR_WEEKLY_SEASONAL,
    STL_PERIOD_DAILY,
    STL_PERIOD_WEEKLY,
    STL_RESIDUAL_ROUND_DECIMALS,
)
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow

__all__ = ["detect_stl_residual"]


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _hourly_counts(rows: Sequence[EventRow]) -> dict[datetime, list[EventRow]]:
    buckets: dict[datetime, list[EventRow]] = defaultdict(list)
    for row in rows:
        buckets[_hour_floor(row.ts)].append(row)
    return buckets


def _fallback_drafts(
    entity_type: str, entity_value: str, buckets: dict[datetime, list[EventRow]]
) -> list[SignalDraft]:
    """Plain robust-z over this entity's own active hourly buckets — see module docstring "Two
    scoring paths." Not STL; no decomposition is attempted."""
    if len(buckets) < STL_MIN_ACTIVE_HOURS_FALLBACK:
        return []
    counts = [len(v) for v in buckets.values()]

    drafts: list[SignalDraft] = []
    for hour, hour_rows in buckets.items():
        x = float(len(hour_rows))
        z = robust_z(counts, x)
        if abs(z) <= BURST_Z_THRESHOLD:
            continue
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in hour_rows])
        explanation: dict[str, Any] = {
            "model": "fallback_robust_z",
            "trend": None,
            "seasonal_component": None,
            "seasonal_daily": None,
            "seasonal_weekly": None,
            "residual": None,
            "residual_z": z if z not in (float("inf"), float("-inf")) else None,
            "residual_z_is_infinite": z in (float("inf"), float("-inf")),
            "period_used": [],
            "entity_type": entity_type,
            "entity_value": entity_value,
            "hourly_count": int(x),
            "n_active_hours": len(buckets),
            "reason": (
                f"fewer than {STL_MIN_HOURS_FOR_DAILY_SEASONAL} hours of span -- not enough "
                "history for even a daily seasonal profile"
            ),
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_STL_RESIDUAL,
                entity_type=entity_type,
                entity_value=entity_value,
                raw_score=z,
                confidence_raw=min(1.0, abs(z) / 10.0)
                if z not in (float("inf"), float("-inf"))
                else 1.0,
                window_start=hour,
                window_end=hour + timedelta(hours=1),
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def _stl_drafts(
    entity_type: str,
    entity_value: str,
    buckets: dict[datetime, list[EventRow]],
    *,
    include_weekly: bool,
) -> list[SignalDraft]:
    hours = sorted(buckets)
    first, last = hours[0], hours[-1]
    span_hours = int((last - first).total_seconds() // 3600) + 1

    index = pd.date_range(start=first, end=last, freq="h", tz=UTC)
    counts = np.array([len(buckets.get(h.to_pydatetime(), ())) for h in index], dtype=np.float64)

    if np.std(counts) == 0.0:
        # A perfectly flat series has nothing to decompose and nothing to flag -- `robust_z`
        # would score every value at the median (`z == 0.0`) regardless; skip the MSTL call
        # rather than run a degenerate decomposition on zero-variance input.
        return []

    series = pd.Series(counts, index=index)
    periods = (STL_PERIOD_DAILY, STL_PERIOD_WEEKLY) if include_weekly else (STL_PERIOD_DAILY,)
    result = MSTL(series, periods=periods).fit()
    # `MSTL` silently drops a period internally (with a `UserWarning`, not an exception) when the
    # series is not *more than* twice that period's length -- stricter than the "at least twice"
    # this module's own threshold constants assume, and `span_hours` (this entity's own inclusive
    # hour count) can legitimately land exactly on that boundary for a real corpus. Rather than
    # tighten `STL_MIN_HOURS_FOR_WEEKLY_SEASONAL` to chase an internal implementation detail
    # exactly, this checks what `MSTL` actually did (`.seasonal` is a `(n, k)` frame only when
    # `k > 1` periods survived) instead of trusting `include_weekly` blindly -- caught directly
    # against real `s06_seasonal_deviation.py` output while building this module, not a
    # hypothetical case.
    actually_has_weekly = include_weekly and isinstance(result.seasonal, pd.DataFrame)
    if actually_has_weekly:
        seasonal_daily = result.seasonal[f"seasonal_{STL_PERIOD_DAILY}"].to_numpy()
        seasonal_weekly = result.seasonal[f"seasonal_{STL_PERIOD_WEEKLY}"].to_numpy()
    else:
        seasonal_daily = result.seasonal.to_numpy()
        seasonal_weekly = np.zeros_like(seasonal_daily)
    trend = result.trend.to_numpy()
    # Rounded before scoring -- module docstring / `constants.py`'s `STL_RESIDUAL_ROUND_DECIMALS`
    # docstring: a real, measured false-positive bug (LOESS floating-point noise on a
    # near-degenerate, highly regular entity's residual population), not defensive styling.
    resid = np.round(result.resid.to_numpy(), STL_RESIDUAL_ROUND_DECIMALS)

    # Active-hours-only population -- module docstring "Dense grid for decomposition,
    # active-only population for scoring." Idle (zero-count) hours are excluded from both the
    # scoring population *and* the set of hours actually flagged: an idle hour's residual is
    # (correctly) near zero, and letting a mostly-idle entity's many idle hours define "normal"
    # is exactly `burst.py`'s own documented MAD-degeneracy failure mode, reproduced here.
    active_mask = np.array([h.to_pydatetime() in buckets for h in index])
    if int(active_mask.sum()) < STL_MIN_ACTIVE_HOURS_FALLBACK:
        return []
    resid_population = resid[active_mask].tolist()
    model_name = "stl_daily_weekly" if actually_has_weekly else "stl_daily_only"
    period_used = (
        [STL_PERIOD_DAILY, STL_PERIOD_WEEKLY] if actually_has_weekly else [STL_PERIOD_DAILY]
    )
    include_weekly = actually_has_weekly

    drafts: list[SignalDraft] = []
    for i, hour in enumerate(index):
        if not active_mask[i]:
            continue
        hour_dt = hour.to_pydatetime()
        z = robust_z(resid_population, float(resid[i]))
        if abs(z) <= BURST_Z_THRESHOLD:
            continue
        # `active_mask` (module docstring) already restricts this loop to hours with events.
        hour_rows = buckets[hour_dt]
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in hour_rows])
        explanation: dict[str, Any] = {
            "model": model_name,
            "trend": float(trend[i]),
            "seasonal_component": float(seasonal_daily[i] + seasonal_weekly[i]),
            "seasonal_daily": float(seasonal_daily[i]),
            "seasonal_weekly": float(seasonal_weekly[i]) if include_weekly else None,
            "residual": float(resid[i]),
            "residual_z": z,
            "residual_z_is_infinite": False,  # MSTL's own resid is always finite by construction
            "period_used": period_used,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "hourly_count": int(counts[i]),
            "span_hours": span_hours,
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_STL_RESIDUAL,
                entity_type=entity_type,
                entity_value=entity_value,
                raw_score=z,
                confidence_raw=min(1.0, abs(z) / 10.0),
                window_start=hour_dt,
                window_end=hour_dt + timedelta(hours=1),
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def _detect_for_entity(
    rows: Sequence[EventRow],
    *,
    entity_type: str,
    entity_value_of: Callable[[EventRow], str | None],
) -> list[SignalDraft]:
    by_entity: dict[str, list[EventRow]] = defaultdict(list)
    for row in rows:
        value = entity_value_of(row)
        if value is None:
            continue
        by_entity[value].append(row)

    drafts: list[SignalDraft] = []
    for entity_value, entity_rows in by_entity.items():
        buckets = _hourly_counts(entity_rows)
        hours = sorted(buckets)
        span_hours = int((hours[-1] - hours[0]).total_seconds() // 3600) + 1 if hours else 0
        if span_hours >= STL_MIN_HOURS_FOR_WEEKLY_SEASONAL:
            drafts += _stl_drafts(entity_type, entity_value, buckets, include_weekly=True)
        elif span_hours >= STL_MIN_HOURS_FOR_DAILY_SEASONAL:
            drafts += _stl_drafts(entity_type, entity_value, buckets, include_weekly=False)
        else:
            drafts += _fallback_drafts(entity_type, entity_value, buckets)
    return drafts


def detect_stl_residual(rows: Sequence[EventRow]) -> list[SignalDraft]:
    """Both entity dimensions (`user`, `src_ip`), mirroring `burst.py`'s own precedent for the
    same "docs/04 says 'entity' without naming which" ambiguity (that module's docstring) — a
    user's own request-volume rhythm and a source IP's own rhythm are different attack surfaces.
    """
    by_user = _detect_for_entity(
        rows, entity_type=ENTITY_USER, entity_value_of=lambda r: r.principal
    )
    by_src_ip = _detect_for_entity(
        rows, entity_type=ENTITY_SRC_IP, entity_value_of=lambda r: r.src_ip
    )
    return by_user + by_src_ip
