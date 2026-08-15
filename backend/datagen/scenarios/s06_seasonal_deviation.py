"""Scenario 6 — seasonal deviation (docs/11 row 6, T1029).

Sustained off-hours and weekend activity that is unremarkable in daily aggregate. The premise,
verbatim from docs/11: robust-z over flat 5-minute buckets has no seasonality model, so a user
whose *total* volume is normal but whose *timing* has shifted to nights and weekends is invisible
to it. STL decomposition of the entity's own request-volume series into trend/seasonality/residual
(docs/04 L2 "Seasonal residuals") should surface it, because it scores a deviation from *this
entity's own learned rhythm*, not from a fixed business-hours rule.

**The trick is a shift, not an addition, and it is sized against the victim's own history, not
invented.** Every added event lands at a genuinely off-hours clock time (outside the victim's own
`[start_h, end_h]`, canonical `is_off_hours`) or on a weekend day (local weekday, matching
`DiurnalCurve`'s own convention in `datagen/realism.py`) — but the *count* added on any given
calendar day is capped to a small MAD-width budget of the victim's own historical daily event
count (`_own_daily_budget`, the same "own-history budget" mechanism `s04_low_and_slow_exfil.py`
uses for hourly `bytes_out`, just applied to daily `n_events` here). A human's benign daily count
already has real day-to-day variance from `DiurnalCurve`'s own night floor and weekend-activity
jitter (`datagen/realism.py`; verified against real generated output: a typical user's daily count
ranges roughly 6-23 events over two natural weeks, several off-hours events most days already) --
so a *modest* addition, entirely concentrated in the off-hours/weekend bucket the victim otherwise
barely touches, moves that bucket's *share* by a large multiple while the *day's total* barely
leaves its normal range. That asymmetry -- a small change in an absolute count is a large change in
a share that started near zero -- is exactly the STL prediction docs/12 is testing.

**Three criteria, checked in this order** (docs/11 row 6's two stated properties, plus a positive
proof that a real seasonal decomposition would flag it -- the same "verify by construction, not by
hope" discipline `s04_low_and_slow_exfil.py`'s `_check_acceptance` uses):

  (a) every campaign day's total event count (the victim's own ordinary traffic plus the
      addition) stays within `_ACCEPT_DAILY_Z_THRESHOLD` MAD-widths (robust z, docs/04) of the
      victim's own pre-campaign daily-count distribution -- "total daily volume within normal
      range";
  (b) the off-hours-or-weekend *share*, pooled over the whole campaign period and compared
      against the pooled pre-campaign share with a two-proportion z-test, exceeds
      `_ACCEPT_SHARE_Z_MIN` -- "far outside the entity's own seasonal baseline". Pooled rather
      than scored per calendar day: verified against real generated output, a single human's
      *daily* off-hours share is itself extremely noisy at ordinary event volumes (~10-20
      events/day; one late browse session on an otherwise quiet day already swings a day's share
      by tens of points), so a per-day robust-z comparison was rejecting genuine campaigns for
      the wrong reason -- the *baseline population* was too noisy to score against, not because
      the campaign failed to separate. Pooling every event in each period is the standard fix
      (a two-proportion z-test), and it is what "far outside the entity's own seasonal baseline"
      actually means in aggregate, which is the docs/11 row 6 wording;
  (c) a lightweight, dependency-free additive decomposition of the victim's *hourly* event-count
      series -- trend (24h centered moving average) + seasonal (median detrended value by hour-of-
      day, fit on pre-campaign hours only) + residual -- scores at least
      `_ACCEPT_RESIDUAL_MIN_SEPARATION` of the specific hours the campaign actually touched above
      the victim's own pre-campaign residual p95. This is the positive complement to (a)/(b): not
      just "a flat check is blind" but "a seasonal-aware check is not".

`statsmodels` (which `app/detection/signal`'s real STL detector will use, docs/04) is not among
`datagen`'s own dependencies (checked: not in `backend/pyproject.toml`, not installed) -- criterion
(c) is a from-scratch classical decomposition in the same trend/seasonal/residual shape, not a call
into the library, and is scoped to what a 14-day window (`datagen.corpus.DEFAULT_WINDOW_DAYS`) can
actually support: a full 24-hour-of-day-by-7-weekday seasonal profile would get roughly one sample
per weekday-hour from a single pre-campaign week, too thin to fit meaningfully, so the seasonal
term pools weekday and weekend together over 24 hour-of-day phases (each getting close to a week's
worth of samples) rather than the full daily+weekly split docs/04 describes for the real detector
with ~3 weeks of history. Criterion (b)'s explicit weekend/off-hours *share* check is what actually
carries the weekend half of the claim; (c) is the from-scratch decomposition proof for the daily
rhythm half.
"""

from __future__ import annotations

import math
import statistics
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

import numpy as np

from app.detection.features import is_off_hours, robust_z
from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    SIGNAL_STL_RESIDUAL,
    EntityRef,
    EventRecord,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
    TimeWindow,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import date

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["SeasonalAcceptanceError", "SeasonalDeviationScenario"]


class SeasonalAcceptanceError(RuntimeError):
    """No candidate campaign satisfied docs/11 row 6's acceptance gate within `max_attempts`
    resample rounds for this scenario instance's seed.

    Scenario 6 exists specifically to test whether `signal.stl_residual` earns its slot (docs/12
    prediction 3): a campaign whose daily volume already reads as unusual, or whose off-hours
    share does not actually stand out against the victim's own baseline, or that a from-scratch
    seasonal decomposition still cannot separate, would make that benchmark measure nothing. A
    loud failure here — naming exactly which criterion failed, and on which attempt — is correct;
    silently emitting an invalid scenario 6 would corrupt every eval number downstream instead.
    """


_ACCEPT_DAILY_Z_THRESHOLD: Final[float] = 3.5
_ACCEPT_SHARE_Z_MIN: Final[float] = 4.0
_ACCEPT_RESIDUAL_MIN_SEPARATION: Final[float] = 0.70

# MAD-width budget (same `0.6745*(x-median)/MAD` formula, scored against the victim's own daily
# history rather than a per-hour one) each campaign day's *added* event count is capped to.
_OWN_DAILY_Z_BUDGET: Final[float] = 1.25
_MIN_SAFE_DAILY_ADD: Final[int] = 2
_MIN_PRE_CAMPAIGN_DAYS: Final[int] = 5
_MIN_CAMPAIGN_DAYS: Final[int] = 5

_OK_STATUS: Final[tuple[int, ...]] = (200, 204, 301, 302)
_OK_WEIGHTS: Final[tuple[float, ...]] = (0.85, 0.05, 0.05, 0.05)

_DEFAULT_MAX_ATTEMPTS: Final[int] = 50


def _is_weekend(ts: datetime, tz_offset_h: float) -> bool:
    """Local weekday, matching `DiurnalCurve.weight`'s own `local.weekday() >= 5` convention in
    `datagen/realism.py` -- reimplemented locally rather than imported, per this package's
    convention that a scenario module owns its own file (only the two truly canonical primitives,
    `is_off_hours`/`robust_z`, are shared, `app/detection/features.py`)."""
    return (ts + timedelta(hours=tz_offset_h)).weekday() >= 5


def _local_date(ts: datetime, tz_offset_h: float) -> date:
    return (ts + timedelta(hours=tz_offset_h)).date()


def _median_mad(values: Sequence[float]) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median([abs(v - median) for v in values])
    return float(median), float(mad)


@register_scenario
class SeasonalDeviationScenario(Scenario):
    key = "seasonal_deviation"
    technique = "T1029"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (SIGNAL_STL_RESIDUAL,)
    description = (
        "Sustained off-hours and weekend browsing sized against the victim's own daily-volume "
        "history -- total daily volume stays normal, but the off-hours/weekend share is far "
        "outside this entity's own seasonal baseline. Invisible to a flat robust-z; a "
        "trend/seasonal/residual decomposition of the entity's own rhythm should catch it."
    )

    def __init__(
        self,
        *,
        pre_campaign_days: float = 7.0,
        campaign_days: float = 6.5,
        start_fraction: float = 0.5,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if pre_campaign_days <= 0:
            raise ValueError("pre_campaign_days must be > 0")
        if campaign_days <= 0:
            raise ValueError("campaign_days must be > 0")
        if not 0.0 <= start_fraction < 1.0:
            raise ValueError("start_fraction must be in [0, 1)")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

        self.pre_campaign_days = float(pre_campaign_days)
        self.campaign_days = float(campaign_days)
        self.start_fraction = float(start_fraction)
        self.max_attempts = int(max_attempts)

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        """Resample victim/timing until a candidate satisfies the docs/11 row 6 acceptance gate
        (module docstring), or raise `SeasonalAcceptanceError` after `max_attempts`. Mirrors
        `s04_low_and_slow_exfil.py`'s `inject`: every attempt is keyed off
        `ctx.rng.substream(f"attempt:{attempt}")`, so a given seed always resamples the same
        sequence of candidates, and a rejected attempt's events are rolled back in full before
        the next one.
        """
        stream_floor = len(ctx.stream)
        injected_floor = len(ctx.injected)
        rejections: list[str] = []

        for attempt in range(self.max_attempts):
            attempt_rng = ctx.rng.substream(f"attempt:{attempt:03d}")
            victim = self._pick_victim(ctx, attempt_rng.substream("victim"))
            rng = attempt_rng.substream(f"campaign:{victim.key}")

            ground_truth, rejection = self._attempt_campaign(ctx, rng, victim)
            if rejection is None:
                return ground_truth

            rejections.append(f"attempt {attempt} victim={victim.principal}: {rejection}")
            del ctx.stream[stream_floor:]
            del ctx.injected[injected_floor:]

        raise SeasonalAcceptanceError(
            f"{ctx.scenario_id}: no candidate campaign satisfied the docs/11 row 6 acceptance "
            f"gate (rng={ctx.rng!r}) within {self.max_attempts} attempts:\n"
            + "\n".join(f"  - {r}" for r in rejections)
        )

    def _attempt_campaign(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User
    ) -> tuple[GroundTruth, str | None]:
        emitter = ZScalerEmitter()
        campaign = ctx.window.subwindow(
            start_fraction=self.start_fraction, hours=self.campaign_days * 24.0
        )
        pre_campaign_start = campaign.start - timedelta(days=self.pre_campaign_days)
        if pre_campaign_start < ctx.window.start:
            pre_campaign_start = ctx.window.start

        natural = [
            r
            for r in ctx.benign_for(victim)
            if r.source is SourceType.ZSCALER and pre_campaign_start <= r.ts < campaign.start
        ]
        pre_daily = self._daily_counts(natural, victim.tz_offset_h)
        if len(pre_daily) < _MIN_PRE_CAMPAIGN_DAYS:
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), (
                f"only {len(pre_daily)} pre-campaign days with activity "
                f"(< {_MIN_PRE_CAMPAIGN_DAYS}) -- too thin a baseline to score against"
            )

        median_n, mad_n = _median_mad(list(pre_daily.values()))
        add_cap = max(
            round(median_n + _OWN_DAILY_Z_BUDGET * mad_n / 0.6745)
            if mad_n > 0
            else round(median_n * 0.5),
            _MIN_SAFE_DAILY_ADD,
        )

        campaign_dates = self._campaign_dates(campaign, victim.tz_offset_h)
        if len(campaign_dates) < _MIN_CAMPAIGN_DAYS:
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), (
                f"only {len(campaign_dates)} campaign days "
                f"(< {_MIN_CAMPAIGN_DAYS}) -- campaign_days knob too small"
            )

        # The victim's *own* ordinary daytime traffic keeps happening during the campaign period
        # too -- "total daily volume" (criterion (a)) and "off-hours/weekend share" (criterion
        # (b)) are properties of the *whole* day (this natural traffic plus the injected
        # addition), not of the addition alone. Fetched *before* the injection loop (not after,
        # as an earlier version of this method did) so each day's `n_add` budget can actually be
        # sized against that day's own natural count -- an earlier version keyed this lookup by
        # `pre_daily` (the *pre-campaign* dict), which never has a campaign date as a key, so
        # `existing` was silently always 0 and the budget never accounted for the campaign day's
        # own traffic; verified against real generated output (an independent audit of the
        # emitted file, `tests/test_datagen_s06_seasonal.py`) to actually double a victim's daily
        # total on the more active campaign days instead of keeping it within the own-history
        # budget criterion (a) claims.
        campaign_natural = [
            r
            for r in ctx.benign_for(victim)
            if r.source is SourceType.ZSCALER and campaign.start <= r.ts < campaign.end
        ]
        campaign_natural_daily = self._daily_counts(campaign_natural, victim.tz_offset_h)

        injected: list[EventRecord] = []
        injected_hours: set[datetime] = set()
        affinity = victim.domain_affinity or (ctx.models.domains.sample(rng),)
        for i, day in enumerate(campaign_dates):
            drng = rng.substream(f"day:{i}")
            existing = campaign_natural_daily.get(day, 0)
            budget_left = add_cap - existing
            if budget_left < _MIN_SAFE_DAILY_ADD:
                # This calendar day's own natural traffic is already close to (or over) the
                # day's own budget -- the usual `_MIN_SAFE_DAILY_ADD` floor would push the day's
                # *total* over the z-budget criterion (a) checks, so a naturally busy day gets a
                # thin or zero addition instead of a guaranteed minimum. Verified against real
                # generated output (`tests/test_datagen_s06_seasonal.py`'s independent audit): an
                # earlier version applied the floor unconditionally and pushed one campaign day's
                # total to z=3.51, just over the docs/04 threshold, on a day whose own natural
                # traffic already sat near the cap.
                n_add = max(budget_left, 0)
            else:
                n_add = min(drng.poisson(add_cap * 0.6) + 1, budget_left)
            weekend_today = day.weekday() >= 5
            timestamps = self._session_timestamps(
                ctx, drng, victim, day, n_add, force_weekend=weekend_today
            )
            for ts in timestamps:
                host = drng.choice(affinity)
                kind = ctx.models.response_sizes.sample_kind(drng)
                record = emitter.inject(
                    ctx,
                    user=victim,
                    ts=ts,
                    host=host,
                    src_ip=victim.source_ip(drng),
                    url="/",
                    method="GET",
                    status=drng.weighted_choice(_OK_STATUS, _OK_WEIGHTS),
                    bytes_out=ctx.models.response_sizes.request_bytes(drng, "GET"),
                    bytes_in=ctx.models.response_sizes.response_bytes(drng, kind),
                )
                injected.append(record)
                injected_hours.add(ts.replace(minute=0, second=0, microsecond=0))

        rejection = self._check_acceptance(
            ctx,
            victim,
            natural,
            campaign_natural,
            injected,
            injected_hours,
            campaign,
            pre_campaign_start,
        )
        if rejection is not None:
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), rejection

        evidence = self._evidence(
            ctx,
            victim,
            natural,
            campaign_natural,
            injected,
            injected_hours,
            campaign,
            pre_campaign_start,
        )
        ground_truth = self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"{victim.username} added {len(injected)} off-hours/weekend events across "
                f"{len(campaign_dates)} days ({campaign.start.isoformat()}..{campaign.end.isoformat()}), "
                f"own device, own address, own affinity domains; daily total (own traffic plus "
                f"addition) stayed within z={_ACCEPT_DAILY_Z_THRESHOLD} of {victim.username}'s own "
                f"pre-campaign history (max|z|={evidence['daily_max_z']:.2f}), off-hours/weekend "
                f"share moved from {evidence['pre_share']:.1%} to {evidence['post_share']:.1%} "
                f"(two-proportion z={evidence['share_z']:.1f}, >= {_ACCEPT_SHARE_Z_MIN}), "
                f"trend/seasonal/residual decomposition separated {evidence['residual_separation']:.0%} "
                f"of touched hours above this entity's own pre-campaign residual p95 "
                f"(>= {_ACCEPT_RESIDUAL_MIN_SEPARATION:.0%}); verified against the docs/11 row 6 "
                "acceptance gate (module docstring)"
            ),
        )
        return ground_truth, None

    # ------------------------------------------------------------------ acceptance gate

    def _check_acceptance(
        self,
        ctx: ScenarioContext,
        victim: User,
        natural: Sequence[EventRecord],
        campaign_natural: Sequence[EventRecord],
        injected: Sequence[EventRecord],
        injected_hours: set[datetime],
        campaign: TimeWindow,
        pre_campaign_start: datetime,
    ) -> str | None:
        if not injected:
            return "no malicious events were generated for this candidate"

        pre_daily = self._daily_counts(natural, victim.tz_offset_h)
        if len(pre_daily) < _MIN_PRE_CAMPAIGN_DAYS:
            return (
                f"only {len(pre_daily)} pre-campaign days to score daily volume against "
                f"(< {_MIN_PRE_CAMPAIGN_DAYS})"
            )
        post_daily = self._daily_counts([*campaign_natural, *injected], victim.tz_offset_h)

        # (a) daily total (own traffic plus addition) stays within normal range of the victim's
        # own pre-campaign history.
        pre_counts = list(pre_daily.values())
        offenders = [
            f"{day.isoformat()} (z={z:.2f})"
            for day, count in post_daily.items()
            if abs(z := robust_z(pre_counts, float(count))) > _ACCEPT_DAILY_Z_THRESHOLD
        ]
        if offenders:
            return f"criterion (a) daily volume out of range on: {', '.join(offenders)}"

        # (b) off-hours/weekend *share*, pooled over the whole campaign period (a two-proportion
        # z-test against the pooled pre-campaign share, module docstring: per-day shares are too
        # noisy at this event volume for a per-day robust-z comparison to be meaningful), is far
        # outside the victim's own baseline.
        share_z, pre_share, post_share = self._share_z(
            natural, [*campaign_natural, *injected], victim
        )
        if share_z < _ACCEPT_SHARE_Z_MIN:
            return (
                f"criterion (b) off-hours/weekend share separation too weak: z={share_z:.2f} "
                f"(< {_ACCEPT_SHARE_Z_MIN}), pre={pre_share:.1%} post={post_share:.1%}"
            )

        # (c) the decomposition's residual separates the specific hours the campaign touched.
        separation = self._residual_separation(
            ctx,
            victim,
            natural,
            campaign_natural,
            injected,
            injected_hours,
            campaign,
            pre_campaign_start,
        )
        if separation is None:
            return "criterion (c) too little pre-campaign hourly history to fit a residual baseline"
        if separation < _ACCEPT_RESIDUAL_MIN_SEPARATION:
            return (
                f"criterion (c) residual separation too weak: {separation:.0%} of touched hours "
                f"above pre-campaign residual p95 (< {_ACCEPT_RESIDUAL_MIN_SEPARATION:.0%})"
            )

        return None

    def _evidence(
        self,
        ctx: ScenarioContext,
        victim: User,
        natural: Sequence[EventRecord],
        campaign_natural: Sequence[EventRecord],
        injected: Sequence[EventRecord],
        injected_hours: set[datetime],
        campaign: TimeWindow,
        pre_campaign_start: datetime,
    ) -> dict[str, float]:
        pre_daily = self._daily_counts(natural, victim.tz_offset_h)
        post_daily = self._daily_counts([*campaign_natural, *injected], victim.tz_offset_h)
        pre_counts = list(pre_daily.values())
        daily_max_z = max(abs(robust_z(pre_counts, float(c))) for c in post_daily.values())
        share_z, pre_share, post_share = self._share_z(
            natural, [*campaign_natural, *injected], victim
        )
        residual_separation = self._residual_separation(
            ctx,
            victim,
            natural,
            campaign_natural,
            injected,
            injected_hours,
            campaign,
            pre_campaign_start,
        )
        return {
            "daily_max_z": daily_max_z,
            "share_z": share_z,
            "pre_share": pre_share,
            "post_share": post_share,
            "residual_separation": residual_separation or 0.0,
        }

    def _share_z(
        self, pre_records: Sequence[EventRecord], post_records: Sequence[EventRecord], victim: User
    ) -> tuple[float, float, float]:
        """Two-proportion z-test comparing the off-hours-or-weekend share of `post_records`
        against `pre_records` -- `(z, pre_share, post_share)`. Pooling every record in each period
        (rather than scoring per-day shares against a per-day population, module docstring) is
        what keeps this stable at the event volumes a single human's daily traffic produces.
        """

        def off_share(records: Sequence[EventRecord]) -> tuple[int, int]:
            n = len(records)
            off = sum(
                1
                for r in records
                if is_off_hours(r.ts, victim.work_hours) or _is_weekend(r.ts, victim.tz_offset_h)
            )
            return off, n

        pre_off, pre_n = off_share(pre_records)
        post_off, post_n = off_share(post_records)
        if pre_n == 0 or post_n == 0:
            return 0.0, 0.0, 0.0
        p_pre, p_post = pre_off / pre_n, post_off / post_n
        p_pool = (pre_off + post_off) / (pre_n + post_n)
        se = math.sqrt(p_pool * (1.0 - p_pool) * (1.0 / pre_n + 1.0 / post_n))
        z = math.inf if se == 0 and p_post != p_pre else (0.0 if se == 0 else (p_post - p_pre) / se)
        return z, p_pre, p_post

    def _residual_separation(
        self,
        ctx: ScenarioContext,
        victim: User,
        natural: Sequence[EventRecord],
        campaign_natural: Sequence[EventRecord],
        injected: Sequence[EventRecord],
        injected_hours: set[datetime],
        campaign: TimeWindow,
        pre_campaign_start: datetime,
    ) -> float | None:
        """Fraction of `injected_hours` whose decomposition residual sits above the victim's own
        pre-campaign residual p95 -- criterion (c)'s positive-proof metric (module docstring).

        The hourly series being decomposed is the *whole* observed stream -- pre-campaign natural
        traffic, the campaign period's own ongoing natural daytime traffic, and the injected
        addition -- not just the pre-campaign natural traffic plus the addition. A real detector
        cannot distinguish "natural" from "injected"; it only ever sees one combined series, and
        an earlier version of this method omitted `campaign_natural`, silently decomposing a
        series with no daytime activity at all during the campaign period. That understated the
        trend during touched hours and inflated the apparent separation in a way that did not
        match what `test_datagen_s06_seasonal.py`'s independent audit (built from the same
        combined series any real detector would see) measured from the emitted file.
        """
        hourly = self._hourly_series(
            natural,
            [*campaign_natural, *injected],
            pre_campaign_start,
            campaign.end + timedelta(hours=1),
        )
        if len(hourly) < 24 * _MIN_PRE_CAMPAIGN_DAYS:
            return None

        hours_sorted = sorted(hourly)
        counts = np.array([hourly[h] for h in hours_sorted], dtype=np.float64)
        trend = _centered_moving_average(counts, window=24)
        detrended = counts - trend

        pre_mask = np.array([h < campaign.start for h in hours_sorted])
        seasonal_by_phase: dict[int, float] = {}
        for phase in range(24):
            phase_mask = pre_mask & np.array([h.hour == phase for h in hours_sorted])
            values = detrended[phase_mask]
            seasonal_by_phase[phase] = float(np.median(values)) if values.size else 0.0
        seasonal = np.array([seasonal_by_phase[h.hour] for h in hours_sorted])
        residual = detrended - seasonal

        pre_residual = residual[pre_mask]
        if pre_residual.size < 24 * _MIN_PRE_CAMPAIGN_DAYS // 2:
            return None
        p95 = float(np.percentile(pre_residual, 95))

        index_by_hour = {h: i for i, h in enumerate(hours_sorted)}
        touched = [index_by_hour[h] for h in injected_hours if h in index_by_hour]
        if not touched:
            return 0.0
        above = sum(1 for i in touched if residual[i] > p95)
        return above / len(touched)

    # ------------------------------------------------------------------ helpers

    def _pick_victim(self, ctx: ScenarioContext, rng: SeededRandom) -> User:
        """A moderate-activity human, mirroring the other scenarios' `_pick_victim` -- too quiet
        leaves too little pre-campaign history to baseline against, too heavy needs an
        implausibly large addition to move the share at all."""
        pool = [u for u in ctx.org.users if 0.6 <= u.activity_weight <= 2.5]
        if not pool:
            pool = list(ctx.org.users)
        return rng.weighted_choice(pool, [u.activity_weight for u in pool])

    def _campaign_dates(self, campaign: TimeWindow, tz_offset_h: float) -> list[date]:
        dates: list[date] = []
        seen: set[date] = set()
        ts = campaign.start
        while ts < campaign.end:
            d = _local_date(ts, tz_offset_h)
            if d not in seen:
                seen.add(d)
                dates.append(d)
            ts += timedelta(hours=6.0)
        return dates

    def _daily_counts(self, records: Sequence[EventRecord], tz_offset_h: float) -> dict[date, int]:
        counts: dict[date, int] = {}
        for r in records:
            d = _local_date(r.ts, tz_offset_h)
            counts[d] = counts.get(d, 0) + 1
        return counts

    def _hourly_series(
        self,
        natural: Sequence[EventRecord],
        injected: Sequence[EventRecord],
        start: datetime,
        end: datetime,
    ) -> dict[datetime, int]:
        hourly: dict[datetime, int] = {}
        ts = start.replace(minute=0, second=0, microsecond=0)
        while ts < end:
            hourly[ts] = 0
            ts += timedelta(hours=1)
        for r in (*natural, *injected):
            bucket = r.ts.replace(minute=0, second=0, microsecond=0)
            if bucket in hourly:
                hourly[bucket] += 1
        return hourly

    def _session_timestamps(
        self,
        ctx: ScenarioContext,
        rng: SeededRandom,
        victim: User,
        day: date,
        n: int,
        *,
        force_weekend: bool,
    ) -> list[datetime]:
        """`n` timestamps on local calendar `day`, all off-hours-or-weekend by construction,
        clustered into a small number of sessions rather than smeared independently across many
        distinct hours.

        Clustering matters for criterion (c): verified against real generated output, spreading
        `n` events across `n` independently-drawn hours left most touched hours with only one
        extra event each, whose residual rarely cleared the (already noisy, thin-history) p95 of
        the victim's own pre-campaign residual distribution -- a real browsing session is a burst
        of several requests within minutes anyway, so clustering is both more realistic and the
        thing that actually produces a residual `_residual_separation` can detect.

        A weekend day already satisfies the criterion at any clock hour, so session anchors are
        drawn from the *whole* day. A weekday draws its anchor strictly from outside
        `[start_h, end_h]` local time -- the same boundary `is_off_hours` scores against, so this
        is a guarantee, not a tendency, mirroring `s04_low_and_slow_exfil.py`'s
        `_sample_work_hours_timestamps` approach in reverse.

        **Known, minor imprecision:** `ctx.window.clamp` (below) bounds a timestamp to the
        *overall* corpus window, not to `[campaign.start, campaign.end)` specifically. For a
        victim whose office sits west of UTC, the first campaign day's own local midnight can
        fall a few hours *before* `campaign.start` in UTC terms, so a low-`local_h` weekend
        session on that first day can land chronologically just outside the nominal campaign
        window (still `malicious=True`, still correctly in `malicious_line_numbers` -- ground
        truth is unaffected). `_check_acceptance`/`_evidence` are unaffected because they never
        rely on a timestamp comparison to separate malicious from natural (they use `natural` /
        `[*campaign_natural, *injected]`, three cleanly-disjoint record sets), but the notes
        field's stated campaign start/end should be read as nominal, not as a hard per-event
        guarantee -- the same class of honestly-documented edge case as
        `s04_low_and_slow_exfil.py`'s own `DiurnalCurve.night_floor` note
        (`test_datagen_ground_truth.py`'s `test_low_and_slow_exfil_notes_overclaim_working_hours`).
        """
        hours = victim.work_hours
        # 1 session for a light day, 2 for a heavier one -- either way each session still lands
        # the bulk of its events in one hour bucket.
        n_sessions = 1 if n <= 6 else 2
        base = n // n_sessions
        sizes = [base] * n_sessions
        sizes[-1] += n - base * n_sessions

        out: list[datetime] = []
        for s, size in enumerate(sizes):
            if size <= 0:
                continue
            srng = rng.substream(f"session:{s}")
            if force_weekend:
                local_h = srng.uniform(0.0, 23.3)
            else:
                span = max(24.0 - hours.span_h, 2.0)
                local_h = (hours.end_h + srng.uniform(0.1, span - 0.6)) % 24.0
            midnight_utc = datetime(day.year, day.month, day.day, tzinfo=UTC) - timedelta(
                hours=hours.tz_offset_h
            )
            anchor = midnight_utc + timedelta(hours=local_h)
            for _i in range(size):
                ts = anchor + timedelta(minutes=srng.uniform(0.0, 22.0))
                out.append(ctx.window.clamp(ts))
        out.sort()
        return out


def _centered_moving_average(values: np.ndarray, *, window: int) -> np.ndarray:
    """Centered moving average with edge handling via a shrinking window at the boundaries --
    `np.convolve`'s "same" mode would taper toward zero at the edges instead, which would read as
    a spurious trend collapse rather than genuinely thinner boundary data."""
    n = values.size
    half = window // 2
    out = np.empty(n, dtype=np.float64)
    cumsum = np.concatenate(([0.0], np.cumsum(values)))
    for i in range(n):
        lo = max(0, i - half)
        hi = min(n, i + half + 1)
        out[i] = (cumsum[hi] - cumsum[lo]) / (hi - lo)
    return out
