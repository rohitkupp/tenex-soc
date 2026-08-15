"""Scenario 8 — low-and-slow exfiltration (docs/11 row 8, T1567).

This is the scenario that decides whether the autoencoder ships as primary. Every other proxy
scenario in this package earns its detection surface honestly: a rare/DGA domain, a volumetric
burst, a bad out/in ratio, a newly-registered destination. This one is built to have none of
that. If any single L2 signal or any single L3 feature's marginal z-score could catch it, the
autoencoder benchmark it exists to feed would be measuring nothing.

**The marginal/joint properties are a postcondition of generation, not a hoped-for outcome.**
Two earlier repair passes tuned this scenario's shaping constants empirically against a small,
hand-picked set of seeds (`_S08_SEEDS` in the regression test) and both overfit: stress-testing
against seeds never used for tuning turned up a victim with `MAD == 0` on `off_hours_ratio` (the
"no marginal fires" check passing vacuously — there was no spread to fire against, not genuine
invisibility) and a victim whose campaign was so well hidden the *joint* distribution no longer
separated it either, which would mean the autoencoder this scenario exists to benchmark could not
find it any better than random. Median/MAD are order statistics, not a smooth function these
constants can be solved for in closed form, so no fixed set of constants generalizes to every
victim a weighted random draw might select.

`inject` therefore does not trust its own shaping to work: after laying down a candidate campaign
for a candidate victim, it independently re-derives that victim's own entity-window feature
vectors (`_check_acceptance`, using the same canonical `is_off_hours`/`robust_z` from
`app.detection.features` that the regression test audits with) and checks the scenario's own
acceptance criteria — docs/11 row 8's three properties, verbatim — before ever committing to a
result:

  (a) no single-feature marginal robust z (docs/04, `0.6745*(x-median)/MAD`) among the docs/04 L3
      features this scenario touches exceeds 3.5 on any attack hour;
  (b) the victim's benign history has genuinely non-zero MAD on `post_ratio` and
      `off_hours_ratio`, so (a) cannot pass vacuously via `robust_z`'s explicit MAD==0 policy;
  (c) the joint (Mahalanobis) distribution still separates at least 70% of attack hours above the
      victim's own benign p95.

A candidate that fails any of the three is rolled back in full (every event it added, benign
shaping included) and a fresh victim/placement is resampled from the next seeded attempt, up to
`max_attempts` (a constructor knob). If no candidate passes within the bound, `inject` raises
`LowAndSlowAcceptanceError` naming exactly which criterion failed on which attempt, rather than
silently emitting a scenario that would corrupt the autoencoder benchmark. The whole loop is
driven by `ctx.rng`, so a given seed always resamples the same sequence of candidates and always
lands on the same accepted campaign — resampling is a search over a deterministic, seeded
sequence, not a source of nondeterminism.

The rest of this docstring explains the shaping *mechanism* the gate is checking — why it is
designed to pass, not just that it must.

**The trick is a broken correlation, not a big number.** In the benign corpus, elevated
`bytes_out_sum` almost always co-occurs with `automation_ua_ratio` near 1 and `off_hours_ratio`
elevated — that is what a heavy uploader looks like, because heavy uploaders are service
accounts and backup jobs (docs/11 "Simulated org"). Calibrating the injected volume against that
service-account population (a flat "modest for automation" constant) is not enough: docs/04's L3
feature list keys `bytes_out_z_vs_own` on the *victim's own* per-hour history, and a human's own
hourly outbound bytes are nothing like a service account's — so this scenario sizes each upload
against the *victim's own* historical `(principal, hour)` `bytes_out_sum` distribution
(`_victim_hourly_budget`), not a corpus-wide or service-account-shaped constant. Every injected
addition stays within a small, fixed number of the victim's own MAD-widths, so `bytes_out_z_vs_own`
computed against that same population never trips — but it still arrives through the victim's own
browser, on their own device, at a human's request cadence, which is a pairing that has no
support in the training manifold even though every coordinate taken alone sits inside the
population's normal range. Only a model that reconstructs the *joint* distribution notices.

Concretely, four properties are load-bearing and none of them is negotiable by a difficulty knob:

* **The destination is a SaaS app the org already runs and this org's users already visit.**
  Not rare, not newly registered, not uncategorized — so `signal.rarity` and
  `signal.newly_registered_domain` have nothing to key on.
* **Per-upload size stays in ordinary attachment territory**, well under the L1 "large POST"
  threshold (docs/04, 10 MB) *and* capped to the victim's own historical per-hour
  `bytes_out_sum` envelope for the *specific hour it lands in* (`_hourly_budget_stats` /
  `_victim_hourly_totals`), so `bytes_out_z_vs_own` — an explicit L3 feature (docs/04) — stays
  quiet against that same victim's own history, not just the org-wide population. Capping only
  the *increment* is not enough: an hour that already carries some of the victim's own ordinary
  traffic would push the *total* for that hour over budget even though the injected addition
  alone looked safe, so the budget is spent against each landed hour's actual running total.
* **Timing is drawn from the victim's own diurnal curve**, not a fixed period — a metronomic
  drip would itself be a beacon, and beaconing is a different scenario's job (#1). At most one
  upload lands per `(principal, hour)` bucket, and never one already claimed by a natural or
  shaped event (`_select_campaign_timestamps`), so two draws never stack their bytes into the
  same window the per-hour cap is sized for.
* **Cumulative volume is real** — this is not a decoy, data actually leaves — but spread thin
  enough over `duration_days`, and capped low enough per hour, that no single entity-hour window
  carries a share of it big enough to read as anomalous against that entity's own baseline.

**A fifth property, added after an independent audit found the scenario still leaked on four of
six marginal features:** the victim's own *pre-campaign* benign history has to actually contain
POST traffic and off-hours activity, not just look for it. A pure light-browsing human has
`MAD == 0` on `post_ratio` and `off_hours_ratio` in real generated output — the org-wide POST
rate the benign corpus produces is ~3.5% of events, too thin for any human's hourly post_ratio to
clear even a bare-majority-nonzero threshold on its own (verified against real generated output,
not assumed) — so a single injected upload is an infinite-MAD-width outlier by construction, not
because the campaign is actually anomalous. The same flat history collapses `out_in_ratio` (a
browsing user's benign ratio is tiny and near-constant) and leaves `bytes_out_z_vs_own` thinner
than the increment-only cap assumed. `_shape_victim_baseline` establishes, with events labelled
`malicious=False` before the campaign is laid down, that this victim already regularly uses
`host` for both browsing and modest uploads, sometimes in the evening — a real SaaS-upload habit,
which is a far better exfil victim profile than a pure browser, and considerably more realistic.

Only `ml.autoencoder` is in `expected_detectors`. Claiming any L1/L2 detector here would be
lying about what this file tests.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

import numpy as np

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
from datagen.emitters.zscaler import UrlCategory, ZScalerEmitter, categorize
from datagen.scenarios import register_scenario
from datagen.types import (
    ML_AUTOENCODER,
    EntityRef,
    EventRecord,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
    TimeWindow,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["LowAndSlowAcceptanceError", "LowAndSlowExfilScenario"]


class LowAndSlowAcceptanceError(RuntimeError):
    """No candidate campaign satisfied docs/11 row 8's acceptance gate within `max_attempts`
    resample rounds for this scenario instance's seed.

    Scenario 8 exists specifically to test whether `ml.autoencoder` earns its slot (docs/11): a
    campaign detectable by a single marginal feature, or invisible to the joint distribution too,
    would make that benchmark measure nothing. A loud failure here — naming exactly which
    criterion failed, and on which attempt — is the correct outcome; silently emitting an invalid
    scenario 8 would corrupt every eval number downstream of it instead.
    """


_STORAGE_CATEGORIES: Final[tuple[str, ...]] = ("storage", "cloud", "productivity")

# docs/04's L2 volumetric-burst robust z (`0.6745 * (x - median) / MAD`) flags `|z| > 3.5`.
# `bytes_out_z_vs_own` (L3) is the same "own-history" shape applied per `(principal, hour)`, so
# every injected upload is capped to stay within this many of the victim's own MAD-widths --
# comfortably under 3.5 even if it lands on an hour that was already on the high side of that
# victim's normal range.
_OWN_HISTORY_Z_BUDGET: Final[float] = 1.5
# Floor so a victim with a near-silent (or empty) own history still gets a nonzero drip rather
# than the cap collapsing to ~0 bytes.
_MIN_SAFE_UPLOAD_BYTES: Final[float] = 2_000.0

# `DiurnalCurve.night_floor` (0.03 by default) means the raw sampler can and does draw genuinely
# nocturnal timestamps. This scenario's whole premise is "no single feature (here, off_hours_ratio)
# out of range", so uploads are rejection-sampled above this weight rather than left to the curve's
# unrestricted tail -- the ground-truth notes below assert this as a guarantee, not a tendency.
_WORK_HOURS_FLOOR: Final[float] = 0.1
_MAX_SAMPLE_ROUNDS: Final[int] = 25

# Ordinary attachment/document sizes, in decimal KB. `max_upload_kb` is the hard cap on any
# single draw — kept an order of magnitude under the L1 large-POST rule's 10 MB threshold
# (docs/04) so no jittered tail sample can accidentally trip it.
_BYTES_PER_KB: Final[int] = 1_000
# The campaign's own upload acks are *not* drawn from this range — see `_hourly_ratio_stats` and
# `_MIN_SAFE_RATIO` in `inject`. This range is only for `_shape_victim_baseline`'s POST events,
# where a realistic small upload-API response is all that is needed.
_ACK_BYTES: Final[tuple[int, int]] = (150, 800)
_OK_CODES: Final[tuple[int, ...]] = (200, 201)
_OK_WEIGHTS: Final[tuple[float, ...]] = (0.4, 0.6)
# Floor under which an ack would stop reading as a plausible HTTP response at all.
_MIN_ACK_BYTES: Final[int] = 80
# Floor for `target_ratio` in `inject` — guards the `body / target_ratio` division and keeps a
# victim with (as yet) no upload-shaped history at all from dividing by something near zero.
_MIN_SAFE_RATIO: Final[float] = 0.05

# ---------------------------------------------------------------------------- baseline shaping
#
# `_shape_victim_baseline` establishes the victim's pre-campaign SaaS-upload habit. Every knob
# below was chosen empirically against real generated output (see the module docstring's "fifth
# property"), not derived from a formula — median/MAD are order-statistics, not smooth functions,
# so "how much shaping is enough" has to be checked against actual data, which
# `tests/test_datagen_s08_marginals.py` does on every run.
#
# Fraction of the victim's *existing* active hours that get one extra same-hour touch. Not 1.0:
# a handful of genuinely POST-free hours is more realistic than a suspiciously uniform habit, and
# the org-wide natural POST rate already supplies a little of its own variety.
_BASELINE_POST_TOUCH_PROB: Final[float] = 0.85
# Within a touched natural hour, how often the extra event is a POST rather than a GET — high
# enough that post_ratio clears zero almost everywhere without every touched hour reading as
# 100% POST, which would just trade one degenerate constant for another.
_BASELINE_POST_PROB: Final[float] = 0.7
# Standalone off-hours/boundary sessions are overwhelmingly POST, unlike a touched natural hour:
# a touch shares its bucket with whatever browsing was already there, so its own method barely
# moves that bucket's out_in_ratio, but a standalone session's bucket has nothing else in it —
# diluting it with GET responses (large, browsing-shaped) would pull the *whole population's*
# out_in_ratio back down toward "browsing user", undoing the reason this sub-shape exists.
_BASELINE_STANDALONE_POST_PROB: Final[float] = 0.92
# Standalone off-hours sessions kept this far clear of the work-hours boundary so a session's own
# few-minute internal spread never straddles back into business hours by accident.
_BASELINE_OFF_HOURS_MARGIN_H: Final[float] = 0.5
# Boundary-mixed sessions (some on-hours events, some off-hours events, same bucket) are what
# actually gives off_hours_ratio variance: a purely binary 0/1 population's median and MAD
# collapse together almost regardless of the on/off split (whichever value is a plurality
# supplies both the median and a matching zero-deviation majority), verified numerically while
# designing this fix. `_BASELINE_MIXED_MIN` floors this even for an otherwise-silent victim.
_BASELINE_MIXED_MIN: Final[int] = 8
_BASELINE_MIXED_DIVISOR: Final[int] = 4
# Safety margin added on top of exact on/off parity — see the `n_off` computation in
# `_shape_victim_baseline` for why exact parity is fragile.
_BASELINE_OFF_MARGIN: Final[int] = 3
_BASELINE_SESSION_MAX_EVENTS: Final[int] = 3
# Shaped-baseline upload sizing is deliberately its own small, fixed range rather than derived
# from `mean_upload_kb`/`max_upload_kb` — those are the *campaign's* difficulty knobs, and tying
# shaping to them would make a harder-campaign sweep silently also resize the baseline. A shaped
# POST's mean size is a fraction of `post_scale_bytes` (`inject`'s natural-history
# `safe_total`-equivalent), not a flat KB constant — see `_emit_baseline_event`'s docstring.
_BASELINE_UPLOAD_SCALE: Final[float] = 0.6

# `_pick_victim`'s activity-weight window (org.py: log-normal, median 1.0). A victim below this
# has too thin a natural history for any shaping to look established -- both because there is
# too little of it to carry real per-feature variance, and because a small benign sample makes
# even a genuinely-separating joint distribution's own p95 too noisy a threshold to reliably
# clear. A victim above it has so much natural browsing volume that even generously-sized shaping
# cannot move out_in_ratio's population enough to cover the campaign's own range (both verified
# against real generated output for several victims while designing this fix — a very heavy
# user's natural on-hours count runs into the shaping loops' own collision-avoidance capacity,
# capping how much a bigger multiplier can help).
_VICTIM_ACTIVITY_MIN: Final[float] = 0.75
_VICTIM_ACTIVITY_MAX: Final[float] = 2.2

# ---------------------------------------------------------------------------- acceptance gate
#
# docs/11 row 8's three properties, enforced as a postcondition of `inject` rather than hoped for
# from the shaping constants above. `_check_acceptance` re-derives each candidate's own
# entity-window feature vectors independently of the shaping logic that produced it (the same way
# `tests/test_datagen_s08_marginals.py` audits the accepted result independently of both) and
# rejects, rather than tunes around, whatever it finds.

# docs/04 L2's volumetric-burst threshold, reused verbatim: criterion (a)'s bar for "no single
# feature's marginal robust z fires on an attack hour".
_ACCEPT_Z_THRESHOLD: Final[float] = 3.5
# Criterion (c): the fraction of attack hours that must sit above the victim's own benign p95
# Mahalanobis distance for the joint distribution to still count as separating the campaign.
_ACCEPT_JOINT_MIN_SEPARATION: Final[float] = 0.70
# A request large enough that it would only ever fire on a genuine outlier -- an order of
# magnitude above anything either the campaign's own per-hour budget or the shaped baseline emits
# (both are sized in the tens of KB) and comfortably under the L1 "large POST" rule's 10 MB
# (docs/04), so this never trips on the ordinary traffic either side of this scenario produces.
_GATE_LARGE_UPLOAD_BYTES: Final[int] = 1_000_000
# Below this many benign (principal, hour) buckets, percentiles and a 7x7 covariance are too
# noisy to score criterion (c) meaningfully -- reject and resample a more active victim rather
# than accept (or reject) on a statistic that is mostly sampling noise.
_MIN_BENIGN_HOURS_FOR_GATE: Final[int] = 20
# Heavy-tailed columns (the natural corpus genuinely contains occasional large-download browsing
# hours) log1p'd before standardizing in `_mahalanobis`, so one wild benign hour cannot inflate
# that column's scale enough to wash out the other six -- the same reason docs/04 specifies a
# *robust* covariance (MCD) for `ml.mahalanobis` rather than a plain sample covariance.
_LOG_GATE_FEATURES: Final[frozenset[str]] = frozenset(
    {
        FEATURE_N_EVENTS,
        FEATURE_BYTES_OUT,
        FEATURE_BYTES_IN,
        FEATURE_OUT_IN_RATIO,
        FEATURE_N_LARGE_UPLOADS,
    }
)
# Generous by default (docs/11 "Parameterization": every scenario takes difficulty/robustness
# knobs). Each rejected attempt is cheap -- no benign-corpus regeneration, just one candidate
# campaign's worth of shaping and injection -- so a high default costs little on the seeds that
# need it and nothing at all on the (common) seeds that accept on the first or second attempt.
_DEFAULT_MAX_ATTEMPTS: Final[int] = 50


@dataclass(frozen=True, slots=True)
class _HostProfile:
    """How the benign corpus already renders this host.

    Injected rows copy category/app/risk from a real benign line for the same host, so the only
    thing that distinguishes an injected row from a routine upload to the same SaaS app is the
    thing the scenario is actually testing — not an incidental column drift.
    """

    category: UrlCategory
    appname: str
    riskscore: int


def _host_profile(stream: Sequence[EventRecord], host: str) -> _HostProfile:
    for record in stream:
        fields = record.fields
        if record.malicious or fields.get("host") != host or fields.get("action") != "Allowed":
            continue
        return _HostProfile(
            category=UrlCategory(
                name=str(fields["urlcategory"]),
                supercategory=str(fields["urlsupercategory"]),
                appclass=str(fields["appclass"]),
                risk=int(fields.get("riskscore", 0)),
            ),
            appname=str(fields.get("appname", "General Browsing")),
            riskscore=int(fields.get("riskscore", 0)),
        )
    fallback = categorize(host)
    return _HostProfile(category=fallback, appname="General Browsing", riskscore=fallback.risk)


@register_scenario
class LowAndSlowExfilScenario(Scenario):
    key = "low_and_slow_exfil"
    technique = "T1567"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (ML_AUTOENCODER,)
    description = (
        "Trickle uploads to a familiar SaaS app, sized and timed to stay under every "
        "per-feature threshold; only the joint distribution is anomalous."
    )

    def __init__(
        self,
        *,
        duration_days: float = 9.0,
        n_uploads: int = 30,
        mean_upload_kb: float = 900.0,
        upload_sigma: float = 0.4,
        max_upload_kb: float = 6_000.0,
        start_fraction: float = 0.05,
        host_app: str | None = None,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if duration_days <= 0:
            raise ValueError("duration_days must be > 0")
        if n_uploads < 1:
            raise ValueError("n_uploads must be >= 1")
        if mean_upload_kb <= 0 or max_upload_kb <= 0:
            raise ValueError("mean_upload_kb and max_upload_kb must be > 0")
        if upload_sigma <= 0:
            raise ValueError("upload_sigma must be > 0")
        if max_upload_kb < mean_upload_kb:
            raise ValueError("max_upload_kb must be >= mean_upload_kb")
        if not 0.0 <= start_fraction < 1.0:
            raise ValueError("start_fraction must be in [0, 1)")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

        self.duration_days = float(duration_days)
        self.n_uploads = int(n_uploads)
        self.mean_upload_kb = float(mean_upload_kb)
        self.upload_sigma = float(upload_sigma)
        self.max_upload_kb = float(max_upload_kb)
        self.start_fraction = float(start_fraction)
        self.host_app = host_app
        # Resample-until-accept bound for the docs/11 row 8 acceptance gate (module docstring) --
        # a robustness knob, not a difficulty one: it does not change what the campaign looks
        # like, only how hard `inject` is willing to search for a victim/placement it can prove
        # satisfies the gate before giving up and raising `LowAndSlowAcceptanceError`.
        self.max_attempts = int(max_attempts)

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        """Resample victim/placement until a candidate satisfies the docs/11 row 8 acceptance
        gate (module docstring), or raise `LowAndSlowAcceptanceError` after `max_attempts`.

        Every attempt is keyed off `ctx.rng.substream(f"attempt:{attempt}")`, so a given seed
        always tries the same sequence of candidates in the same order and always lands on the
        same accepted campaign — resampling is deterministic search, not a nondeterminism leak.
        A rejected candidate's events (campaign *and* the baseline shaping laid down for it) are
        rolled back from `ctx.stream`/`ctx.injected` in full before the next attempt, so a failed
        attempt never leaks into either the final corpus or the next candidate's own history.
        """
        stream_floor = len(ctx.stream)
        injected_floor = len(ctx.injected)
        rejections: list[str] = []

        for attempt in range(self.max_attempts):
            attempt_rng = ctx.rng.substream(f"attempt:{attempt:03d}")
            victim = self._pick_victim(ctx, attempt_rng.substream("victim"))
            # Keyed by attempt *and* victim, not victim alone: a weighted redraw can land on the
            # same victim twice, and this still has to produce a different placement rather than
            # silently replaying the exact rejected candidate.
            rng = attempt_rng.substream(f"campaign:{victim.key}")

            ground_truth, rejection = self._attempt_campaign(ctx, rng, victim)
            if rejection is None:
                return ground_truth

            rejections.append(f"attempt {attempt} victim={victim.principal}: {rejection}")
            del ctx.stream[stream_floor:]
            del ctx.injected[injected_floor:]

        raise LowAndSlowAcceptanceError(
            f"{ctx.scenario_id}: no candidate campaign satisfied the docs/11 row 8 acceptance "
            f"gate (rng={ctx.rng!r}) within {self.max_attempts} attempts:\n"
            + "\n".join(f"  - {r}" for r in rejections)
        )

    def _attempt_campaign(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User
    ) -> tuple[GroundTruth, str | None]:
        """Build one candidate campaign for `victim` and score it against `_check_acceptance`.

        Returns `(ground_truth, None)` if the candidate is accepted, or `(ground_truth, reason)`
        if rejected — the caller discards the ground truth and rolls back every event this
        attempt added to `ctx.stream`/`ctx.injected` when `reason` is not `None`.
        """
        emitter = ZScalerEmitter()

        host = self._destination(ctx, rng)
        profile = _host_profile(ctx.stream, host)
        referer = f"https://{host}/drive"

        # Establish the victim's own SaaS-upload/evening-activity habit *before* the campaign is
        # laid down, so post_ratio and off_hours_ratio have genuine pre-campaign variance rather
        # than MAD == 0 (see module docstring, "fifth property"). Every event is malicious=False.
        natural_hours = self._natural_active_hours(ctx, victim)
        n_shaped, shaped_hours = self._shape_victim_baseline(
            ctx,
            victim,
            rng,
            host=host,
            profile=profile,
            referer=referer,
            natural_hours=natural_hours,
        )

        campaign = ctx.window.subwindow(
            start_fraction=self.start_fraction, hours=self.duration_days * 24.0
        )
        # Drawn from the victim's own diurnal curve (docs/11 "Diurnal activity"), so cadence
        # follows their normal working pattern rather than a fixed period — a regular drip would
        # itself read as a beacon, which is a different scenario's job. Rejection-sampled above
        # `_WORK_HOURS_FLOOR` so `off_hours_ratio` is actually pinned near zero, not merely usually
        # low (see module docstring and `_sample_work_hours_timestamps`).
        #
        # Every upload lands in an hour with *nothing else* in it — not a natural hour, not a
        # shaped one. A natural hour can carry an ordinary video or large-download browsing spike
        # (real corpus traffic, verified against real generated output while designing this fix);
        # sharing a bucket with one would make that hour's bytes_in/out_in_ratio/n_events reflect
        # the coincidence, not the upload, and no per-upload budget can correct for a coincidence.
        timestamps = self._select_campaign_timestamps(
            ctx, rng, victim, campaign, self.n_uploads, avoid=set(natural_hours) | shaped_hours
        )

        # Sized against the *victim's own* historical per-hour `bytes_out_sum` total for the
        # specific hour each upload lands in (not just a flat increment budget), computed after
        # shaping so the newly-established baseline is already part of the population that
        # `bytes_out_z_vs_own` (docs/04 L3) would be computed against.
        hourly_totals = self._victim_hourly_totals(ctx, victim)
        median, mad = self._hourly_budget_stats(hourly_totals)
        safe_total = max(
            median + _OWN_HISTORY_Z_BUDGET * mad / 0.6745 if mad > 0 else median * 3.0,
            _MIN_SAFE_UPLOAD_BYTES,
        )

        # out_in_ratio (docs/04 L3) is a *ratio* of two sums, not a sum itself — capping
        # bytes_out alone does not bound it, because bytes_in (the ack) is independent. Rather
        # than hoping the shaped population happens to land wherever the campaign's own bytes_out
        # falls (tuning that by volume alone hit a hard capacity ceiling for heavier victims,
        # verified against real generated output while designing this fix), size each upload's
        # ack directly so *its own* ratio lands within budget of the population's, the same
        # mechanism `safe_total` already applies to bytes_out.
        ratio_median, ratio_mad = self._hourly_ratio_stats(ctx, victim)

        injected: list[EventRecord] = []
        off_hours = 0
        for ts in timestamps:
            clamped = ctx.window.clamp(ts)
            # `_select_campaign_timestamps` guarantees this in the common case, but recheck the
            # weight that actually lands in the log rather than trust it unconditionally.
            if ctx.models.diurnal.weight(clamped, victim.work_hours) <= _WORK_HOURS_FLOOR:
                off_hours += 1
            hour = clamped.replace(minute=0, second=0, microsecond=0)
            existing = hourly_totals.get(hour, 0)
            budget_left = max(safe_total - existing, _MIN_SAFE_UPLOAD_BYTES)
            mean_bytes = min(self.mean_upload_kb * _BYTES_PER_KB, budget_left)
            max_bytes = min(self.max_upload_kb * _BYTES_PER_KB, budget_left)
            mu = math.log(max(mean_bytes, _MIN_SAFE_UPLOAD_BYTES)) - self.upload_sigma**2 / 2.0
            body = int(min(rng.lognormal(mu, self.upload_sigma), max_bytes))
            hourly_totals[hour] = existing + body

            if ratio_mad > 0:
                target_ratio = ratio_median + rng.uniform(-0.2, 0.6) * (
                    _OWN_HISTORY_Z_BUDGET * ratio_mad / 0.6745
                )
            else:
                target_ratio = ratio_median
            # A downward jitter large enough to push `target_ratio` near zero would make `ack`
            # (`body / target_ratio`) blow up — the asymmetric jitter range above already leans
            # this away from zero, and the floor below (a fraction of the population's own
            # median, not just an absolute epsilon) keeps a wide `ratio_mad` from doing it anyway.
            target_ratio = max(target_ratio, ratio_median * 0.5, _MIN_SAFE_RATIO)
            ack = max(int(body / target_ratio), _MIN_ACK_BYTES)

            injected.append(
                emitter.inject(
                    ctx,
                    user=victim,
                    ts=clamped,
                    host=host,
                    src_ip=victim.source_ip(rng),
                    url=f"/api/v3/files/{rng.hex_token(6)}/upload?folder={rng.hex_token(4)}",
                    method="POST",
                    status=rng.weighted_choice(_OK_CODES, _OK_WEIGHTS),
                    bytes_out=body,
                    bytes_in=ack,
                    category=profile.category,
                    appname=profile.appname,
                    riskscore=profile.riskscore,
                    referer=referer,
                )
            )

        rejection = self._check_acceptance(ctx, victim, injected)
        if rejection is not None:
            # Discarded by the caller (`inject` rolls this whole attempt back), so there is no
            # value in spending more effort on `notes` than a placeholder.
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), rejection

        uploaded = sum(int(r.fields["requestsize"]) for r in injected)
        hours_note = (
            "every upload inside the victim's own working hours"
            if off_hours == 0
            else f"{off_hours}/{len(injected)} uploads landed off the victim's usual hours"
        )
        ground_truth = self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"{victim.username} pushed {uploaded / 1e3:.1f} KB to {host} in "
                f"{len(injected)} uploads over {self.duration_days:.1f}d "
                f"(campaign {campaign.start.isoformat()}..{campaign.end.isoformat()}); "
                f"{hours_note}, own browser UA, own device — each upload's hour capped to "
                f"{safe_total:.0f} bytes total ({_OWN_HISTORY_Z_BUDGET:.1f} own-history "
                f"MAD-widths above median={median:.0f}/MAD={mad:.0f}); {n_shaped} benign "
                f"(malicious=False) baseline events establish {victim.username} as a regular "
                f"{host} POST/upload user with real evening activity, so post_ratio and "
                "off_hours_ratio carry genuine pre-campaign variance; verified against the "
                "docs/11 row 8 acceptance gate (module docstring)"
            ),
        )
        return ground_truth, None

    # ------------------------------------------------------------------ acceptance gate

    def _check_acceptance(
        self, ctx: ScenarioContext, victim: User, injected: Sequence[EventRecord]
    ) -> str | None:
        """docs/11 row 8's acceptance gate, run as a postcondition of this candidate's generation.

        Re-derives the victim's own entity-window feature vectors independently of the shaping
        logic that produced them — the same in-memory `EventRecord`s, but bucketed and scored
        fresh, the same way `tests/test_datagen_s08_marginals.py` re-derives them from the
        written file to audit the accepted result independently a second time.

        Checks, in the order that gives the clearest rejection reason:

          (b) the benign population has genuine MAD on `post_ratio`/`off_hours_ratio` — checked
              *before* (a) because (a) passing against a zero-spread population is meaningless,
              not reassuring (see `app.detection.features.robust_z`'s MAD==0 policy);
          (a) no single docs/04 L3 feature's marginal robust z exceeds `_ACCEPT_Z_THRESHOLD` on
              any attack hour;
          (c) the joint (Mahalanobis) distribution separates at least
              `_ACCEPT_JOINT_MIN_SEPARATION` of attack hours above the benign p95.

        Returns `None` if all three hold, otherwise a reason string naming exactly which
        criterion failed and by how much.
        """
        attack_records = [r for r in injected if r.malicious]
        if not attack_records:
            return "no malicious events were generated for this candidate"

        benign_buckets = self._bucket_zscaler_records(ctx, victim)
        if len(benign_buckets) < _MIN_BENIGN_HOURS_FOR_GATE:
            return (
                f"only {len(benign_buckets)} benign (principal, hour) buckets available "
                f"(< {_MIN_BENIGN_HOURS_FOR_GATE}) — too thin to score the gate against"
            )

        attack_buckets: dict[datetime, list[EventRecord]] = {}
        for record in attack_records:
            bucket = record.ts.replace(minute=0, second=0, microsecond=0)
            attack_buckets.setdefault(bucket, []).append(record)
        if not attack_buckets:
            return "no distinct attack-hour buckets were produced for this candidate"

        benign_feats = {
            hour: self._hourly_gate_features(rows, victim) for hour, rows in benign_buckets.items()
        }
        attack_feats = {
            hour: self._hourly_gate_features(rows, victim) for hour, rows in attack_buckets.items()
        }

        for feature in (FEATURE_POST_RATIO, FEATURE_OFF_HOURS_RATIO):
            values = [f[feature] for f in benign_feats.values()]
            median = statistics.median(values)
            mad = statistics.median([abs(v - median) for v in values])
            if mad == 0:
                return (
                    f"criterion (b): benign {feature} has MAD == 0 "
                    f"(values={sorted({round(v, 3) for v in values})}) — the marginal check in "
                    "(a) cannot fire meaningfully against a zero-spread population"
                )

        offenders: list[str] = []
        for feature in ENTITY_WINDOW_FEATURES:
            benign_values = [f[feature] for f in benign_feats.values()]
            max_z = max(abs(robust_z(benign_values, f[feature])) for f in attack_feats.values())
            if max_z > _ACCEPT_Z_THRESHOLD:
                offenders.append(f"{feature} (max|z|={max_z:.2f})")
        if offenders:
            return f"criterion (a): single-feature marginal(s) fired: {', '.join(offenders)}"

        benign_matrix = np.array(
            [[f[feat] for feat in ENTITY_WINDOW_FEATURES] for f in benign_feats.values()],
            dtype=np.float64,
        )
        attack_matrix = np.array(
            [[f[feat] for feat in ENTITY_WINDOW_FEATURES] for f in attack_feats.values()],
            dtype=np.float64,
        )
        benign_dists = self._mahalanobis(benign_matrix, benign_matrix)
        attack_dists = self._mahalanobis(benign_matrix, attack_matrix)
        benign_p95 = float(np.percentile(benign_dists, 95))
        above = float(np.mean(attack_dists > benign_p95))
        if above < _ACCEPT_JOINT_MIN_SEPARATION:
            return (
                f"criterion (c): joint separation {above:.0%} < "
                f"{_ACCEPT_JOINT_MIN_SEPARATION:.0%} (benign p95={benign_p95:.2f}, attack_p50="
                f"{float(np.percentile(attack_dists, 50)):.2f}, benign_p50="
                f"{float(np.percentile(benign_dists, 50)):.2f})"
            )

        return None

    def _hourly_gate_features(self, rows: Sequence[EventRecord], victim: User) -> dict[str, float]:
        """Per-`(principal, hour)` feature vector for `_check_acceptance` — the same seven
        docs/04 L3 features (`app.detection.features.ENTITY_WINDOW_FEATURES`) the regression test
        audits independently from the emitted file, computed here in-memory off a candidate's own
        records so a failing candidate can be rejected and rolled back before anything is written
        to disk.
        """
        n_events = len(rows)
        bytes_out = sum(int(r.fields.get("requestsize", 0) or 0) for r in rows)
        bytes_in = sum(int(r.fields.get("responsesize", 0) or 0) for r in rows)
        n_post = sum(1 for r in rows if r.fields.get("requestmethod") == "POST")
        n_off = sum(1 for r in rows if is_off_hours(r.ts, victim.work_hours))
        n_large = sum(
            1 for r in rows if int(r.fields.get("requestsize", 0) or 0) >= _GATE_LARGE_UPLOAD_BYTES
        )
        return {
            FEATURE_N_EVENTS: float(n_events),
            FEATURE_BYTES_OUT: float(bytes_out),
            FEATURE_BYTES_IN: float(bytes_in),
            FEATURE_OUT_IN_RATIO: bytes_out / max(bytes_in, 1),
            FEATURE_POST_RATIO: n_post / n_events,
            FEATURE_OFF_HOURS_RATIO: n_off / n_events,
            FEATURE_N_LARGE_UPLOADS: float(n_large),
        }

    @staticmethod
    def _mahalanobis(benign_matrix: np.ndarray, query_matrix: np.ndarray) -> np.ndarray:
        """Mahalanobis distance of each row of `query_matrix` from `benign_matrix`'s own
        distribution — criterion (c)'s joint-separation metric.

        Log1p's the heavy-tailed columns (`_LOG_GATE_FEATURES`; the natural corpus genuinely has
        occasional large-download browsing hours with outsized `bytes_in`) before standardizing
        by `benign_matrix`'s own median/MAD, so one wild benign hour cannot inflate that column's
        scale enough to wash out the other six — the same reason docs/04 specifies a *robust*
        covariance (MCD) for `ml.mahalanobis` rather than a plain sample covariance.
        """
        log_mask = np.array([feat in _LOG_GATE_FEATURES for feat in ENTITY_WINDOW_FEATURES])

        def transform(matrix: np.ndarray) -> np.ndarray:
            out = matrix.copy()
            out[:, log_mask] = np.log1p(out[:, log_mask])
            return out

        benign_t = transform(benign_matrix)
        query_t = transform(query_matrix)

        median = np.median(benign_t, axis=0)
        mad = np.median(np.abs(benign_t - median), axis=0)
        mad[mad == 0] = 1.0
        benign_std = (benign_t - median) / mad
        query_std = (query_t - median) / mad

        cov = np.cov(benign_std, rowvar=False) + np.eye(benign_std.shape[1]) * 1e-6
        inv_cov = np.linalg.pinv(cov)
        return np.sqrt(np.einsum("ij,jk,ik->i", query_std, inv_cov, query_std))

    # ------------------------------------------------------------------ helpers

    def _pick_victim(self, ctx: ScenarioContext, rng: SeededRandom) -> User:
        """A moderately active human — unlike scenario 7, no peer-group model is in play here,
        but not *any* active human works either. `_VICTIM_ACTIVITY_MIN`/`_MAX` exclude both the
        lightest browsers (whose thin history leaves `_shape_victim_baseline` nothing to work
        with) and the heaviest users (whose sheer natural volume outruns what that method can
        realistically add) — see the constants' own docstring.

        `rng` is attempt-scoped (`inject`), not a single fixed `ctx.rng.substream("victim")` draw
        — a rejected candidate's next attempt needs an independent chance at a different victim,
        not a deterministic replay of the same one.
        """
        pool = [
            u
            for u in ctx.org.users
            if _VICTIM_ACTIVITY_MIN <= u.activity_weight <= _VICTIM_ACTIVITY_MAX
        ]
        if not pool:
            pool = list(ctx.org.users)
        return rng.weighted_choice(pool, [u.activity_weight for u in pool])

    def _destination(self, ctx: ScenarioContext, rng: SeededRandom) -> str:
        """A sanctioned SaaS app already in every principal's affinity set (docs/11) — not rare,
        not new, not newly registered, so those three signals have nothing to key on."""
        if self.host_app is not None:
            for app in ctx.org.saas_apps:
                if app.name == self.host_app:
                    return app.domain
            raise KeyError(f"unknown saas app {self.host_app!r} for scenario {self.key}")
        for category in _STORAGE_CATEGORIES:
            candidates = [a.domain for a in ctx.org.saas_apps if a.category == category]
            if candidates:
                return rng.choice(candidates)
        return ctx.models.domains.sample(rng)

    def _sample_work_hours_timestamps(
        self,
        ctx: ScenarioContext,
        rng: SeededRandom,
        victim: User,
        campaign: TimeWindow,
        n: int,
    ) -> list[datetime]:
        """`n` sorted timestamps from the victim's own diurnal curve, rejection-sampled above
        `_WORK_HOURS_FLOOR` *and* strictly inside `[start_h, end_h]` local time.

        The diurnal-weight floor alone is not enough: `DiurnalCurve`'s sigmoid ramps mean a
        timestamp an hour or two outside `[start_h, end_h]` can still clear a weight floor as
        low as 0.1 (verified against real generated output while designing this fix), and a
        single such draw lands in an otherwise-empty campaign hour at `off_hours_ratio == 1.0` —
        a population-maximum value against a benign history whose own off_hours_ratio is a modest
        fraction, not the flat zero this scenario used to assume. The strict bound is the exact
        boundary `off_hours_ratio` itself is scored against
        (`app.detection.features.is_off_hours`), so this is what actually delivers the module
        docstring's "off_hours_ratio ... pinned near zero" guarantee rather than merely a
        usually-low tendency.

        Oversamples each round rather than drawing one-at-a-time -- `DiurnalCurve.night_floor`
        rejects roughly one draw in ten, so a handful of doubling rounds comfortably reaches `n`
        without an unbounded loop.
        """
        accepted: list[datetime] = []
        seen: set[datetime] = set()
        batch = max(n * 2, 8)
        for _ in range(_MAX_SAMPLE_ROUNDS):
            for ts in ctx.models.diurnal.sample_timestamps(
                rng, campaign.start, campaign.end, victim.work_hours, batch
            ):
                if ts in seen:
                    continue
                seen.add(ts)
                if ctx.models.diurnal.weight(
                    ts, victim.work_hours
                ) > _WORK_HOURS_FLOOR and not is_off_hours(ts, victim.work_hours):
                    accepted.append(ts)
            if len(accepted) >= n:
                break
            batch *= 2
        accepted.sort()
        return accepted[:n]

    def _select_campaign_timestamps(
        self,
        ctx: ScenarioContext,
        rng: SeededRandom,
        victim: User,
        campaign: TimeWindow,
        n: int,
        *,
        avoid: set[datetime],
    ) -> list[datetime]:
        """Up to `n` sorted on-hours timestamps, none sharing an `(principal, hour)` bucket with
        `avoid` or with each other.

        Filters an oversampled candidate pool rather than nudging a collision forward to the next
        hour: once `avoid` covers a sizeable chunk of the victim's own on-hours (natural history
        plus this scenario's own shaping), a forward-nudged collision can walk straight through
        the end of the working day and land somewhere genuinely off-hours by `off_hours_ratio`'s
        own definition — reproducing, at a larger scale, the exact mismatch this scenario exists
        to avoid (verified against real generated output while designing this fix). Filtering
        instead only ever keeps candidates the diurnal sampler itself already judged on-hours,
        escalating the oversampling factor rather than falling back to a nudge if the first pass
        comes up short.
        """
        used = set(avoid)
        out: list[datetime] = []
        oversample = 8
        for _ in range(6):
            candidates = self._sample_work_hours_timestamps(
                ctx, rng.fresh(f"select:{oversample}"), victim, campaign, n * oversample
            )
            out = []
            seen = set(used)
            for ts in candidates:
                bucket = ts.replace(minute=0, second=0, microsecond=0)
                if bucket in seen:
                    continue
                seen.add(bucket)
                out.append(ts)
                if len(out) >= n:
                    break
            if len(out) >= n:
                break
            oversample *= 3
        # No forward-nudge fallback: nudging a collision into the next hour is exactly what used
        # to walk uploads past the end of the working day into genuinely off-hours territory
        # (see the docstring above). A victim whose on-hours are so saturated that even this much
        # oversampling cannot find `n` free slots gets fewer, still strictly on-hours, uploads
        # rather than ones that would quietly break the scenario's own off-hours guarantee.
        out.sort()
        return out

    def _natural_active_hours(self, ctx: ScenarioContext, victim: User) -> list[datetime]:
        """Distinct UTC hour buckets the victim already has ZScaler activity in, read *before*
        `_shape_victim_baseline` adds anything — the population that method sizes itself
        against, so the fix scales with how active this particular victim already is rather
        than a flat constant.
        """
        hours: set[datetime] = set()
        for record in ctx.benign_for(victim):
            if record.source is not SourceType.ZSCALER:
                continue
            hours.add(record.ts.replace(minute=0, second=0, microsecond=0))
        return sorted(hours)

    def _victim_hourly_totals(self, ctx: ScenarioContext, victim: User) -> dict[datetime, int]:
        """Per-`(principal, hour)` proxy `bytes_out_sum` from the victim's own (now-shaped)
        benign history — the exact population `bytes_out_z_vs_own` (docs/04 L3) is computed
        against, and what each upload's per-hour budget is spent against.
        """
        hourly: dict[datetime, int] = {}
        for record in ctx.benign_for(victim):
            if record.source is not SourceType.ZSCALER:
                continue
            bucket = record.ts.replace(minute=0, second=0, microsecond=0)
            hourly[bucket] = hourly.get(bucket, 0) + int(record.fields.get("requestsize", 0) or 0)
        return hourly

    def _hourly_budget_stats(self, hourly: dict[datetime, int]) -> tuple[float, float]:
        """Median and MAD of `_victim_hourly_totals`'s values. Falls back to a conservative zero
        baseline for a victim with no proxy history yet, which `_MIN_SAFE_UPLOAD_BYTES` keeps
        from collapsing the campaign to nothing.
        """
        if not hourly:
            return (0.0, 0.0)
        values = sorted(hourly.values())
        median = statistics.median(values)
        mad = statistics.median([abs(v - median) for v in values])
        return (float(median), float(mad))

    def _hourly_ratio_stats(self, ctx: ScenarioContext, victim: User) -> tuple[float, float]:
        """Median and MAD of the victim's own historical per-hour out_in_ratio
        (`bytes_out_sum / bytes_in_sum`) — the population `out_in_ratio` (docs/04 L3) would
        actually be scored against. `inject` uses this to size each upload's own ack so its
        ratio lands within budget directly, rather than relying on the shaped population to
        coincidentally cover wherever the campaign's bytes_out happens to fall.
        """
        buckets = self._bucket_zscaler_records(ctx, victim)
        ratios: list[float] = []
        for records in buckets.values():
            bytes_out = sum(int(r.fields.get("requestsize", 0) or 0) for r in records)
            bytes_in = sum(int(r.fields.get("responsesize", 0) or 0) for r in records)
            ratios.append(bytes_out / max(bytes_in, 1))
        if not ratios:
            return (0.0, 0.0)
        ratios.sort()
        median = statistics.median(ratios)
        mad = statistics.median([abs(v - median) for v in ratios])
        return (float(median), float(mad))

    # ------------------------------------------------------------------ baseline shaping

    def _shape_victim_baseline(
        self,
        ctx: ScenarioContext,
        victim: User,
        rng: SeededRandom,
        *,
        host: str,
        profile: _HostProfile,
        referer: str,
        natural_hours: Sequence[datetime],
    ) -> tuple[int, set[datetime]]:
        """Establish the victim as a genuine, regular user of `host` before the campaign lands.

        Root cause (module docstring, "fifth property"): a victim whose real benign traffic
        never POSTs and never works off-hours has `MAD == 0` on exactly those two L3 features,
        so a single injected upload is an infinite-MAD-width outlier by construction — not
        because the campaign is actually anomalous. Every event this method adds is
        `malicious=False`; it never appears in `malicious_line_numbers` and changes nothing
        about what the campaign itself injects, only what the campaign is measured against.

        Three sub-shapes, all sized off `natural_hours` (measured before this method runs)
        rather than a flat constant:

        * A same-hour POST/GET touch on most of the victim's existing active hours — turns
          `post_ratio` from "almost always exactly zero" into a population with real, varying
          positive values. The org-wide benign POST rate is only ~3.5% of events (verified
          against real generated output), too thin for any human's hourly post_ratio to clear a
          bare-majority-nonzero threshold on its own — median/MAD are order statistics, and the
          modal value (zero) has to actually lose its plurality for MAD to be nonzero.
        * Boundary-mixed sessions (some on-hours events, some off-hours events, in the *same*
          bucket) — what actually gives `off_hours_ratio` variance: a purely binary 0/1
          population's median and MAD collapse together almost regardless of the on/off split
          (verified numerically while designing this fix), so "some off-hours events exist
          somewhere" is not sufficient on its own. Structurally capped at roughly two boundary
          slots per calendar day (there is only one `start_h` hour and one `end_h` hour per day),
          so a very active victim needs the next sub-shape too.
        * Standalone off-hours sessions, sized to close the gap between the boundary-mixed
          capacity and the number of hours that are genuinely "pure on" (natural + touch, with
          neither contributing an off-hours event) — matching that population rather than
          `len(natural_hours)` itself, because `natural_hours` already includes a few genuinely
          off-hours hours from the diurnal curve's own night floor.

        Every sub-shape reserves the UTC hour bucket it lands in and skips a collision rather
        than stacking — two independently-drawn sessions landing in the same hour would inflate
        that single `(principal, hour)` window's own `n_events`/`bytes_out` well past what either
        session was individually sized for, which is exactly the kind of self-inflicted anomaly
        this method exists to avoid.

        Returns `(events_added, shaped_hours)`; `shaped_hours` (the *new* standalone hours from
        the mixed/off sub-shapes, not `natural_hours` itself) is threaded through to the
        campaign's own timestamp sampler so a malicious upload never lands on top of one.
        """
        emitter = ZScalerEmitter()
        shape_rng = rng.substream("baseline-shape")
        added = 0
        reserved: set[datetime] = set(natural_hours)
        shaped_hours: set[datetime] = set()

        # Same formula `inject` uses for the campaign's own `safe_total`, computed here against
        # the victim's *natural* (pre-shaping) bytes_out history — the reference scale every
        # shaped POST's size is pegged to (see `_emit_baseline_event`'s docstring).
        natural_median, natural_mad = self._hourly_budget_stats(
            self._victim_hourly_totals(ctx, victim)
        )
        post_scale_bytes = max(
            natural_median + _OWN_HISTORY_Z_BUDGET * natural_mad / 0.6745
            if natural_mad > 0
            else natural_median * 3.0,
            _MIN_SAFE_UPLOAD_BYTES,
        )

        for i, hour in enumerate(natural_hours):
            srng = shape_rng.substream(f"touch:{i}")
            if not srng.chance(_BASELINE_POST_TOUCH_PROB):
                continue
            method = "POST" if srng.chance(_BASELINE_POST_PROB) else "GET"
            ts = ctx.window.clamp(hour + timedelta(seconds=srng.uniform(0.0, 3599.0)))
            added += self._emit_baseline_event(
                ctx,
                emitter,
                victim,
                srng,
                host=host,
                profile=profile,
                referer=referer,
                ts=ts,
                method=method,
                post_scale_bytes=post_scale_bytes,
            )

        buckets = self._bucket_zscaler_records(ctx, victim)
        pure_on = sum(
            1
            for hour in natural_hours
            if not any(is_off_hours(r.ts, victim.work_hours) for r in buckets.get(hour, ()))
        )
        # Natural hours that *already* carry an off-hours event (the diurnal curve's own night
        # floor) count toward the off-touching side for free — omitting them here undercounts
        # that side and lets off/mixed sessions push it well past parity with `pure_on` (verified
        # against real generated output while designing this fix: for some victims this natural
        # contribution alone was large enough to make off_hours_ratio's population collapse the
        # other way, median 1.0 and MAD 0).
        natural_dirty = len(natural_hours) - pure_on

        # At most ~2 distinct (day, boundary) slots exist per calendar day, so oversampling past
        # that ceiling would only manufacture collisions, not variety.
        mixed_capacity = max(_BASELINE_MIXED_MIN, 2 * int(ctx.window.duration_days))
        n_mixed = min(max(_BASELINE_MIXED_MIN, pure_on // _BASELINE_MIXED_DIVISOR), mixed_capacity)
        # `+ _BASELINE_OFF_MARGIN`, not exact parity: median/MAD are order statistics, so even a
        # single-hour shortfall on the off-touching side (from ordinary collision attrition below)
        # can land the population's median back on the "pure on" plurality and collapse MAD to 0
        # (verified against real generated output while designing this fix — parity computed
        # exactly, with no margin, reproduced this for one victim in three). A small excess is
        # harmless: `off_hours_ratio`'s median landing modestly above zero is still nowhere near
        # `_Z_THRESHOLD` for a population with real spread.
        n_off = max(0, pure_on - n_mixed - natural_dirty) + _BASELINE_OFF_MARGIN

        created = 0
        attempts = 0
        i = 0
        while created < n_mixed and attempts < n_mixed * 8:
            srng = shape_rng.substream(f"mixed:{i}")
            i += 1
            attempts += 1
            to_utc, on_range, off_range = self._sample_boundary_window(ctx, srng, victim)
            bucket = to_utc(on_range[0]).replace(minute=0, second=0, microsecond=0)
            if bucket in reserved:
                continue
            reserved.add(bucket)
            shaped_hours.add(bucket)
            created += 1
            for lo, hi in (on_range, off_range):
                for _ in range(srng.randint(1, 3)):
                    local_h = srng.uniform(lo, hi) if hi > lo else lo
                    ts = ctx.window.clamp(to_utc(local_h))
                    method = "POST" if srng.chance(_BASELINE_STANDALONE_POST_PROB) else "GET"
                    added += self._emit_baseline_event(
                        ctx,
                        emitter,
                        victim,
                        srng,
                        host=host,
                        profile=profile,
                        referer=referer,
                        ts=ts,
                        method=method,
                        post_scale_bytes=post_scale_bytes,
                    )

        created = 0
        attempts = 0
        i = 0
        while created < n_off and attempts < n_off * 16:
            srng = shape_rng.substream(f"off:{i}")
            i += 1
            attempts += 1
            ts0 = self._sample_off_hours_timestamp(ctx, srng, victim)
            bucket = ts0.replace(minute=0, second=0, microsecond=0)
            if bucket in reserved:
                continue
            reserved.add(bucket)
            shaped_hours.add(bucket)
            created += 1
            n_events = srng.randint(1, _BASELINE_SESSION_MAX_EVENTS)
            for j in range(n_events):
                method = "POST" if srng.chance(_BASELINE_STANDALONE_POST_PROB) else "GET"
                event_ts = ctx.window.clamp(ts0 + timedelta(seconds=j * srng.uniform(5.0, 45.0)))
                added += self._emit_baseline_event(
                    ctx,
                    emitter,
                    victim,
                    srng,
                    host=host,
                    profile=profile,
                    referer=referer,
                    ts=event_ts,
                    method=method,
                    post_scale_bytes=post_scale_bytes,
                )

        return added, shaped_hours

    def _bucket_zscaler_records(
        self, ctx: ScenarioContext, victim: User
    ) -> dict[datetime, list[EventRecord]]:
        """The victim's own benign ZScaler records, grouped by UTC hour bucket — one pass over
        `ctx.benign_for(victim)`, reused by every classification `_shape_victim_baseline` needs
        rather than re-scanning the stream per hour.
        """
        buckets: dict[datetime, list[EventRecord]] = {}
        for record in ctx.benign_for(victim):
            if record.source is not SourceType.ZSCALER:
                continue
            buckets.setdefault(record.ts.replace(minute=0, second=0, microsecond=0), []).append(
                record
            )
        return buckets

    def _emit_baseline_event(
        self,
        ctx: ScenarioContext,
        emitter: ZScalerEmitter,
        victim: User,
        rng: SeededRandom,
        *,
        host: str,
        profile: _HostProfile,
        referer: str,
        ts: datetime,
        method: str,
        post_scale_bytes: float,
    ) -> int:
        """One `malicious=False` baseline event.

        `post_scale_bytes` — not a flat constant — is what keeps a shaped POST's size in the same
        ballpark as the campaign's *own* per-hour upload budget (`safe_total` in `inject`),
        computed off the victim's natural (pre-shaping) `bytes_out` history the same way. A flat
        size across every victim regardless of how active they are left out_in_ratio's population
        mismatched for heavier users, whose own campaign budget (and therefore upload size) scales
        with their history (verified against real generated output for multiple victims while
        designing this fix).
        """
        if method == "POST":
            mean_bytes = max(_BASELINE_UPLOAD_SCALE * post_scale_bytes, _MIN_SAFE_UPLOAD_BYTES)
            mu = math.log(mean_bytes) - self.upload_sigma**2 / 2.0
            cap = max(post_scale_bytes, _MIN_SAFE_UPLOAD_BYTES)
            body = int(min(rng.lognormal(mu, self.upload_sigma), cap))
            bytes_in = rng.randint(*_ACK_BYTES)
            url = f"/api/v3/files/{rng.hex_token(6)}/upload?folder={rng.hex_token(4)}"
        else:
            # A deliberately small, tightly-bounded range rather than `ResponseSizeModel`'s
            # heavy-tailed "api" kind (sigma=1.4): that model's own tail can land an order of
            # magnitude above a shaped POST's ack-sized response, which would just trade the
            # out_in_ratio mismatch this method exists to fix for a new one in the other
            # direction — a browsing-style check-in should stay unobtrusive, not occasionally
            # dwarf the campaign's own uploads.
            body = rng.randint(200, 1500)
            bytes_in = rng.randint(400, 6000)
            url = f"/drive/view/{rng.hex_token(6)}"
        emitter.inject(
            ctx,
            user=victim,
            ts=ts,
            host=host,
            src_ip=victim.source_ip(rng),
            url=url,
            method=method,
            status=rng.weighted_choice(_OK_CODES, _OK_WEIGHTS),
            bytes_out=body,
            bytes_in=bytes_in,
            category=profile.category,
            appname=profile.appname,
            riskscore=profile.riskscore,
            referer=referer,
            malicious=False,
        )
        return 1

    def _sample_off_hours_timestamp(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User
    ) -> datetime:
        """A timestamp comfortably outside `[start_h, end_h]` local time, anywhere in the
        overnight/evening span, on a random day in the full scenario window (not just the
        campaign) — this is the victim's ordinary evening habit, not part of the attack.
        """
        hours = victim.work_hours
        margin = _BASELINE_OFF_HOURS_MARGIN_H
        span = max(24.0 - (hours.end_h - hours.start_h) - 2.0 * margin, 1.0)
        local_h = (hours.end_h + margin + rng.uniform(0.0, span)) % 24.0
        day_offset = rng.uniform(0.0, ctx.window.duration_days)
        base_midnight = (ctx.window.start + timedelta(days=day_offset)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        ts = base_midnight + timedelta(hours=local_h - hours.tz_offset_h)
        return ctx.window.clamp(ts)

    def _sample_boundary_window(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User
    ) -> tuple[Callable[[float], datetime], tuple[float, float], tuple[float, float]]:
        """A UTC-hour bucket that straddles the victim's `start_h` or `end_h` boundary, on a
        random day, plus the on-hours and off-hours local-time sub-ranges within that *same*
        bucket. `_shape_victim_baseline` places events in both sub-ranges so the bucket's own
        `off_hours_ratio` is a genuine fraction, not 0 or 1 — see that method's docstring for why
        this is the property that actually gives the feature variance.
        """
        hours = victim.work_hours
        is_start = rng.chance(0.5)
        boundary_h = hours.start_h if is_start else hours.end_h
        bucket_lo = float(math.floor(boundary_h))
        bucket_hi = bucket_lo + 1.0
        on_range, off_range = (
            ((boundary_h, bucket_hi), (bucket_lo, boundary_h))
            if is_start
            else ((bucket_lo, boundary_h), (boundary_h, bucket_hi))
        )
        day_offset = rng.uniform(0.0, ctx.window.duration_days)
        base_midnight = (ctx.window.start + timedelta(days=day_offset)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        def to_utc(local_h: float) -> datetime:
            return base_midnight + timedelta(hours=local_h - hours.tz_offset_h)

        return to_utc, on_range, off_range
