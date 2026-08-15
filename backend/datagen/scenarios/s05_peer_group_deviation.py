"""Scenario 5 — peer-group deviation (docs/11 row 5, T1078).

A user adopts a *different department's* behaviour profile. The premise, verbatim from docs/11:
every feature sits **inside the org-wide distribution**; only comparison against the user's own
department cohort reveals it. Concretely: a member of one department (its home department) spends
a sustained run of hours browsing dev-shaped domains and API endpoints, at a diurnal shape and
volume level modelled on a real member of another department (its target department, fixed to
"Engineering" — always present, since `DEFAULT_DEPARTMENTS` in `datagen/org.py` orders it first
and it survives every `n_departments` truncation `Org` supports) — all of which is perfectly
ordinary for an actual Engineering employee, because the org-wide population this scenario is
checked against genuinely contains ~90 of them (default org) doing exactly this, every day.

Two pre-registered claims this scenario exists to test (docs/12 prediction 2): `ml.peer_group`
(the cohort-relative features and — per docs/04's "Peer-group cohorts" section — LOF, which
"is, in effect, a formalization of the `ml.peer_group` model") detects it; the four *global* L3
models (Isolation Forest, Mahalanobis, ECOD, Autoencoder) do not, because none of them segment by
cohort — they see one org-wide population, and Engineering's genuine traffic already occupies the
exact region of feature space this campaign lands in.

**Why the acceptance gate does not use a single flat "6 features x org-wide marginal z" check,
and why that is not a shortcut.** An early design checked marginal robust-z (docs/04,
`0.6745*(x-median)/MAD`) against the org-wide population for a feature set naturally including
`dev_domain_ratio`, `post_ratio` and `n_unique_domains` alongside volume. Verified against real
generated output (250-user default org, seed 7, 50k-event eval file): all three are structurally
degenerate at the org-wide level regardless of this scenario — `post_ratio` and `dev_domain_ratio`
are exactly zero in >80% of every entity's own hourly buckets org-wide (median 0, **MAD 0**), and
`n_unique_domains` is 1 in the modal bucket (also MAD 0), because most human browsing hours are a
single page-load cluster to a single host. Per `robust_z`'s explicit MAD==0 policy (`app.detection
.features`), *any* nonzero value against a zero-spread population reads as an infinite z — which
would flag a genuine Engineering employee's own ordinary dev-heavy hour exactly as hard as this
scenario's campaign, proving the check measures nothing about this scenario specifically. So the
gate instead does what a real detector suite actually does: check the *well-behaved* volume/size
features on the marginal, and check the *whole* feature vector (domain composition included) on
the joint distribution (Mahalanobis, which standardizes degenerate columns to a `MAD == 0 -> 1.0`
fallback scale rather than blowing up, the same convention `s04_low_and_slow_exfil.py`'s own
`_mahalanobis` helper uses) — twice: once against the org-wide population (must **not** separate,
proving global joint methods are blind too, not just their marginals) and once against the home
department's own population (must separate clearly, proving the cohort-relative view is not).

Three criteria, checked in this order, mirroring `s04_low_and_slow_exfil.py`'s
`_check_acceptance` discipline — verify by construction, resample a fresh victim/exemplar/timing
on failure, raise loudly if no candidate within `max_attempts` clears all three:

  (a) no single *well-behaved* marginal feature (`n_events`, `bytes_out`, `bytes_in` — the three
      with genuine, non-degenerate org-wide spread, verified above) has |robust z| > 3.5 against
      the org-wide population on any campaign hour;
  (b) the *joint* (Mahalanobis, all six features) distance of campaign hours against the org-wide
      population separates only weakly — at most 35% of campaign hours sit above the org-wide
      population's own benign p95, i.e. a global joint model would mostly not flag it either;
  (c) the *joint* distance of campaign hours against the home department's own population
      separates clearly — at least 70% of campaign hours sit above the cohort's own benign p95.

**Timing is deliberately kept inside the victim's own on-hours window.** `off_hours_ratio` (the
canonical `is_off_hours`, per-user local time) is *also* structurally degenerate org-wide (verified
the same way: median 0, MAD 0, since the large majority of any entity's own hourly buckets are, by
construction, hours that entity is normally active in) — including it in criterion (a) would make
the gate unsatisfiable by any campaign that ever touches an off-hours bucket, for the same reason
`post_ratio` was excluded. Rather than lean on that degeneracy, campaign timestamps are drawn from
the *target-department exemplar's* diurnal shape but rejection-filtered to stay inside the
*victim's own* `[start_h, end_h]` — so `off_hours_ratio` for the victim never moves off its usual
near-zero value, and the "different diurnal shape" claim rests on the exemplar's own start/end/
phase-shift genuinely differing from the victim's (both are independent per-user draws in
`org.py`, not department-linked, so a candidate exemplar is chosen for having a meaningfully
different profile — see `_pick_exemplar`), not on stepping outside the victim's own workday.

**Per-hour volume is sized against the org-wide budget, not invented.** Every campaign hour is
capped to `_ORG_Z_BUDGET` (1.5) MAD-widths of the org-wide `n_events`/`bytes_out` median — the
same "own-history budget" mechanism `s04_low_and_slow_exfil.py` uses, just scored against the
org-wide population instead of the victim's own history, because criterion (a) is an org-wide
claim. Verified against real generated output: the org-wide per-(principal, hour) budget is tight
(median ~3 events, ~2KB out) — consistent with a modest, believable "checked a dashboard, pushed a
small commit" hour, not a burst.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

import numpy as np

from app.detection.features import is_off_hours, robust_z
from datagen.emitters.zscaler import UrlCategory, ZScalerEmitter, categorize
from datagen.scenarios import register_scenario
from datagen.types import (
    ML_PEER_GROUP,
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
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["PeerGroupAcceptanceError", "PeerGroupDeviationScenario"]


class PeerGroupAcceptanceError(RuntimeError):
    """No candidate campaign satisfied docs/11 row 5's acceptance gate within `max_attempts`
    resample rounds for this scenario instance's seed.

    Scenario 5 exists specifically to test whether `ml.peer_group`/LOF earns its slot (docs/12
    prediction 2): a campaign that a global marginal or joint model can already separate, or one
    that the home department's own cohort cannot separate either, would make that benchmark
    measure nothing. A loud failure here — naming exactly which criterion failed on which
    attempt — is correct; silently emitting an invalid scenario 5 would corrupt every eval number
    downstream of it instead.
    """


# Categories in `datagen.org.DEFAULT_SAAS_APPS` that read as "engineer's toolchain" rather than
# general business software — GitHub, Atlassian, AWS Console, Snowflake, Datadog in the default
# catalogue. Not hand-invented hostnames: every domain this resolves to is already a real,
# already-visited destination in the corpus (every principal's `domain_affinity` includes every
# SaaS app domain, `org.py`), so `signal.rarity` and `signal.newly_registered_domain` have nothing
# to key on either.
_DEV_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"engineering", "cloud", "data", "observability"}
)

# Always present: `DEFAULT_DEPARTMENTS` (org.py) orders "Engineering" first and `Org.__init__`
# only ever truncates that tuple from the end, never reorders it, so it survives any
# `1 <= n_departments <= len(DEFAULT_DEPARTMENTS)`.
_TARGET_DEPARTMENT: Final[str] = "Engineering"

# API-shaped paths on the dev domains above — docs/11 names "API endpoints" specifically as part
# of the adopted profile, not just a change of destination.
_DEV_PATHS: Final[tuple[str, ...]] = (
    "/api/v3/repos/{t}/commits",
    "/api/v3/repos/{t}/deployments",
    "/rest/api/2/search?jql={t}",
    "/api/v2/statements?warehouse={t}",
    "/api/v1/dashboard/{t}",
    "/api/v1/query?query={t}",
    "/v2/functions/{t}/invocations",
    "/graphql?operationName=metrics&v={t}",
)

_METHODS: Final[tuple[str, ...]] = ("GET", "POST")
# API-call mix once the page/app itself has loaded (the first hit of every campaign hour is
# always a GET) -- mostly reads, matching genuine dev-hit hours' observed low-but-nonzero
# `post_ratio` (verified against real generated output) rather than a coin flip on every request.
_METHOD_WEIGHTS: Final[tuple[float, ...]] = (0.75, 0.25)
_OK_CODES: Final[tuple[int, ...]] = (200, 201)
_OK_WEIGHTS: Final[tuple[float, ...]] = (0.8, 0.2)

# The three features with genuine, non-degenerate org-wide spread (module docstring, verified
# against real generated output). `dev_domain_ratio`/`post_ratio`/`n_unique_domains` are excluded
# from the *marginal* check for exactly that reason -- they still feed the joint checks below.
_MARGINAL_FEATURES: Final[tuple[str, ...]] = ("n_events", "bytes_out", "bytes_in")
_ALL_FEATURES: Final[tuple[str, ...]] = (
    "n_events",
    "bytes_out",
    "bytes_in",
    "n_unique_domains",
    "dev_domain_ratio",
    "post_ratio",
)
# Heavy-tailed columns, log1p'd before standardizing in `_mahalanobis` -- same rationale as
# `s04_low_and_slow_exfil.py`'s own gate: a handful of large legitimate downloads in the org-wide
# population must not inflate that column's scale enough to wash out the others.
_LOG_FEATURES: Final[frozenset[str]] = frozenset({"n_events", "bytes_out", "bytes_in"})

_ACCEPT_Z_THRESHOLD: Final[float] = 3.5
_ACCEPT_ORG_JOINT_MAX_SEPARATION: Final[float] = 0.35
_ACCEPT_COHORT_JOINT_MIN_SEPARATION: Final[float] = 0.70
_MIN_ORG_BUCKETS_FOR_GATE: Final[int] = 300
_MIN_COHORT_BUCKETS_FOR_GATE: Final[int] = 15
_MIN_ATTACK_HOURS_FOR_GATE: Final[int] = 12

# MAD-width budget (docs/04's `0.6745*(x-median)/MAD`, same formula, org-wide population instead
# of a single victim's own history) each campaign hour's `n_events`/`bytes_out` is capped to --
# comfortably under the 3.5 acceptance threshold even after jitter. Mirrors
# `s04_low_and_slow_exfil.py`'s `_OWN_HISTORY_Z_BUDGET`.
_ORG_Z_BUDGET: Final[float] = 1.5
_MIN_SAFE_EVENTS: Final[int] = 2
_MIN_SAFE_BYTES: Final[float] = 400.0

_DEFAULT_MAX_ATTEMPTS: Final[int] = 40


@dataclass(frozen=True, slots=True)
class _HostProfile:
    """How the benign corpus already renders this host -- copied in shape from
    `s03_insider_mass_download.py` / `s04_low_and_slow_exfil.py` rather than imported, per this
    package's convention that a scenario module owns its own file."""

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


def _bucket_features(
    records: Sequence[EventRecord], dev_domains: frozenset[str]
) -> dict[tuple[str, datetime], dict[str, float]]:
    """Per-`(principal, hour)` feature vectors -- the population every criterion is scored
    against, computed identically for the org-wide population, the cohort population, and the
    campaign's own attack hours so the three are directly comparable."""
    buckets: dict[tuple[str, datetime], list[EventRecord]] = {}
    for r in records:
        key = (r.principal, r.ts.replace(minute=0, second=0, microsecond=0))
        buckets.setdefault(key, []).append(r)

    out: dict[tuple[str, datetime], dict[str, float]] = {}
    for key, rows in buckets.items():
        n = len(rows)
        bytes_out = sum(int(r.fields.get("requestsize", 0) or 0) for r in rows)
        bytes_in = sum(int(r.fields.get("responsesize", 0) or 0) for r in rows)
        hosts = {r.fields.get("host") for r in rows}
        n_dev = sum(1 for r in rows if r.fields.get("host") in dev_domains)
        n_post = sum(1 for r in rows if r.fields.get("requestmethod") == "POST")
        out[key] = {
            "n_events": float(n),
            "bytes_out": float(bytes_out),
            "bytes_in": float(bytes_in),
            "n_unique_domains": float(len(hosts)),
            "dev_domain_ratio": n_dev / n,
            "post_ratio": n_post / n,
        }
    return out


def _matrix(features: dict[tuple[str, datetime], dict[str, float]]) -> np.ndarray:
    return np.array(
        [[f[name] for name in _ALL_FEATURES] for f in features.values()], dtype=np.float64
    )


def _mahalanobis(reference: np.ndarray, query: np.ndarray) -> np.ndarray:
    """Mahalanobis distance of each row of `query` from `reference`'s own distribution.

    Log1p's the heavy-tailed columns then standardizes by `reference`'s own median/MAD (robust,
    matching docs/04's `ml.mahalanobis`), with the same `MAD == 0 -> scale 1.0` fallback
    `s04_low_and_slow_exfil.py`'s own `_mahalanobis` uses -- a degenerate column (verified above:
    `post_ratio`/`dev_domain_ratio`/`n_unique_domains` routinely are, org-wide) still contributes
    a finite, meaningful standardized deviation instead of exploding to infinity.
    """
    log_mask = np.array([name in _LOG_FEATURES for name in _ALL_FEATURES])

    def transform(matrix: np.ndarray) -> np.ndarray:
        out = matrix.copy()
        out[:, log_mask] = np.log1p(out[:, log_mask])
        return out

    ref_t = transform(reference)
    query_t = transform(query)

    median = np.median(ref_t, axis=0)
    mad = np.median(np.abs(ref_t - median), axis=0)
    mad[mad == 0] = 1.0
    ref_std = (ref_t - median) / mad
    query_std = (query_t - median) / mad

    cov = np.cov(ref_std, rowvar=False) + np.eye(ref_std.shape[1]) * 1e-6
    inv_cov = np.linalg.pinv(cov)
    return np.sqrt(np.einsum("ij,jk,ik->i", query_std, inv_cov, query_std))


@register_scenario
class PeerGroupDeviationScenario(Scenario):
    key = "peer_group_deviation"
    technique = "T1078"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (ML_PEER_GROUP,)
    description = (
        "A department member adopts another department's real behaviour profile (dev domains, "
        "API paths, that peer's diurnal shape and volume) -- globally normal (the org-wide "
        "population genuinely contains that other department), locally anomalous against the "
        "victim's own department cohort."
    )

    def __init__(
        self,
        *,
        duration_days: float = 10.0,
        n_campaign_hours: int = 40,
        events_per_hour_mean: float = 3.0,
        target_department: str = _TARGET_DEPARTMENT,
        home_department: str | None = None,
        start_fraction: float = 0.08,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if duration_days <= 0:
            raise ValueError("duration_days must be > 0")
        if n_campaign_hours < 1:
            raise ValueError("n_campaign_hours must be >= 1")
        if events_per_hour_mean <= 0:
            raise ValueError("events_per_hour_mean must be > 0")
        if not 0.0 <= start_fraction < 1.0:
            raise ValueError("start_fraction must be in [0, 1)")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

        self.duration_days = float(duration_days)
        self.n_campaign_hours = int(n_campaign_hours)
        self.events_per_hour_mean = float(events_per_hour_mean)
        self.target_department = target_department
        self.home_department = home_department
        self.start_fraction = float(start_fraction)
        self.max_attempts = int(max_attempts)

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        """Resample victim/exemplar/timing until a candidate satisfies the docs/11 row 5
        acceptance gate (module docstring), or raise `PeerGroupAcceptanceError`.

        The org-wide and cohort *populations* are computed once, before the attempt loop -- they
        are a property of the org and the benign backdrop, not of which victim/exemplar this
        attempt picked, so recomputing them per attempt would be wasted work, not extra rigor.
        """
        target_dept = self._resolve_target_department(ctx)
        home_dept = self._resolve_home_department(ctx, target_dept)
        dev_domains = self._dev_domains(ctx)
        if not dev_domains:
            raise ValueError(
                f"{self.key}: no SaaS app in {sorted(_DEV_CATEGORIES)} categories is configured "
                "for this org -- scenario 5 has no dev-domain destination to inject"
            )

        benign = [r for r in ctx.stream if not r.malicious and r.source is SourceType.ZSCALER]
        org_population = _bucket_features(benign, dev_domains)
        if len(org_population) < _MIN_ORG_BUCKETS_FOR_GATE:
            raise PeerGroupAcceptanceError(
                f"{ctx.scenario_id}: org-wide population only has {len(org_population)} "
                f"(principal, hour) buckets (< {_MIN_ORG_BUCKETS_FOR_GATE}) -- too thin to score "
                "the acceptance gate against; increase total_events or org size"
            )

        home_principals = {u.principal for u in ctx.org.department_members(home_dept)}
        cohort_population = {
            key: feats for key, feats in org_population.items() if key[0] in home_principals
        }
        if len(cohort_population) < _MIN_COHORT_BUCKETS_FOR_GATE:
            raise PeerGroupAcceptanceError(
                f"{ctx.scenario_id}: home department {home_dept!r} cohort only has "
                f"{len(cohort_population)} (principal, hour) buckets "
                f"(< {_MIN_COHORT_BUCKETS_FOR_GATE}) -- too thin to score the acceptance gate "
                "against; increase total_events, org size, or n_departments"
            )

        home_members = ctx.org.department_members(home_dept)
        target_members = ctx.org.department_members(target_dept)

        stream_floor = len(ctx.stream)
        injected_floor = len(ctx.injected)
        rejections: list[str] = []

        for attempt in range(self.max_attempts):
            attempt_rng = ctx.rng.substream(f"attempt:{attempt:03d}")
            victim = self._pick_victim(home_members, attempt_rng.substream("victim"))
            exemplar = self._pick_exemplar(
                target_members, victim, attempt_rng.substream("exemplar")
            )
            rng = attempt_rng.substream(f"campaign:{victim.key}:{exemplar.key}")

            ground_truth, rejection = self._attempt_campaign(
                ctx,
                rng,
                victim=victim,
                exemplar=exemplar,
                home_dept=home_dept,
                target_dept=target_dept,
                dev_domains=dev_domains,
                org_population=org_population,
                cohort_population=cohort_population,
            )
            if rejection is None:
                return ground_truth

            rejections.append(f"attempt {attempt} victim={victim.principal}: {rejection}")
            del ctx.stream[stream_floor:]
            del ctx.injected[injected_floor:]

        raise PeerGroupAcceptanceError(
            f"{ctx.scenario_id}: no candidate campaign satisfied the docs/11 row 5 acceptance "
            f"gate (rng={ctx.rng!r}) within {self.max_attempts} attempts:\n"
            + "\n".join(f"  - {r}" for r in rejections)
        )

    def _attempt_campaign(
        self,
        ctx: ScenarioContext,
        rng: SeededRandom,
        *,
        victim: User,
        exemplar: User,
        home_dept: str,
        target_dept: str,
        dev_domains: frozenset[str],
        org_population: dict[tuple[str, datetime], dict[str, float]],
        cohort_population: dict[tuple[str, datetime], dict[str, float]],
    ) -> tuple[GroundTruth, str | None]:
        emitter = ZScalerEmitter()
        campaign = ctx.window.subwindow(
            start_fraction=self.start_fraction, hours=self.duration_days * 24.0
        )

        natural_hours = self._natural_active_hours(ctx, victim)
        timestamps = self._select_campaign_timestamps(
            ctx, rng, victim, exemplar, campaign, self.n_campaign_hours, avoid=set(natural_hours)
        )
        if len(timestamps) < _MIN_ATTACK_HOURS_FOR_GATE:
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), (
                f"only {len(timestamps)} campaign hours placed "
                f"(< {_MIN_ATTACK_HOURS_FOR_GATE}) -- exemplar={exemplar.principal} diurnal "
                "shape barely overlaps the victim's own on-hours window"
            )

        # Org-wide per-hour budgets, one per volume feature -- `bytes_in` gets its *own* (roomy)
        # cap rather than reusing `bytes_out`'s (tight) one; the two features have very different
        # org-wide scales (verified against real generated output: `bytes_out` median ~2KB,
        # `bytes_in` median ~53KB) and capping `bytes_in` to `bytes_out`'s budget produced
        # unrealistically small page loads that separated from genuine dev-hit hours instead of
        # blending with them (an earlier draft of this scenario did exactly that).
        median_n, mad_n = self._median_mad([f["n_events"] for f in org_population.values()])
        median_bo, mad_bo = self._median_mad([f["bytes_out"] for f in org_population.values()])
        median_bi, mad_bi = self._median_mad([f["bytes_in"] for f in org_population.values()])
        n_cap = max(
            round(median_n + _ORG_Z_BUDGET * mad_n / 0.6745) if mad_n > 0 else round(median_n * 2),
            _MIN_SAFE_EVENTS,
        )
        bytes_out_cap = max(
            median_bo + _ORG_Z_BUDGET * mad_bo / 0.6745 if mad_bo > 0 else median_bo * 2,
            _MIN_SAFE_BYTES,
        )
        bytes_in_cap = max(
            median_bi + _ORG_Z_BUDGET * mad_bi / 0.6745 if mad_bi > 0 else median_bi * 2,
            _MIN_SAFE_BYTES,
        )

        referers = {d: f"https://{d}/" for d in dev_domains}
        profiles = {d: _host_profile(ctx.stream, d) for d in dev_domains}
        # `sorted`, not a bare `tuple(dev_domains)`: `dev_domains` is a `frozenset`, and CPython
        # randomizes string hashing per process (PYTHONHASHSEED, `datagen/rng.py`'s own
        # docstring on exactly this hazard) -- an unsorted set-to-tuple conversion would give
        # `hrng.choice(domain_pool)` a differently-ordered pool on every process run, silently
        # breaking the "same seed -> byte-identical output" guarantee even though every draw is
        # otherwise correctly seeded. Verified against real generated output: this was the one
        # difference between two `python -m datagen all --seed 42` runs a `diff -rq` caught.
        domain_pool = tuple(sorted(dev_domains))
        sizes = ctx.models.response_sizes

        injected: list[EventRecord] = []
        for i, hour in enumerate(timestamps):
            hrng = rng.substream(f"hour:{i}")
            # One host per hour, not one per event: a real visit to a dev tool is a session on
            # that one app, not a hop across five unrelated ones in the same hour (verified
            # against real generated output -- genuine dev-hit hours are overwhelmingly
            # single-domain, `n_unique_domains` 1-2).
            host = hrng.choice(domain_pool)
            profile = profiles[host]
            n_events = min(hrng.poisson(self.events_per_hour_mean) + 1, n_cap)
            offsets = sorted(hrng.uniform(0.0, 3599.0) for _ in range(n_events))

            out_left, in_left = bytes_out_cap, bytes_in_cap
            for idx, offset in enumerate(offsets):
                ts = ctx.window.clamp(hour + timedelta(seconds=offset))
                is_first = idx == 0
                # The first hit of the hour is the page/app load itself (GET, page-weight sized
                # response); later hits are the API calls that page makes while the user works --
                # mostly reads, some writes, mirroring genuine dev-hit hours' low-but-nonzero
                # post_ratio rather than a flat coin flip on every request.
                if is_first:
                    method, kind = "GET", "html"
                else:
                    method = hrng.weighted_choice(_METHODS, _METHOD_WEIGHTS)
                    kind = "api"
                path = "/" if is_first else hrng.choice(_DEV_PATHS).format(t=hrng.hex_token(4))

                bytes_in = int(min(sizes.response_bytes(hrng, kind), max(in_left, _MIN_SAFE_BYTES)))
                in_left -= bytes_in
                bytes_out = int(
                    min(sizes.request_bytes(hrng, method), max(out_left, _MIN_SAFE_BYTES))
                )
                out_left -= bytes_out

                injected.append(
                    emitter.inject(
                        ctx,
                        user=victim,
                        ts=ts,
                        host=host,
                        src_ip=victim.source_ip(hrng),
                        url=path,
                        method=method,
                        status=hrng.weighted_choice(_OK_CODES, _OK_WEIGHTS),
                        bytes_out=max(bytes_out, 64),
                        bytes_in=max(bytes_in, 64),
                        category=profile.category,
                        appname=profile.appname,
                        riskscore=profile.riskscore,
                        referer=referers[host],
                    )
                )

        rejection = self._check_acceptance(injected, dev_domains, org_population, cohort_population)
        if rejection is not None:
            return self.make_ground_truth(
                ctx, primary_entity=EntityRef(type="user", value=victim.principal)
            ), rejection

        stats = self._evidence(injected, dev_domains, org_population, cohort_population)
        ground_truth = self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"{victim.username} ({home_dept}) adopted {target_dept}'s browsing "
                f"profile modelled on {exemplar.username} ({target_dept}) for "
                f"{len(timestamps)} hours over {self.duration_days:.1f}d "
                f"({len(injected)} events to {', '.join(sorted(dev_domains))}); own device, own "
                "address, own department -- every marginal well-behaved feature stayed under "
                f"z={_ACCEPT_Z_THRESHOLD} against the org-wide population "
                f"(max|z|={stats['org_marginal_max_z']:.2f}), org-wide joint separation "
                f"{stats['org_joint_separation']:.0%} (<= {_ACCEPT_ORG_JOINT_MAX_SEPARATION:.0%}), "
                f"cohort joint separation {stats['cohort_joint_separation']:.0%} "
                f"(>= {_ACCEPT_COHORT_JOINT_MIN_SEPARATION:.0%}); verified against the docs/11 "
                "row 5 acceptance gate (module docstring)"
            ),
        )
        return ground_truth, None

    # ------------------------------------------------------------------ acceptance gate

    def _check_acceptance(
        self,
        injected: Sequence[EventRecord],
        dev_domains: frozenset[str],
        org_population: dict[tuple[str, datetime], dict[str, float]],
        cohort_population: dict[tuple[str, datetime], dict[str, float]],
    ) -> str | None:
        attack_records = [r for r in injected if r.malicious]
        if not attack_records:
            return "no malicious events were generated for this candidate"
        attack_buckets = _bucket_features(attack_records, dev_domains)
        if len(attack_buckets) < _MIN_ATTACK_HOURS_FOR_GATE:
            return (
                f"only {len(attack_buckets)} distinct attack-hour buckets "
                f"(< {_MIN_ATTACK_HOURS_FOR_GATE}) -- too thin to score the gate against"
            )

        # (a) org-wide marginal blindness, well-behaved features only (module docstring).
        offenders: list[str] = []
        for feature in _MARGINAL_FEATURES:
            values = [f[feature] for f in org_population.values()]
            max_z = max(abs(robust_z(values, f[feature])) for f in attack_buckets.values())
            if max_z > _ACCEPT_Z_THRESHOLD:
                offenders.append(f"{feature} (max|z|={max_z:.2f})")
        if offenders:
            return f"criterion (a) org-wide marginal fired: {', '.join(offenders)}"

        # (b) org-wide joint blindness.
        org_matrix = _matrix(org_population)
        attack_matrix = _matrix(attack_buckets)
        org_dists = _mahalanobis(org_matrix, org_matrix)
        attack_vs_org = _mahalanobis(org_matrix, attack_matrix)
        org_p95 = float(np.percentile(org_dists, 95))
        above_org = float(np.mean(attack_vs_org > org_p95))
        if above_org > _ACCEPT_ORG_JOINT_MAX_SEPARATION:
            return (
                f"criterion (b) org-wide joint separates too much: {above_org:.0%} of attack "
                f"hours above org p95 (> {_ACCEPT_ORG_JOINT_MAX_SEPARATION:.0%}, org_p95="
                f"{org_p95:.2f})"
            )

        # (c) cohort joint separation.
        cohort_matrix = _matrix(cohort_population)
        cohort_dists = _mahalanobis(cohort_matrix, cohort_matrix)
        attack_vs_cohort = _mahalanobis(cohort_matrix, attack_matrix)
        cohort_p95 = float(np.percentile(cohort_dists, 95))
        above_cohort = float(np.mean(attack_vs_cohort > cohort_p95))
        if above_cohort < _ACCEPT_COHORT_JOINT_MIN_SEPARATION:
            return (
                f"criterion (c) cohort separation too weak: {above_cohort:.0%} of attack hours "
                f"above cohort p95 (< {_ACCEPT_COHORT_JOINT_MIN_SEPARATION:.0%}, cohort_p95="
                f"{cohort_p95:.2f})"
            )

        return None

    def _evidence(
        self,
        injected: Sequence[EventRecord],
        dev_domains: frozenset[str],
        org_population: dict[tuple[str, datetime], dict[str, float]],
        cohort_population: dict[tuple[str, datetime], dict[str, float]],
    ) -> dict[str, float]:
        """Re-derive the same three numbers `_check_acceptance` scored, purely for the
        human-readable notes -- no different math, just no early-return."""
        attack_buckets = _bucket_features([r for r in injected if r.malicious], dev_domains)
        org_marginal_max_z = max(
            max(
                abs(robust_z([f[feat] for f in org_population.values()], af[feat]))
                for af in attack_buckets.values()
            )
            for feat in _MARGINAL_FEATURES
        )
        org_matrix, attack_matrix = _matrix(org_population), _matrix(attack_buckets)
        org_dists = _mahalanobis(org_matrix, org_matrix)
        attack_vs_org = _mahalanobis(org_matrix, attack_matrix)
        org_joint_separation = float(np.mean(attack_vs_org > float(np.percentile(org_dists, 95))))
        cohort_matrix = _matrix(cohort_population)
        cohort_dists = _mahalanobis(cohort_matrix, cohort_matrix)
        attack_vs_cohort = _mahalanobis(cohort_matrix, attack_matrix)
        cohort_joint_separation = float(
            np.mean(attack_vs_cohort > float(np.percentile(cohort_dists, 95)))
        )
        return {
            "org_marginal_max_z": org_marginal_max_z,
            "org_joint_separation": org_joint_separation,
            "cohort_joint_separation": cohort_joint_separation,
        }

    # ------------------------------------------------------------------ helpers

    def _resolve_target_department(self, ctx: ScenarioContext) -> str:
        if self.target_department not in ctx.org.departments:
            raise ValueError(
                f"{self.key}: target_department {self.target_department!r} is not one of this "
                f"org's departments {ctx.org.departments!r}"
            )
        return self.target_department

    def _resolve_home_department(self, ctx: ScenarioContext, target_dept: str) -> str:
        """Explicit `home_department` if given (validated); otherwise the *largest* remaining
        department by member count, deterministic and not seed-dependent -- maximizing cohort
        population size is what keeps the acceptance gate feasible on a small org (verified: the
        30-user/4-department structural-test org has only 3 Marketing members but 10 Customer
        Success members), not a difficulty knob."""
        if self.home_department is not None:
            if self.home_department not in ctx.org.departments:
                raise ValueError(
                    f"{self.key}: home_department {self.home_department!r} is not one of this "
                    f"org's departments {ctx.org.departments!r}"
                )
            if self.home_department == target_dept:
                raise ValueError(f"{self.key}: home_department must differ from target_department")
            return self.home_department
        candidates = [d for d in ctx.org.departments if d != target_dept]
        if not candidates:
            raise ValueError(f"{self.key}: org has no department other than {target_dept!r}")
        return max(candidates, key=lambda d: len(ctx.org.department_members(d)))

    def _dev_domains(self, ctx: ScenarioContext) -> frozenset[str]:
        return frozenset(a.domain for a in ctx.org.saas_apps if a.category in _DEV_CATEGORIES)

    def _pick_victim(self, home_members: Sequence[User], rng: SeededRandom) -> User:
        """A moderate-activity member of the home department -- not the quietest (too little
        natural history to contrast against) nor the heaviest (their own volume alone would
        already look unusual), mirroring `s03_insider_mass_download.py`'s `_pick_victim`."""
        ordered = sorted(home_members, key=lambda u: (u.activity_weight, u.username))
        low, high = len(ordered) // 4, max(len(ordered) * 3 // 4, 1)
        pool = ordered[low:high] or list(ordered)
        return rng.choice(pool)

    def _pick_exemplar(
        self, target_members: Sequence[User], victim: User, rng: SeededRandom
    ) -> User:
        """A target-department member whose profile genuinely differs from the victim's --
        `work_hours` and `activity_weight` are independent per-user draws in `org.py`, not
        department-linked, so "a typical member of the target department" has to be a specific,
        picked exemplar, not an invented department average.

        Restricted to the victim's own office timezone first: an exemplar in a different UTC
        offset would have almost no diurnal overlap with the victim's own on-hours window (module
        docstring's "kept inside the victim's own on-hours" constraint), starving
        `_select_campaign_timestamps` of candidates. Among same-timezone candidates, prefers
        (top half, then a random pick for resample variety) the ones whose start/end/phase-shift
        hours and activity level differ most from the victim's own -- a genuinely different
        diurnal shape and volume band, not a coincidentally similar one.
        """
        same_tz = [u for u in target_members if u.office.tz_offset_h == victim.office.tz_offset_h]
        pool = same_tz or list(target_members)

        def difference(u: User) -> float:
            wh, vh = u.work_hours, victim.work_hours
            return (
                abs(wh.start_h - vh.start_h)
                + abs(wh.end_h - vh.end_h)
                + abs(wh.phase_shift_h - vh.phase_shift_h)
                + abs(u.activity_weight - victim.activity_weight) * 2.0
            )

        ranked = sorted(pool, key=difference, reverse=True)
        top = ranked[: max(1, len(ranked) // 2)]
        return rng.choice(top)

    def _natural_active_hours(self, ctx: ScenarioContext, victim: User) -> list[datetime]:
        hours: set[datetime] = set()
        for record in ctx.benign_for(victim):
            if record.source is not SourceType.ZSCALER:
                continue
            hours.add(record.ts.replace(minute=0, second=0, microsecond=0))
        return sorted(hours)

    def _select_campaign_timestamps(
        self,
        ctx: ScenarioContext,
        rng: SeededRandom,
        victim: User,
        exemplar: User,
        campaign: TimeWindow,
        n: int,
        *,
        avoid: set[datetime],
    ) -> list[datetime]:
        """Up to `n` sorted hour buckets, drawn from `exemplar`'s diurnal shape but kept strictly
        inside `victim`'s own on-hours window (module docstring) and never colliding with `avoid`
        or each other. Best-effort: returns fewer than `n` if the exemplar's shape and the
        victim's own hours barely overlap, which `_attempt_campaign` treats as a rejection
        (resample a different exemplar) rather than silently accepting a thin campaign.
        """
        used = set(avoid)
        out: list[datetime] = []
        oversample = 8
        for _ in range(6):
            candidates = sorted(
                ctx.models.diurnal.sample_timestamps(
                    rng.fresh(f"select:{oversample}"),
                    campaign.start,
                    campaign.end,
                    exemplar.work_hours,
                    n * oversample,
                )
            )
            out = []
            seen = set(used)
            for ts in candidates:
                if is_off_hours(ts, victim.work_hours):
                    continue
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
        out.sort()
        return out

    @staticmethod
    def _median_mad(values: list[float]) -> tuple[float, float]:
        median = statistics.median(values)
        mad = statistics.median([abs(v - median) for v in values])
        return float(median), float(mad)
