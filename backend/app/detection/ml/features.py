"""L3 entity-window feature extraction (docs/04 §L3 "Entity-window ML").

## Unit of analysis

`(entity, 1-hour window)`, `entity` in `{principal, src_ip}` (docs/04, verbatim). This is the
module that "turns categorical logs into the continuous numeric regime these models need" — raw
log lines are never fed to `ml.iforest`/`ml.mahalanobis`/`ml.autoencoder` directly; every one of
them scores a row of this module's output instead. Both entity dimensions are scored
independently by the identical pipeline (mirrors `app.detection.signal.burst`'s precedent of
running one detector's logic once per dimension rather than picking one and missing the other):
a principal's own account behavior and a source IP's own network behavior are different attack
surfaces (account takeover vs. a shared/compromised egress point), and an event with both a
`principal` and a `src_ip` contributes to both entities' windows.

## Canonical primitives, reused not re-derived

`is_off_hours` and `robust_z` come from `app.detection.features` — the module that exists
specifically so this file does not invent a third definition of either (see that module's
docstring). `shannon_entropy` was added there at M8 for the same reason (this module's own
docstring extension explains why it does not instead import `app.detection.signal.dga_features`'s
copy: `app/detection/ml/**` does not import the concurrently-developed `app/detection/signal/**`
package).

## Estimated work hours — a production-realistic substitute for `datagen`'s `Org`

`is_off_hours` needs a `WorkHoursLike` (start/end hour + UTC offset, in the entity's own local
time). `datagen.org.User.work_hours` supplies that in the synthetic corpus, but
`app.detection.ml` must not import `datagen` (`app/detection/features.py`'s own boundary,
restated in `events.py`) — and a real deployment has no HR feed of every principal's office and
timezone either. `estimate_work_hours` below derives a `WorkHoursLike` empirically, from the
entity's own event-timestamp history: the contiguous ~9-hour UTC block capturing the most of that
entity's own activity, found by a circular sliding-window search over a 24-bin hour-of-day
histogram. `tz_offset_h` is fixed at `0.0` (the search already operates in UTC, so "local time"
here is simply "the entity's own busiest UTC block" — this does not recover a literal timezone,
only the behavioral effect a timezone has on when an entity is typically active, which is what
`off_hours_ratio`/`weekend_ratio`/`night_ratio` actually need).

**Known limitation, stated honestly (docs/12 asks for this in `results.md` too):** the estimate is
built from the *same* event set being scored, self-inclusive (matching `app.detection.signal.
burst`'s own precedent of scoring a bucket against a population that bucket is itself a member
of) — a sustained, low-and-slow shift in an entity's activity pattern could gradually pull its own
work-hours estimate toward the attacker's schedule rather than flagging it, over a campaign long
enough relative to the entity's total history in the analyzed file. Scenario 8's own acceptance
gate (`datagen/scenarios/s08_low_and_slow_exfil.py`) is deliberately short (9 days by default)
relative to the corpus window and keeps `off_hours_ratio` pinned near zero for exactly this
reason, so this limitation does not undermine that scenario's own guarantee — but a much longer
real-world low-and-slow campaign could, in principle, partially normalize itself. A production
deployment would instead anchor the baseline to a lagging window that excludes the period being
scored; that requires persisted cross-analysis history this milestone's single-file harness does
not have (the same caveat `app.detection.signal.rarity` already states for `user_novelty`).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

import numpy as np
import numpy.typing as npt
import pandas as pd

from app.detection.features import is_off_hours, robust_z, shannon_entropy
from app.detection.ml.events import MLEvent

__all__ = [
    "DEVICE_FEATURES",
    "DOMAIN_FEATURES",
    "ENTITY_WINDOW_MODEL_FEATURES",
    "HTTP_FEATURES",
    "IDENTITY_FEATURES",
    "SCORE_OVERFLOW_SENTINEL",
    "TEMPORAL_FEATURES",
    "TRANSFER_FEATURES",
    "VOLUME_FEATURES",
    "Z_SCORE_CLIP",
    "EstimatedWorkHours",
    "build_entity_window_features",
    "estimate_work_hours",
    "sanitize_scores",
    "to_feature_matrix",
]

# ---------------------------------------------------------------------------- feature names
#
# ~50 features (docs/04), grouped exactly as that doc's table groups them. The doc names 38 of
# these verbatim; the remainder (marked below) are natural extensions within the same category,
# added to round the vector out to docs/04's own "~50" — never a substitute for a named one.

VOLUME_FEATURES: Final[tuple[str, ...]] = (
    "n_events",
    "n_events_z_vs_own_history",
    "n_events_z_vs_cohort",
)

TEMPORAL_FEATURES: Final[tuple[str, ...]] = (
    "off_hours_ratio",
    "weekend_ratio",
    "iat_mean",
    "iat_cv",
    "iat_min",  # added: smallest gap between consecutive events -- rapid scripted request pairs
    "hour_entropy",  # added: entropy of *where within the hour* events land (burst vs. spread)
    "burstiness",
    "night_ratio",  # added: 00:00-05:59 local share -- deep-night activity, not just "off hours"
)

DOMAIN_FEATURES: Final[tuple[str, ...]] = (
    "n_unique_domains",
    "n_rare_domains",
    "rare_domain_ratio",
    "n_new_domains_for_user",
    "mean_domain_entropy",
    "max_domain_entropy",
    "n_newly_registered_domains",
    "high_risk_tld_ratio",  # added: share of traffic to enrichment high-risk-tier TLDs
    "non_top_site_ratio",  # added: share of traffic outside the bundled top-5000 list
)

TRANSFER_FEATURES: Final[tuple[str, ...]] = (
    "bytes_out_sum",
    "bytes_in_sum",
    "out_in_ratio",
    "bytes_out_max",
    "bytes_out_z_vs_own",
    "n_large_uploads",
    "bytes_in_max",  # added: largest single download -- insider mass-download signal (docs/11 #7)
    "bytes_out_cv",  # added: per-event upload-size variability (steady drip vs. bursty transfer)
)

HTTP_FEATURES: Final[tuple[str, ...]] = (
    "post_ratio",
    "blocked_ratio",
    "error_ratio",
    "n_unique_status_codes",
    "direct_ip_ratio",
    "n_unique_url_paths",  # added: path diversity -- low diversity suggests scripted/automated
    "threat_category_ratio",  # added: share of events ZScaler itself flagged with malware[]
)

DEVICE_FEATURES: Final[tuple[str, ...]] = (
    "n_unique_user_agents",
    "automation_ua_ratio",
    "n_unique_asns",
    "n_unique_countries",
    "hosting_provider_ratio",
    "n_unique_src_ips",  # added: source-IP fan-out for a principal (account sharing/proxy hop)
    "ua_diversity_ratio",  # added: n_unique_user_agents normalized by n_events
)

IDENTITY_FEATURES: Final[tuple[str, ...]] = (
    "n_auth_failures",
    "n_auth_successes",
    "auth_failure_ratio",
    "n_mfa_challenges",
    "n_distinct_geos",
    "privilege_events",
    "mfa_failure_ratio",  # added: MFA-fatigue precursor -- repeated challenge failures
    "session_start_events",  # added: `user.session.start` count -- identity activity volume base
)

# Fixed column order every consumer (models, calibration, SHAP) reads `X` in. Concatenation
# order matches docs/04's own table order; never reorder without retraining every artifact.
ENTITY_WINDOW_MODEL_FEATURES: Final[tuple[str, ...]] = (
    VOLUME_FEATURES
    + TEMPORAL_FEATURES
    + DOMAIN_FEATURES
    + TRANSFER_FEATURES
    + HTTP_FEATURES
    + DEVICE_FEATURES
    + IDENTITY_FEATURES
)
assert len(ENTITY_WINDOW_MODEL_FEATURES) == len(set(ENTITY_WINDOW_MODEL_FEATURES))

# docs/04 L1's "large POST" rule threshold is 10MB; scenario 8's own acceptance gate
# (`_GATE_LARGE_UPLOAD_BYTES`) independently settled on 1MB as "large enough to only ever fire on
# a genuine outlier" relative to both its own campaign (mean 900KB) and ordinary attachment
# traffic. Reused verbatim here rather than picking a third number, so this feature's marginal
# behavior on scenario 8's attack hours is provably consistent with what that scenario's own
# acceptance proof already checked.
LARGE_UPLOAD_BYTES: Final[int] = 1_000_000

# "Rare enough, file-wide, to count" -- same reasoning as
# `app.detection.signal.constants.RARITY_MAX_ORG_EVENT_COUNT` (10: "ten or fewer hits, org-wide,
# in this file -- rare for a few-hundred-person org"), re-derived independently here rather than
# imported across the `app/detection/ml` <-> `app/detection/signal` boundary (see `events.py`'s
# module docstring on why this package does not import that concurrently-developed sibling).
RARE_DOMAIN_MAX_EVENT_COUNT: Final[int] = 10

# `estimate_work_hours`: width of the contiguous UTC block treated as this entity's "on hours" --
# matches `datagen.realism.WorkHours`'s own default span (`end_h - start_h == 8.5`) rounded up to
# a whole number of histogram bins.
_WORK_HOURS_SPAN_H: Final[int] = 9
# Fallback for an entity with too little history to estimate anything from (docs/04's own
# fallback business-hours window, UTC, when nothing better is available).
_DEFAULT_START_H: Final[float] = 9.0
_DEFAULT_END_H: Final[float] = 17.5
_MIN_EVENTS_FOR_ESTIMATE: Final[int] = 5

_SUB_BUCKETS_PER_HOUR: Final[int] = 12  # 5-minute sub-buckets, for `hour_entropy`

# `n_events_z_vs_own_history` / `n_events_z_vs_cohort` / `bytes_out_z_vs_own` legitimately return
# `math.inf` (`robust_z`'s documented MAD==0 policy -- a degenerate, zero-spread baseline makes
# *any* other value an unbounded outlier by construction). That is the right value for a
# threshold check (`abs(z) > 3.5`), but every consumer downstream of this module (StandardScaler,
# a covariance matrix, a PyTorch tensor) cannot accept a literal infinity. `Z_SCORE_CLIP` is the
# finite sentinel `to_feature_matrix` substitutes for `+/-inf` -- large enough that no ordinary,
# non-degenerate z-score in this corpus's scale ever legitimately reaches it (`|z| > 3.5` is
# already the L2 burst threshold for "extreme"; real burst z-scores observed in this codebase's
# own fixtures top out in the tens, never the hundreds).
#
# **This is a substitution for the three `inf`-valued z-score features only, never a blanket
# clip of the whole matrix.** An earlier version of `to_feature_matrix` called `np.clip` across
# every column after `nan_to_num`, which silently flattened `bytes_out_sum` (and every other
# unbounded-range raw feature -- sums, maxes, counts) down to 100 for any genuinely large value
# -- e.g. a multi-megabyte exfiltration burst's `bytes_out_sum` clipped to the same 100 as an
# ordinary browsing session, destroying exactly the volumetric signal `ml.iforest`/
# `ml.mahalanobis`/`ml.autoencoder` most need. Caught via a real eval run against the trained
# models raising `ValueError: Input contains NaN` from an unrelated numerical-overflow symptom
# further downstream (a near-singular robust covariance blowing up on an artificially
# range-compressed matrix) -- fixed at the root (`to_feature_matrix` below) rather than papered
# over at the crash site.
Z_SCORE_CLIP: Final[float] = 100.0

# `activity_name` values (docs/03: "make sure these survive normalization intact") this module
# treats as identity-layer signals distinct from a plain successful/failed sign-in.
_MFA_CHALLENGE_ACTIVITY: Final[str] = "user.authentication.auth_via_mfa"
_SESSION_START_ACTIVITY: Final[str] = "user.session.start"
# Security-sensitive account changes -- privilege escalation, new API credential, MFA factor
# removed. All three are also individually covered by L1 Sigma rules (docs/04); counting them
# here as one L3 feature gives the unsupervised models a continuous "how much sensitive identity
# churn happened in this window" signal the binary rule firings do not carry on their own.
_PRIVILEGE_ACTIVITY: Final[frozenset[str]] = frozenset(
    {
        "user.account.privilege.grant",
        "system.api_token.create",
        "user.mfa.factor.deactivate",
        "policy.lifecycle.update",
    }
)


# ---------------------------------------------------------------------------- estimated work hours


@dataclass(slots=True)
class EstimatedWorkHours:
    """`WorkHoursLike` (satisfies `app.detection.features.WorkHoursLike` structurally) derived
    from an entity's own event history. See module docstring for the estimation method and its
    stated limitation.

    Deliberately *not* frozen, unlike most value objects in this codebase: `WorkHoursLike` (its
    own docstring, `app/detection/features.py`) declares plain mutable attributes, and mypy's
    structural Protocol matching under `--strict` requires an implementing type's attributes to
    be settable too ("Protocol member expected settable variable, got read-only attribute") —
    verified directly against a minimal repro before making this choice, since `datagen.realism.
    WorkHours` (the Protocol's other implementer) is frozen but lives in a module this project's
    `mypy --strict` override list does not cover, so it never hits this check.
    """

    start_h: float
    end_h: float
    tz_offset_h: float = 0.0


def estimate_work_hours(timestamps: Sequence[datetime]) -> EstimatedWorkHours:
    """The contiguous `_WORK_HOURS_SPAN_H`-hour UTC block containing the most of `timestamps`.

    Circular sliding-window search over a 24-bin hour-of-day histogram — circular because
    business hours can wrap past midnight UTC for some offices (e.g. `IE-DU`, docs/11), and a
    non-circular scan would systematically undercount any entity whose real local-time block
    straddles the UTC day boundary.

    Falls back to a fixed `[9, 17.5)` UTC default when there is too little history
    (`_MIN_EVENTS_FOR_ESTIMATE`) to trust an estimate — an entity seen only a handful of times in
    the whole file has no meaningful "usual pattern" to recover, and a noisy estimate from 2-3
    points would be worse than an honest, stated default.
    """
    if len(timestamps) < _MIN_EVENTS_FOR_ESTIMATE:
        return EstimatedWorkHours(start_h=_DEFAULT_START_H, end_h=_DEFAULT_END_H)

    hist = [0] * 24
    for ts in timestamps:
        hist[ts.hour] += 1

    best_start = 0
    best_count = -1
    for start in range(24):
        count = sum(hist[(start + offset) % 24] for offset in range(_WORK_HOURS_SPAN_H))
        if count > best_count:
            best_count = count
            best_start = start

    return EstimatedWorkHours(
        start_h=float(best_start), end_h=float(best_start + _WORK_HOURS_SPAN_H)
    )


# ---------------------------------------------------------------------------- entity-window build


def _events_frame(events: Sequence[MLEvent]) -> pd.DataFrame:
    """One row per `MLEvent`, column-built (not `dataclasses.asdict` per row) for speed at
    hundreds-of-thousands-of-rows scale."""
    if not events:
        return pd.DataFrame(
            columns=[
                "line_no",
                "ts",
                "source_type",
                "kind",
                "principal",
                "src_ip",
                "domain",
                "registrable_domain",
                "url_path",
                "http_method",
                "status_code",
                "bytes_in",
                "bytes_out",
                "user_agent",
                "action",
                "activity_name",
                "country",
                "asn",
                "is_hosting",
                "is_automation_ua",
                "domain_newly_registered",
                "domain_high_risk_tld",
                "domain_is_top_site",
                "threat_present",
                "is_direct_ip",
            ]
        )
    cols: dict[str, list[object]] = {
        "line_no": [e.line_no for e in events],
        "ts": [e.ts for e in events],
        "source_type": [e.source_type for e in events],
        "kind": [e.kind for e in events],
        "principal": [e.principal for e in events],
        "src_ip": [e.src_ip for e in events],
        "domain": [e.domain for e in events],
        "registrable_domain": [e.registrable_domain for e in events],
        "url_path": [e.url_path for e in events],
        "http_method": [e.http_method for e in events],
        "status_code": [e.status_code for e in events],
        "bytes_in": [e.bytes_in for e in events],
        "bytes_out": [e.bytes_out for e in events],
        "user_agent": [e.user_agent for e in events],
        "action": [e.action for e in events],
        "activity_name": [e.activity_name for e in events],
        "country": [e.country for e in events],
        "asn": [e.asn for e in events],
        "is_hosting": [e.is_hosting for e in events],
        "is_automation_ua": [e.is_automation_ua for e in events],
        "domain_newly_registered": [e.domain_newly_registered for e in events],
        "domain_high_risk_tld": [e.domain_high_risk_tld for e in events],
        "domain_is_top_site": [e.domain_is_top_site for e in events],
        "threat_present": [e.threat_present for e in events],
        "is_direct_ip": [e.is_direct_ip for e in events],
    }
    df = pd.DataFrame(cols)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["hour"] = df["ts"].dt.floor("h")
    return df


def _domain_label_entropy(domains: Sequence[str]) -> tuple[float, float]:
    """`(mean, max)` Shannon entropy over the character distribution of each unique domain in
    `domains`. Exposes DGA/algorithmically-generated destinations the same way L2's
    `signal.dga` does, but as a coarser, complementary L3 signal computed directly on the
    registrable domain string rather than L2's fitted logistic model — the joint-distribution
    models (`ml.mahalanobis`, `ml.autoencoder`) can use it alongside volume/transfer features in
    ways a single-domain L2 classifier never sees.
    """
    unique = sorted(set(domains))
    if not unique:
        return 0.0, 0.0
    entropies = [shannon_entropy(d) for d in unique]
    return statistics.fmean(entropies), max(entropies)


def _own_history_z(agg: pd.DataFrame, entity_col: str, value_col: str, out_col: str) -> None:
    """`robust_z` of `value_col`, scored against each entity's own full set of window values
    (median/MAD computed over that entity's own rows, self-inclusive — see module docstring).
    Operates on the already-aggregated (one row per entity-window) frame, so calling the
    canonical scalar `robust_z` once per row is cheap even at tens of thousands of rows.
    """
    result = np.empty(len(agg), dtype=np.float64)
    for _, group in agg.groupby(entity_col, sort=False):
        values = group[value_col].tolist()
        for idx, x in zip(group.index, values, strict=True):
            result[agg.index.get_loc(idx)] = robust_z(values, x)
    agg[out_col] = result


def _cohort_z(agg: pd.DataFrame, window_col: str, value_col: str, out_col: str) -> None:
    """`robust_z` of `value_col`, scored against every entity (of the same entity_type, already
    the only rows in `agg`) sharing the same absolute window -- "how does this entity's volume
    this hour compare to its peers' volume the same hour," the complement of `_own_history_z`'s
    "compared to its own typical hour."
    """
    result = np.empty(len(agg), dtype=np.float64)
    for _, group in agg.groupby(window_col, sort=False):
        values = group[value_col].tolist()
        for idx, x in zip(group.index, values, strict=True):
            result[agg.index.get_loc(idx)] = robust_z(values, x)
    agg[out_col] = result


def _build_for_entity(df: pd.DataFrame, entity_col: str, entity_type: str) -> pd.DataFrame:
    """Full ~50-feature table for one entity dimension (`principal` or `src_ip`).

    `df` must already be restricted to rows with a non-null `entity_col`. Returns one row per
    `(entity_value, hour)` actually observed -- entity-windows with zero events are never
    materialized (there is nothing to score; every model here operates on observed activity).
    """
    work = df.dropna(subset=[entity_col]).copy()
    if work.empty:
        return pd.DataFrame(
            columns=[
                "entity_type",
                "entity_value",
                "window_start",
                "window_end",
                "line_numbers",
                *ENTITY_WINDOW_MODEL_FEATURES,
            ]
        )

    entity_values = work[entity_col].to_numpy()

    # ---- per-entity estimated work hours (module docstring), computed once from full history
    work_hours_by_entity: dict[str, EstimatedWorkHours] = {}
    ts_by_entity: dict[str, list[datetime]] = defaultdict(list)
    for entity_value, ts in zip(entity_values, work["ts"], strict=True):
        ts_by_entity[entity_value].append(ts.to_pydatetime())
    for entity_value, ts_list in ts_by_entity.items():
        work_hours_by_entity[entity_value] = estimate_work_hours(ts_list)

    work["is_off_hours"] = [
        is_off_hours(ts.to_pydatetime(), work_hours_by_entity[ev])
        for ts, ev in zip(work["ts"], entity_values, strict=True)
    ]
    local_h = np.array(
        [
            (ts.to_pydatetime().timestamp() / 3600.0 + work_hours_by_entity[ev].tz_offset_h) % 24.0
            for ts, ev in zip(work["ts"], entity_values, strict=True)
        ]
    )
    # Local weekday: UTC weekday shifted by the *hour* delta between local and UTC clock time
    # (tz_offset_h is 0.0 for the estimator today, but this stays correct if a future work-hours
    # source supplies a real offset).
    local_ts = work["ts"] + pd.to_timedelta(
        [work_hours_by_entity[ev].tz_offset_h for ev in entity_values], unit="h"
    )
    work["is_weekend"] = local_ts.dt.weekday.isin([5, 6]).to_numpy()
    work["is_night"] = (local_h >= 0.0) & (local_h < 5.0)
    work["sub_bucket"] = (
        (work["ts"].dt.minute * 60 + work["ts"].dt.second) // (3600 // _SUB_BUCKETS_PER_HOUR)
    ).astype(int)

    # ---- file-wide domain popularity (for n_rare_domains / rare_domain_ratio)
    proxy = work[work["kind"] == "proxy"]
    domain_event_counts = proxy["registrable_domain"].value_counts()

    # ---- first-seen (entity, domain) hour, for n_new_domains_for_user
    if not proxy.empty:
        first_hour = proxy.groupby([entity_col, "registrable_domain"])["hour"].transform("min")
        new_domain_mask = proxy["hour"] == first_hour
    else:
        new_domain_mask = pd.Series([], dtype=bool)

    grouped = work.groupby([entity_col, "hour"], sort=True)

    rows: list[dict[str, object]] = []
    proxy_groups = (
        proxy.assign(_is_new_domain=new_domain_mask if not proxy.empty else False).groupby(
            [entity_col, "hour"], sort=True
        )
        if not proxy.empty
        else None
    )
    identity_groups = work[work["kind"] == "identity"].groupby([entity_col, "hour"], sort=True)

    proxy_group_map = dict(list(proxy_groups)) if proxy_groups is not None else {}
    identity_group_map = dict(list(identity_groups))

    for (entity_value, hour), g in grouped:
        n_events = len(g)
        pg = proxy_group_map.get((entity_value, hour))
        ig = identity_group_map.get((entity_value, hour))

        row: dict[str, object] = {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "window_start": hour,
            "window_end": hour + pd.Timedelta(hours=1),
            "line_numbers": g["line_no"].tolist(),
        }

        # ---------------------------------------------------------------- Volume
        row["n_events"] = float(n_events)
        # n_events_z_vs_own_history / n_events_z_vs_cohort filled in a second pass below.

        # ---------------------------------------------------------------- Temporal
        row["off_hours_ratio"] = float(g["is_off_hours"].mean())
        row["weekend_ratio"] = float(g["is_weekend"].mean())
        row["night_ratio"] = float(g["is_night"].mean())
        ts_sorted = g["ts"].sort_values()
        if len(ts_sorted) >= 2:
            iat = ts_sorted.diff().dropna().dt.total_seconds().to_numpy()
            iat = iat[iat >= 0]
        else:
            iat = np.array([])
        if iat.size >= 1:
            row["iat_mean"] = float(iat.mean())
            row["iat_min"] = float(iat.min())
        else:
            row["iat_mean"] = 0.0
            row["iat_min"] = 0.0
        if iat.size >= 2 and iat.mean() > 0:
            row["iat_cv"] = float(iat.std(ddof=0) / iat.mean())
            row["burstiness"] = float(
                (iat.std(ddof=0) - iat.mean()) / (iat.std(ddof=0) + iat.mean())
            )
        else:
            row["iat_cv"] = 0.0
            row["burstiness"] = 0.0
        row["hour_entropy"] = shannon_entropy(g["sub_bucket"].tolist())

        # ---------------------------------------------------------------- Domains
        if pg is not None:
            unique_domains = pg["registrable_domain"].dropna().unique().tolist()
            n_unique = len(unique_domains)
            rare = [
                d
                for d in unique_domains
                if domain_event_counts.get(d, 0) <= RARE_DOMAIN_MAX_EVENT_COUNT
            ]
            mean_ent, max_ent = _domain_label_entropy(unique_domains)
            row["n_unique_domains"] = float(n_unique)
            row["n_rare_domains"] = float(len(rare))
            row["rare_domain_ratio"] = float(len(rare) / n_unique) if n_unique else 0.0
            row["n_new_domains_for_user"] = float(
                pg.loc[pg["_is_new_domain"], "registrable_domain"].nunique()
            )
            row["mean_domain_entropy"] = mean_ent
            row["max_domain_entropy"] = max_ent
            row["n_newly_registered_domains"] = float(
                pg.loc[pg["domain_newly_registered"], "registrable_domain"].nunique()
            )
            row["high_risk_tld_ratio"] = float(pg["domain_high_risk_tld"].mean())
            row["non_top_site_ratio"] = float((~pg["domain_is_top_site"]).mean())
        else:
            for name in DOMAIN_FEATURES:
                row[name] = 0.0

        # ---------------------------------------------------------------- Transfer
        if pg is not None:
            bytes_out = pg["bytes_out"].fillna(0).to_numpy(dtype=np.float64)
            bytes_in = pg["bytes_in"].fillna(0).to_numpy(dtype=np.float64)
            row["bytes_out_sum"] = float(bytes_out.sum())
            row["bytes_in_sum"] = float(bytes_in.sum())
            row["out_in_ratio"] = float(bytes_out.sum() / max(bytes_in.sum(), 1.0))
            row["bytes_out_max"] = float(bytes_out.max()) if bytes_out.size else 0.0
            row["bytes_in_max"] = float(bytes_in.max()) if bytes_in.size else 0.0
            row["n_large_uploads"] = float(int((bytes_out >= LARGE_UPLOAD_BYTES).sum()))
            if bytes_out.size >= 2 and bytes_out.mean() > 0:
                row["bytes_out_cv"] = float(bytes_out.std(ddof=0) / bytes_out.mean())
            else:
                row["bytes_out_cv"] = 0.0
        else:
            for name in TRANSFER_FEATURES:
                if name != "bytes_out_z_vs_own":
                    row[name] = 0.0
        # bytes_out_z_vs_own filled in a second pass below.

        # ---------------------------------------------------------------- HTTP
        if pg is not None:
            row["post_ratio"] = float((pg["http_method"] == "POST").mean())
            row["blocked_ratio"] = float((pg["action"] == "blocked").mean())
            status = pg["status_code"].dropna()
            row["error_ratio"] = float((status >= 400).mean()) if not status.empty else 0.0
            row["n_unique_status_codes"] = float(pg["status_code"].nunique())
            row["direct_ip_ratio"] = float(pg["is_direct_ip"].mean())
            row["n_unique_url_paths"] = float(pg["url_path"].nunique())
            row["threat_category_ratio"] = float(pg["threat_present"].mean())
        else:
            for name in HTTP_FEATURES:
                row[name] = 0.0

        # ---------------------------------------------------------------- Device
        n_unique_uas = float(g["user_agent"].nunique())
        row["n_unique_user_agents"] = n_unique_uas
        row["automation_ua_ratio"] = float(g["is_automation_ua"].mean())
        row["n_unique_asns"] = float(g["asn"].nunique())
        row["n_unique_countries"] = float(g["country"].nunique())
        row["hosting_provider_ratio"] = float(g["is_hosting"].mean())
        row["n_unique_src_ips"] = float(g["src_ip"].nunique())
        row["ua_diversity_ratio"] = (n_unique_uas / n_events) if n_events else 0.0

        # ---------------------------------------------------------------- Identity
        if ig is not None and not ig.empty:
            failures = int((ig["action"] == "FAILURE").sum())
            successes = int((ig["action"] == "SUCCESS").sum())
            mfa = ig[ig["activity_name"] == _MFA_CHALLENGE_ACTIVITY]
            row["n_auth_failures"] = float(failures)
            row["n_auth_successes"] = float(successes)
            row["auth_failure_ratio"] = float(failures / max(failures + successes, 1))
            row["n_mfa_challenges"] = float(len(mfa))
            row["mfa_failure_ratio"] = (
                float((mfa["action"] == "FAILURE").mean()) if len(mfa) else 0.0
            )
            row["n_distinct_geos"] = float(ig["country"].nunique())
            row["privilege_events"] = float(ig["activity_name"].isin(_PRIVILEGE_ACTIVITY).sum())
            row["session_start_events"] = float(
                (ig["activity_name"] == _SESSION_START_ACTIVITY).sum()
            )
        else:
            for name in IDENTITY_FEATURES:
                row[name] = 0.0

        rows.append(row)

    result = pd.DataFrame(rows)
    if result.empty:
        return result

    result = result.sort_values(["entity_value", "window_start"]).reset_index(drop=True)
    _own_history_z(result, "entity_value", "n_events", "n_events_z_vs_own_history")
    _cohort_z(result, "window_start", "n_events", "n_events_z_vs_cohort")
    _own_history_z(result, "entity_value", "bytes_out_sum", "bytes_out_z_vs_own")
    return result


def build_entity_window_features(events: Sequence[MLEvent]) -> pd.DataFrame:
    """Build the full `(entity, 1-hour window)` feature table (docs/04 §L3) for both entity
    dimensions (`principal` -> `entity_type="user"`, `src_ip` -> `entity_type="src_ip"`).

    Returns one row per observed `(entity_type, entity_value, window_start)`, columns
    `entity_type`, `entity_value`, `window_start`, `window_end`, `line_numbers` (the file line
    numbers of every event in that window -- evidence, and what the eval harness matches against
    `GroundTruth.malicious_line_numbers`), plus every name in `ENTITY_WINDOW_MODEL_FEATURES`, in
    that fixed order.
    """
    df = _events_frame(events)
    if df.empty:
        return pd.DataFrame(
            columns=[
                "entity_type",
                "entity_value",
                "window_start",
                "window_end",
                "line_numbers",
                *ENTITY_WINDOW_MODEL_FEATURES,
            ]
        )

    by_user = _build_for_entity(df, "principal", "user")
    by_src_ip = _build_for_entity(df, "src_ip", "src_ip")
    combined = pd.concat([by_user, by_src_ip], ignore_index=True)
    ordered_cols = ["entity_type", "entity_value", "window_start", "window_end", "line_numbers"]
    ordered_cols += list(ENTITY_WINDOW_MODEL_FEATURES)
    return combined[ordered_cols]


def to_feature_matrix(df: pd.DataFrame) -> npt.NDArray[np.float64]:
    """`df[ENTITY_WINDOW_MODEL_FEATURES]` as a finite `float64` matrix, ready for
    `StandardScaler`/`IsolationForest`/`MinCovDet`/the autoencoder — every one of which requires
    finite input. See `Z_SCORE_CLIP`'s docstring for why *substituting* a finite sentinel for
    `+/-inf`, not dropping it, is correct: an infinite `robust_z` is real information (a
    degenerate own-history baseline made this value an outlier by construction), not a
    data-quality defect to discard.

    Substitution only — every other finite value (a `bytes_out_sum` in the millions, a genuinely
    large `n_events`) passes through completely unclipped. See `Z_SCORE_CLIP`'s docstring for why
    a blanket clip here was a real bug this module once had, not a hypothetical one.
    """
    raw = df[list(ENTITY_WINDOW_MODEL_FEATURES)].to_numpy(dtype=np.float64, copy=True)
    matrix: npt.NDArray[np.float64] = np.nan_to_num(
        raw, nan=0.0, posinf=Z_SCORE_CLIP, neginf=-Z_SCORE_CLIP
    )
    return matrix


# Numerical safety net for `ml.mahalanobis` specifically (`mahalanobis.py`'s own docstring):
# `z^T P z` (`P` a 50x50 robust precision matrix over genuinely wide-range, correlated features)
# can overflow float64 for an extreme-enough row even though every input to it is finite -- an
# `inf`/`nan` *output* in that case is a numerical-overflow artifact, not a meaningful "how
# anomalous" signal the way an `inf` *input* z-score is (see `Z_SCORE_CLIP`'s docstring for that
# distinction). `SCORE_OVERFLOW_SENTINEL` is large enough that a sanitized row still ranks as
# "more anomalous than anything else observed" for both the percentile-confidence calculation and
# AUC-PR (both only care about relative order), without ever reaching a caller (`evaluate.py`'s
# `average_precision_score`) that rejects non-finite input outright.
SCORE_OVERFLOW_SENTINEL: Final[float] = 1e12


def sanitize_scores(scores: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Replace any non-finite raw anomaly score with `SCORE_OVERFLOW_SENTINEL` (sign-preserving).
    Every model's `raw_scores` in this package funnels through this before returning."""
    sanitized: npt.NDArray[np.float64] = np.nan_to_num(
        scores,
        nan=SCORE_OVERFLOW_SENTINEL,
        posinf=SCORE_OVERFLOW_SENTINEL,
        neginf=-SCORE_OVERFLOW_SENTINEL,
    )
    return sanitized
