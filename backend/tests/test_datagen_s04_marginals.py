"""Regression tests for scenario 8's docs/11 row 8 acceptance gate.

A companion regression test for scenario 5's smaller n_events-margin fix (docs/11 row 5,
`account_takeover_chain`) used to live here too; that scenario was Okta-only and was deleted along
with that source — this project is narrowed to ZScaler web proxy logs only.

Scenario 8 exists specifically to test whether `ml.autoencoder` earns its slot (docs/11): if any
single L3 feature's marginal robust z-score can catch the campaign, the benchmark it feeds is
measuring nothing. `datagen/scenarios/s08_low_and_slow_exfil.py` no longer treats that property as
something to hope emerges from tuned shaping constants — `inject` checks it as a postcondition of
generation (its own `_check_acceptance`) and resamples a fresh victim/placement until a candidate
provably satisfies it, raising `LowAndSlowAcceptanceError` rather than emitting an invalid
scenario if it cannot. This file is the independent second opinion on that guarantee: it re-derives
each feature straight from the *emitted* TSV and `malicious_line_numbers` — not from anything the
scenario computed internally, and not by calling the scenario's own gate — the same way the audit
that originally found scenario 8 leaking on four of six marginal features did. A bug in the
generator's in-memory gate (wrong bucketing, a stale feature) would not be self-confirming here,
because this file never imports `s08_low_and_slow_exfil`'s own aggregation logic.

What *is* shared: `app.detection.features.is_off_hours` and `.robust_z`, the two low-level
formulas both the generator's gate and this audit score against. Before that module existed,
`off_hours_ratio` was defined three times in this codebase (the scenario's own `_is_off_hours`,
this file's independent copy, and never in docs/04 itself) — sharing only the primitives, not the
per-hour aggregation, keeps this file an independent audit while still guaranteeing both sides
agree on what "off hours" and "robust z" actually mean.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.detection.features import ENTITY_WINDOW_FEATURES, is_off_hours, robust_z
from datagen import corpus
from datagen.types import TimeWindow

# Real-scale reproduction, matching docs/11's own eval-file volume target (~50k events) and the
# default 250-user org — the phenomenon this file guards against (a shaped population too thin to
# carry real variance, or too small to size a campaign upload against) is a property of realistic
# scale, not of a shrunken test fixture.
_TOTAL_EVENTS = 50_000
_ORG_SPEC = corpus.OrgSpec()

# docs/04 L2 volumetric-burst threshold, reused here because scenario 8's own design goal (module
# docstring, "no single L2 signal or any single L3 feature's marginal z-score") is stated in
# exactly these terms. This is also the exact bar `s08_low_and_slow_exfil._check_acceptance`
# builds candidates against, so a seed passing generation should always pass this audit too.
_Z_THRESHOLD = 3.5

# The canonical docs/04 L3 feature set scenario 8's acceptance gate is built against
# (`app.detection.features.ENTITY_WINDOW_FEATURES`) — imported, not restated, so this audit and
# the generator's own gate can never silently drift onto different feature lists.
_S08_FEATURES = ENTITY_WINDOW_FEATURES
# A request well under the L1 "large POST" threshold (docs/04, 10 MB) and comfortably above
# anything the campaign's own per-hour budget or the shaped baseline ever emits (both are sized
# in the tens of KB) — large enough that it would only fire on a genuine outlier, never on the
# ordinary traffic either side of this scenario produces.
_LARGE_UPLOAD_BYTES = 1_000_000

# Scenario 8's own `inject` now enforces these checks as a postcondition of generation
# (`_check_acceptance`, resample-until-accept — see that module's docstring), so any seed it
# accepts should pass this independent audit by construction, not by luck. These seeds were
# widened past the original hand-picked three (`2, 5, 11`, which is exactly the overfitting this
# gate exists to end) and spot-checked clean; kept at a representative handful rather than the
# full widened sweep to keep this file's own runtime modest — the gate, not this seed list, is
# what carries the correctness guarantee now.
_S08_SEEDS = (3, 17, 33, 55, 77, 99)


def _median_mad(values: list[float]) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median([abs(v - median) for v in values])
    return median, mad


# ---------------------------------------------------------------------------- scenario 8 (zscaler)


def _generate_s08(seed: int, tmp_path: Path) -> Path:
    written = corpus.run_scenario(
        "low_and_slow_exfil", seed, tmp_path, total_events=_TOTAL_EVENTS, org_spec=_ORG_SPEC
    )
    return next(p for p in written if p.suffix == ".log")


def _s08_hourly_features(
    log_path: Path,
) -> tuple[str, dict[datetime, dict[str, float]], dict[datetime, dict[str, float]]]:
    """Per-`(principal, hour)` feature vectors for the scenario's victim, split into the benign
    and attack populations by `malicious_line_numbers` — independently re-derived from the raw
    TSV, not from anything the scenario computed internally.
    """
    # Single-source scenario (docs/11): `<base>.log` + `<base>.labels.json`.
    labels_path = log_path.with_name(f"{log_path.stem}.labels.json")
    labels = json.loads(labels_path.read_text())
    scenario = labels["scenarios"][0]
    malicious = set(scenario["malicious_line_numbers"])
    victim = scenario["primary_entity"]["value"]

    seed = labels["seed"]
    org = corpus.build_org(seed, corpus.ROLE_EVAL, _ORG_SPEC)
    user = org.get(victim)
    work_hours = user.work_hours

    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {name: i for i, name in enumerate(header)}

    buckets: dict[datetime, list[tuple[bool, list[str]]]] = defaultdict(list)
    for line_no in range(2, len(lines) + 1):
        parts = lines[line_no - 1].split("\t")
        if parts[idx["user"]] != victim:
            continue
        ts = datetime.strptime(parts[idx["datetime"]], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        bucket = ts.replace(minute=0, second=0, microsecond=0)
        buckets[bucket].append((line_no in malicious, parts))

    benign: dict[datetime, dict[str, float]] = {}
    attack: dict[datetime, dict[str, float]] = {}
    for bucket, rows in buckets.items():
        n_events = len(rows)
        bytes_out = sum(int(p[idx["requestsize"]]) for _, p in rows)
        bytes_in = sum(int(p[idx["responsesize"]]) for _, p in rows)
        n_post = sum(1 for _, p in rows if p[idx["requestmethod"]] == "POST")
        n_off = 0
        n_large = 0
        for _, p in rows:
            ts = datetime.strptime(p[idx["datetime"]], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if is_off_hours(ts, work_hours):
                n_off += 1
            if int(p[idx["requestsize"]]) >= _LARGE_UPLOAD_BYTES:
                n_large += 1
        feats = {
            "n_events": float(n_events),
            "bytes_out": float(bytes_out),
            "bytes_in": float(bytes_in),
            "out_in_ratio": bytes_out / max(bytes_in, 1),
            "post_ratio": n_post / n_events,
            "off_hours_ratio": n_off / n_events,
            "n_large_uploads": float(n_large),
        }
        is_attack = any(m for m, _ in rows)
        (attack if is_attack else benign)[bucket] = feats

    return victim, benign, attack


# ---------------------------------------------------------------------------- check 1 + 2


def test_s08_no_single_feature_fires_on_attack_hours(tmp_path: Path) -> None:
    """docs/11 row 8's whole premise: no single L2 signal or L3 feature's marginal robust z-score
    (docs/04, `|z| > 3.5`) may separate an attack hour from the victim's own benign history, for
    any of the six features an earlier repair pass left leaking on four of.
    """
    for seed in _S08_SEEDS:
        log_path = _generate_s08(seed, tmp_path / f"s08-{seed}")
        victim, benign, attack = _s08_hourly_features(log_path)
        assert benign, f"seed={seed} victim={victim}: no benign hours to compare against"
        assert attack, f"seed={seed} victim={victim}: no attack hours found"

        offenders: list[str] = []
        for feature in _S08_FEATURES:
            benign_values = [f[feature] for f in benign.values()]
            max_z = max(abs(robust_z(benign_values, f[feature])) for f in attack.values())
            if max_z > _Z_THRESHOLD:
                offenders.append(f"{feature} (max|z|={max_z:.2f})")
        assert not offenders, (
            f"seed={seed} victim={victim}: single-feature marginal(s) fired: {', '.join(offenders)}"
        )


def test_s08_victim_history_has_real_variance(tmp_path: Path) -> None:
    """Guard against the MAD == 0 artifact (module docstring, "fifth property"): the previous
    version of this scenario passed check 1 vacuously for post_ratio and off_hours_ratio because
    the victim's own benign history had zero variance on both, so a naive detector's
    divide-by-epsilon convention happened to score every attack hour as z == 0. A victim whose
    real POST/evening-activity habit has been established should show genuine spread on both.
    """
    for seed in _S08_SEEDS:
        log_path = _generate_s08(seed, tmp_path / f"s08-var-{seed}")
        victim, benign, _attack = _s08_hourly_features(log_path)

        for feature in ("post_ratio", "off_hours_ratio"):
            values = [f[feature] for f in benign.values()]
            _median, mad = _median_mad(values)
            assert mad > 0, (
                f"seed={seed} victim={victim}: benign {feature} has MAD == 0 "
                f"(values={sorted({round(v, 3) for v in values})}) — check 1 would pass "
                "vacuously via the MAD==0 convention rather than because the feature is "
                "genuinely quiet"
            )


# ---------------------------------------------------------------------------- check 3: joint separation


# Features whose raw scale is heavy-tailed (the natural corpus genuinely contains occasional
# video/large-download browsing hours with bytes_in in the hundreds of thousands, verified against
# real generated output while designing this fix) — log1p'd before standardizing so a single wild
# natural hour cannot inflate that dimension's scale enough to wash out the other six. This mirrors
# why docs/04 specifies a *robust* covariance (MCD) for `ml.mahalanobis` rather than a plain
# sample covariance: the latter is exactly this sensitive to heavy tails.
_LOG_FEATURES = frozenset({"n_events", "bytes_out", "bytes_in", "out_in_ratio", "n_large_uploads"})


def _mahalanobis(benign_matrix: np.ndarray, query_matrix: np.ndarray) -> np.ndarray:
    """Mahalanobis distance of each row of `query_matrix` from `benign_matrix`'s own distribution.

    Log-transforms the heavy-tailed columns (`_LOG_FEATURES`) and standardizes every column by
    `benign_matrix`'s own median/MAD (robust, matching the rest of this file) rather than mean/std
    — a single extreme benign hour should not be able to widen its own column's scale enough to
    make every other dimension look proportionally unremarkable.
    """
    log_mask = np.array([name in _LOG_FEATURES for name in _S08_FEATURES])

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

    cov = np.cov(benign_std, rowvar=False)
    cov = cov + np.eye(cov.shape[0]) * 1e-6  # numerical floor against a near-singular covariance
    inv_cov = np.linalg.pinv(cov)

    return np.sqrt(np.einsum("ij,jk,ik->i", query_std, inv_cov, query_std))


def test_s08_joint_distribution_still_separates(tmp_path: Path) -> None:
    """The other half of the measurement: a scenario invisible to every marginal *and* to the
    joint distribution would be undetectable by anything, including the autoencoder this
    scenario exists to benchmark. At least 70% of attack hours must sit above the victim's own
    benign p95 Mahalanobis distance.
    """
    for seed in _S08_SEEDS:
        log_path = _generate_s08(seed, tmp_path / f"s08-maha-{seed}")
        victim, benign, attack = _s08_hourly_features(log_path)

        benign_matrix = np.array(
            [[f[feat] for feat in _S08_FEATURES] for f in benign.values()], dtype=np.float64
        )
        attack_matrix = np.array(
            [[f[feat] for feat in _S08_FEATURES] for f in attack.values()], dtype=np.float64
        )

        benign_dists = _mahalanobis(benign_matrix, benign_matrix)
        attack_dists = _mahalanobis(benign_matrix, attack_matrix)

        benign_p95 = float(np.percentile(benign_dists, 95))
        above = float(np.mean(attack_dists > benign_p95))
        assert above >= 0.70, (
            f"seed={seed} victim={victim}: only {above:.0%} of attack hours sit above the "
            f"benign p95 Mahalanobis distance ({benign_p95:.2f}); joint distribution no longer "
            "separates the campaign — attack p50="
            f"{float(np.percentile(attack_dists, 50)):.2f}, benign p50="
            f"{float(np.percentile(benign_dists, 50)):.2f}"
        )


# `_s05_attack_hour_n_events_z` / `test_s05_attack_hour_n_events_margin` used to live here,
# auditing `account_takeover_chain`'s (scenario 5) attack-hour volumetric footprint. Deleted along
# with that Okta-only scenario -- see module docstring.


# ---------------------------------------------------------------------------- sanity: window sizing


def test_s08_window_default_matches_scenario_assumptions() -> None:
    """`TimeWindow.of_days` default span backs every duration assumption `s08`'s shaping makes
    (e.g. `mixed_capacity`'s "~2 boundary slots per calendar day"); a docs/11 change to the
    default window would silently invalidate this file's own tuning."""
    window = TimeWindow.of_days(corpus.DEFAULT_WINDOW_DAYS)
    assert window.duration_days == corpus.DEFAULT_WINDOW_DAYS
