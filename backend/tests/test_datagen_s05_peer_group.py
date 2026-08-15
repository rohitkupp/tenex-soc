"""Regression tests for scenario 5's docs/11 row 5 acceptance gate
(`datagen/scenarios/s05_peer_group_deviation.py`).

Independent audit, in the same spirit as `test_datagen_s04_marginals.py`: re-derives every
feature straight from the *emitted* TSV and `malicious_line_numbers`, not from anything the
scenario computed internally, and does not import `s05_peer_group_deviation`'s own bucketing or
Mahalanobis helpers. A bug in the generator's in-memory gate (wrong bucketing, a stale feature)
would not be self-confirming here.

What *is* shared with the scenario under audit: `app.detection.features.robust_z` (the canonical
docs/04 formula) and the same `_DEV_CATEGORIES` set (a fixed, small, documented constant --
verified to match `s05_peer_group_deviation.py`'s own copy by
`test_dev_categories_match_the_scenario_under_audit` below, so the two cannot silently drift
without a test catching it).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import numpy as np

from app.detection.features import robust_z
from datagen import corpus
from datagen.scenarios.s05_peer_group_deviation import _DEV_CATEGORIES

_TOTAL_EVENTS = 50_000
_ORG_SPEC = corpus.OrgSpec()

# Mirrors `s05_peer_group_deviation.py`'s own thresholds -- this is the audited claim, not a
# looser tolerance for the test.
_ORG_MARGINAL_Z_THRESHOLD = 3.5
_ORG_JOINT_MAX_SEPARATION = 0.35
_COHORT_JOINT_MIN_SEPARATION = 0.70

_MARGINAL_FEATURES = ("n_events", "bytes_out", "bytes_in")
_ALL_FEATURES = (
    "n_events",
    "bytes_out",
    "bytes_in",
    "n_unique_domains",
    "dev_domain_ratio",
    "post_ratio",
)
_LOG_FEATURES = frozenset({"n_events", "bytes_out", "bytes_in"})

# A representative handful of seeds, not an exhaustive sweep -- the acceptance gate inside
# `inject` (resample-until-accept) is what carries the correctness guarantee; this file spot-
# checks that seeds it actually accepts really do satisfy the claim when re-measured
# independently, the same posture `test_datagen_s04_marginals.py` takes for scenario 4.
_S05_SEEDS = (3, 17, 33, 55, 77)


def test_dev_categories_match_the_scenario_under_audit() -> None:
    """Guards this file's independence claim: if `s05_peer_group_deviation.py`'s own
    `_DEV_CATEGORIES` ever changes, this file must be updated deliberately, not silently start
    auditing a different (and therefore meaningless) domain set."""
    assert frozenset({"engineering", "cloud", "data", "observability"}) == _DEV_CATEGORIES


def _generate(seed: int, tmp_path: Path) -> Path:
    written = corpus.run_scenario(
        "peer_group_deviation", seed, tmp_path, total_events=_TOTAL_EVENTS, org_spec=_ORG_SPEC
    )
    return next(p for p in written if p.suffix == ".log")


def _read_labels(log_path: Path) -> dict:
    labels_path = log_path.with_name(f"{log_path.stem}.labels.json")
    return json.loads(labels_path.read_text())


def _bucket_features(
    rows: list[list[str]], idx: dict[str, int], dev_domains: frozenset[str]
) -> dict[tuple[str, datetime], dict[str, float]]:
    buckets: dict[tuple[str, datetime], list[list[str]]] = {}
    for parts in rows:
        ts = datetime.strptime(parts[idx["datetime"]], "%Y-%m-%dT%H:%M:%SZ")
        hour = ts.replace(minute=0, second=0, microsecond=0)
        buckets.setdefault((parts[idx["user"]], hour), []).append(parts)

    out: dict[tuple[str, datetime], dict[str, float]] = {}
    for key, group in buckets.items():
        n = len(group)
        bytes_out = sum(int(p[idx["requestsize"]]) for p in group)
        bytes_in = sum(int(p[idx["responsesize"]]) for p in group)
        hosts = {p[idx["host"]] for p in group}
        n_dev = sum(1 for p in group if p[idx["host"]] in dev_domains)
        n_post = sum(1 for p in group if p[idx["requestmethod"]] == "POST")
        out[key] = {
            "n_events": float(n),
            "bytes_out": float(bytes_out),
            "bytes_in": float(bytes_in),
            "n_unique_domains": float(len(hosts)),
            "dev_domain_ratio": n_dev / n,
            "post_ratio": n_post / n,
        }
    return out


def _mahalanobis(reference: np.ndarray, query: np.ndarray) -> np.ndarray:
    log_mask = np.array([name in _LOG_FEATURES for name in _ALL_FEATURES])

    def transform(matrix: np.ndarray) -> np.ndarray:
        out = matrix.copy()
        out[:, log_mask] = np.log1p(out[:, log_mask])
        return out

    ref_t, query_t = transform(reference), transform(query)
    median = np.median(ref_t, axis=0)
    mad = np.median(np.abs(ref_t - median), axis=0)
    mad[mad == 0] = 1.0
    ref_std = (ref_t - median) / mad
    query_std = (query_t - median) / mad
    cov = np.cov(ref_std, rowvar=False) + np.eye(ref_std.shape[1]) * 1e-6
    inv_cov = np.linalg.pinv(cov)
    return np.sqrt(np.einsum("ij,jk,ik->i", query_std, inv_cov, query_std))


def _matrix(features: dict[tuple[str, datetime], dict[str, float]]) -> np.ndarray:
    return np.array(
        [[f[name] for name in _ALL_FEATURES] for f in features.values()], dtype=np.float64
    )


def _load(log_path: Path) -> tuple[dict, list[list[str]], dict[str, int], set[int]]:
    labels = _read_labels(log_path)
    scenario = labels["scenarios"][0]
    malicious = set(scenario["malicious_line_numbers"])

    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {name: i for i, name in enumerate(header)}
    rows = [line.split("\t") for line in lines[1:]]
    return scenario, rows, idx, malicious


def test_s05_org_wide_marginal_blindness_and_cohort_separation(tmp_path: Path) -> None:
    """docs/11 row 5 / docs/12 prediction 2, re-measured independently from the emitted file:
    the campaign's marginal well-behaved features (`n_events`, `bytes_out`, `bytes_in`) never
    exceed the docs/04 robust-z threshold against the *org-wide* population, and the campaign's
    joint (Mahalanobis) distance against the victim's own *department cohort* separates clearly.
    """
    org = corpus.build_org(_S05_SEEDS[0], corpus.ROLE_EVAL, _ORG_SPEC)
    dev_domains = frozenset(a.domain for a in org.saas_apps if a.category in _DEV_CATEGORIES)

    for seed in _S05_SEEDS:
        log_path = _generate(seed, tmp_path / f"s05-{seed}")
        scenario, rows, idx, malicious = _load(log_path)
        victim = scenario["primary_entity"]["value"]

        org_for_seed = corpus.build_org(seed, corpus.ROLE_EVAL, _ORG_SPEC)
        victim_user = org_for_seed.get(victim)
        home_dept = victim_user.department
        cohort_principals = {u.principal for u in org_for_seed.department_members(home_dept)}

        benign_rows = [p for i, p in enumerate(rows, start=2) if i not in malicious]
        attack_rows = [p for i, p in enumerate(rows, start=2) if i in malicious]
        assert attack_rows, f"seed={seed}: no malicious rows found"

        org_pop = _bucket_features(benign_rows, idx, dev_domains)
        cohort_pop = {k: v for k, v in org_pop.items() if k[0] in cohort_principals}
        attack_buckets = _bucket_features(attack_rows, idx, dev_domains)

        # (a) org-wide marginal blindness on the well-behaved features.
        offenders = []
        for feature in _MARGINAL_FEATURES:
            values = [f[feature] for f in org_pop.values()]
            max_z = max(abs(robust_z(values, f[feature])) for f in attack_buckets.values())
            if max_z > _ORG_MARGINAL_Z_THRESHOLD:
                offenders.append(f"{feature} (max|z|={max_z:.2f})")
        assert not offenders, (
            f"seed={seed} victim={victim}: org-wide marginal(s) fired: {offenders}"
        )

        # (b) org-wide joint blindness.
        org_matrix, attack_matrix = _matrix(org_pop), _matrix(attack_buckets)
        org_dists = _mahalanobis(org_matrix, org_matrix)
        attack_vs_org = _mahalanobis(org_matrix, attack_matrix)
        org_p95 = float(np.percentile(org_dists, 95))
        above_org = float(np.mean(attack_vs_org > org_p95))
        assert above_org <= _ORG_JOINT_MAX_SEPARATION, (
            f"seed={seed} victim={victim}: org-wide joint separation {above_org:.0%} exceeds "
            f"{_ORG_JOINT_MAX_SEPARATION:.0%} -- a global joint model would flag this campaign"
        )

        # (c) cohort joint separation.
        cohort_matrix = _matrix(cohort_pop)
        cohort_dists = _mahalanobis(cohort_matrix, cohort_matrix)
        attack_vs_cohort = _mahalanobis(cohort_matrix, attack_matrix)
        cohort_p95 = float(np.percentile(cohort_dists, 95))
        above_cohort = float(np.mean(attack_vs_cohort > cohort_p95))
        assert above_cohort >= _COHORT_JOINT_MIN_SEPARATION, (
            f"seed={seed} victim={victim} home_dept={home_dept}: cohort separation "
            f"{above_cohort:.0%} below {_COHORT_JOINT_MIN_SEPARATION:.0%}"
        )


def test_s05_campaign_dev_domain_ratio_is_far_above_home_cohorts_own_baseline(
    tmp_path: Path,
) -> None:
    """A simpler, more legible companion to the Mahalanobis check above: the raw
    `dev_domain_ratio` the campaign shows is far higher than what the victim's own department
    cohort ever produces naturally -- the plain-English version of "locally anomalous"."""
    for seed in _S05_SEEDS[:3]:
        log_path = _generate(seed, tmp_path / f"s05-ratio-{seed}")
        scenario, rows, idx, malicious = _load(log_path)
        victim = scenario["primary_entity"]["value"]

        org = corpus.build_org(seed, corpus.ROLE_EVAL, _ORG_SPEC)
        dev_domains = frozenset(a.domain for a in org.saas_apps if a.category in _DEV_CATEGORIES)
        home_dept = org.get(victim).department
        cohort_principals = {u.principal for u in org.department_members(home_dept)}

        benign_rows = [p for i, p in enumerate(rows, start=2) if i not in malicious]
        attack_rows = [p for i, p in enumerate(rows, start=2) if i in malicious]

        cohort_rows = [p for p in benign_rows if p[idx["user"]] in cohort_principals]
        cohort_dev = sum(1 for p in cohort_rows if p[idx["host"]] in dev_domains)
        cohort_ratio = cohort_dev / len(cohort_rows) if cohort_rows else 0.0

        attack_dev = sum(1 for p in attack_rows if p[idx["host"]] in dev_domains)
        attack_ratio = attack_dev / len(attack_rows) if attack_rows else 0.0

        assert attack_ratio > 0.9, f"seed={seed}: campaign dev_domain_ratio only {attack_ratio:.2f}"
        # A relative/gap comparison rather than an absolute near-zero bound: the cohort's own
        # pooled, event-level dev-domain rate is a different statistic from the scenario's own
        # per-bucket-averaged `dev_domain_ratio` feature and is not itself expected to be near
        # zero (every principal has *some* chance of a dev-domain visit via ordinary Zipf domain
        # sampling, `datagen/org.py`) -- what has to hold is that the campaign is dramatically
        # more dev-domain-heavy than the department it was injected into, not that the department
        # never touches these domains at all.
        assert attack_ratio > cohort_ratio + 0.5 and attack_ratio > cohort_ratio * 5, (
            f"seed={seed} home_dept={home_dept}: campaign ratio {attack_ratio:.3f} is not "
            f"dramatically above the cohort's own pooled rate {cohort_ratio:.3f}"
        )


def test_s05_ground_truth_verified_against_emitted_lines(tmp_path: Path) -> None:
    """Sanity check in the `test_datagen_ground_truth.py` spirit: every malicious line actually
    contains the victim's own principal and one of the dev domains named in the scenario's own
    notes, and no non-malicious line for that principal in the campaign window is missing from
    the label by construction (the label is exactly the scenario's own injected records)."""
    log_path = _generate(_S05_SEEDS[0], tmp_path)
    scenario, rows, idx, _malicious = _load(log_path)
    victim = scenario["primary_entity"]["value"]

    org = corpus.build_org(_S05_SEEDS[0], corpus.ROLE_EVAL, _ORG_SPEC)
    dev_domains = frozenset(a.domain for a in org.saas_apps if a.category in _DEV_CATEGORIES)

    for line_no in scenario["malicious_line_numbers"]:
        parts = rows[line_no - 2]
        assert parts[idx["user"]] == victim, f"line {line_no} is not the victim's own principal"
        assert parts[idx["host"]] in dev_domains, f"line {line_no} host is not a dev domain"

    assert len(scenario["malicious_line_numbers"]) == len(set(scenario["malicious_line_numbers"]))
    assert scenario["expected_detectors"] == ["ml.peer_group"]
    assert scenario["expected_disposition"] == "true_positive"
    assert scenario["must_correlate_into_one_incident"] is True
