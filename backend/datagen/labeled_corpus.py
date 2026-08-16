"""The train/validation/golden labeled corpus (docs/v2_migration change 13) — the successor to
`datagen/generate_corpus.py`, deleted as part of this consolidation.

## Why this module exists

Two independently hand-maintained generators drifted: `generate_corpus.py` wrote
`datetime.strftime("%Y-%m-%d %H:%M:%S")`, `datagen/emitters/zscaler.py` (used by every other
`python -m datagen` command) writes `...THH:MM:SSZ`, and `app/parsers/zscaler.py` only accepts
the latter. Every file `generate_corpus.py` ever produced — the 271 committed under
`backend/data/corpus/` plus the golden split under `backend/data/eval/golden/` — was 100%
unparseable. The fix is not a format patch; it is deleting the second generator and building the
one artifact only it produced (the labeled train/validation/golden split, `manifest.json`, and
per-file `.labels.json` sidecars) on top of the same `datagen` package every other command uses,
so there is exactly one place a log line's shape is decided.

## What carries over from `generate_corpus.py` and what does not

Eight of its eleven scenario keys already existed in `datagen/scenarios/` under the same or a
renamed key (`off_hours_spike` -> `seasonal_deviation`, rewritten with a real statistical
acceptance check rather than a fixed multiplier — see `s06_seasonal_deviation.py`). Two were
genuinely missing and are ported as `s09_multi_domain_c2_failover.py` and
`s10_web_shell_probing.py`. The eleventh, `benign` (a file with no injected scenario at all — the
pure false-positive floor, distinct from `benign_but_weird`'s deliberately suspicious-shaped
control), has no `Scenario` subclass anywhere in the package and does not need one: `_write_benign`
below builds the background stream the same way every other file does and tags a handful of its
already-benign records with a scenario id, which is enough to satisfy
`corpus.write_labeled_files`'s "at least one tagged record" gate without inventing any new
behaviour to inject.

`SHARED_CAMPAIGN_DOMAINS` — the legacy generator's mechanism for making a domain recur across
tenants — is deliberately not ported. `app/scripts/seed_tier2.py` already seeds that cross-tenant
overlap independently and does not import the corpus generator (see its own module docstring), so
nothing downstream depends on this module doing it too.

`build_baseline` (6-month `baseline_*` rollups) is ported as well, on the real `Org`/`User` model
rather than `generate_corpus.py`'s parallel hand-rolled one — `User.events_per_day`,
`.work_hours`, and `.domain_affinity` already carry exactly what the legacy `DEPT_PROFILE` table
was standing in for, so the port removes a table instead of copying one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from app.core.logging import get_logger

from . import corpus
from .org import Org, User
from .realism import DEFAULT_OFFICE_CODES
from .rng import SeededRandom, stable_hash
from .scenarios import get_scenario
from .types import (
    EntityRef,
    GroundTruth,
    LabelSet,
    ScenarioContext,
    SourceType,
    TimeWindow,
)

log = get_logger(__name__)

__all__ = [
    "DEFAULT_SPLITS",
    "SplitSpec",
    "build_baseline",
    "build_labeled_corpus",
    "build_split_org",
]


# ---------------------------------------------------------------------------- split definitions


@dataclass(frozen=True, slots=True)
class SplitSpec:
    """One named split. Seeds and org identities are pinned, not derived from a caller `--seed`
    flag: `seed-state.json`/`corpus-manifest-summary.json` (`evals/validation-run/`) already
    record northwind=42, contoso=1337, fabrikam=90210 as the split identities other evidence
    documents reference, and `app/scripts/seed_tier2.py` seeds `contoso`/`fabrikam` as peer
    tenants by these same names. Changing them here would silently orphan that continuity."""

    name: str
    fraction: float
    org_name: str
    email_domain: str
    seed: int
    n_users: int
    n_service_accounts: int
    out_subdir: str


# 70/10/20 train/val/golden, matching `generate_corpus.py`'s split and the counts already
# evidenced in `evals/validation-run/corpus-manifest-summary.json` (105/30/15 at 150 files).
DEFAULT_SPLITS: Final[tuple[SplitSpec, ...]] = (
    SplitSpec("train", 0.70, "northwind", "northwind.example", 42, 250, 12, "corpus"),
    SplitSpec("val", 0.20, "contoso", "contoso.example", 1337, 180, 8, "corpus"),
    SplitSpec("golden", 0.10, "fabrikam", "fabrikam.example", 90210, 220, 10, "eval/golden"),
)

# Weighted over all eleven scenario identities `generate_corpus.py` distinguished (nine `Scenario`
# subclasses plus the pure-`benign` control); ~25% land on `benign`/`benign_but_weird` as the
# false-positive floor, matching docs/11's "roughly 25% benign as the false-positive control".
_SCENARIO_WEIGHTS: Final[dict[str, float]] = {
    "c2_beaconing": 0.12,
    "data_exfiltration": 0.10,
    "low_and_slow_exfil": 0.10,
    "insider_mass_download": 0.07,
    "multi_domain_c2_failover": 0.08,
    "web_shell_probing": 0.08,
    "peer_group_deviation": 0.09,
    "seasonal_deviation": 0.08,
    "prompt_injection_canary": 0.03,
    "benign_but_weird": 0.10,
    "benign": 0.15,
}

# One difficulty knob swept per scenario (docs/11 "Parameterization" — a curve beats a point
# estimate), named against each `Scenario` subclass's real `__init__` parameter rather than
# `generate_corpus.py`'s ad hoc dict keys. `None` means the scenario takes no meaningful sweep
# axis for this corpus (benign has no scenario at all; benign_but_weird's difficulty is which
# flavour it draws, an internal choice, not a knob).
_DIFFICULTY: Final[dict[str, tuple[str, tuple[Any, ...]] | None]] = {
    "c2_beaconing": ("jitter_pct", (0.02, 0.05, 0.10, 0.18, 0.28, 0.40, 0.55)),
    "data_exfiltration": ("chunk_mb", (8.0, 20.0, 45.0, 90.0, 160.0)),
    "low_and_slow_exfil": ("mean_upload_kb", (250.0, 500.0, 900.0, 1800.0, 3200.0)),
    "insider_mass_download": ("n_downloads", (200, 350, 550, 850)),
    "multi_domain_c2_failover": ("jitter_pct", (0.05, 0.15, 0.30, 0.45)),
    "web_shell_probing": ("n_probes", (15, 40, 90, 180, 320)),
    "peer_group_deviation": ("n_campaign_hours", (10, 20, 30, 40)),
    "seasonal_deviation": ("campaign_days", (2.0, 4.0, 6.5, 9.0)),
    "prompt_injection_canary": ("n_requests", (12, 24, 40, 60)),
    "benign_but_weird": None,
    "benign": None,
}

_DEFAULT_EVENTS_PER_FILE: Final[int] = 3_000
# The three scenarios with a real statistical acceptance check (`*AcceptanceError` in their own
# modules) need enough background density for their own cohort/history statistics to be
# meaningful — verified empirically: below roughly this floor, `peer_group_deviation` in
# particular fails its own acceptance check often enough to threaten forced-coverage slots.
# Every other scenario is fine at `_DEFAULT_EVENTS_PER_FILE`, and keeping the floor scenario-
# specific rather than raising the corpus-wide default keeps the common case small.
_MIN_EVENTS_FOR_SCENARIO: Final[dict[str, int]] = {
    "peer_group_deviation": 10_000,
    "seasonal_deviation": 8_000,
    "low_and_slow_exfil": 8_000,
}
# How many already-benign background records a pure-`benign` file tags with its scenario id —
# just enough to satisfy `write_labeled_files`'s "at least one record references this
# GroundTruth" gate. `malicious_line_numbers` still comes out empty, because none of them are
# `malicious=True`, which is the entire point of this scenario identity.
_BENIGN_TAG_SAMPLE: Final[int] = 5
_MAX_INJECT_ATTEMPTS: Final[int] = 3


def build_split_org(spec: SplitSpec) -> Org:
    """The `Org` for one named split — same identity every time (`spec.seed` scoped through
    `role_seed`), reused both when building the corpus and, for `train`, when building the
    baseline (`python -m datagen split`'s `--skip-baseline`-guarded step)."""
    return Org(
        n_users=spec.n_users,
        n_departments=8,
        offices=DEFAULT_OFFICE_CODES,
        n_service_accounts=spec.n_service_accounts,
        seed=corpus.role_seed(spec.seed, f"split:{spec.name}"),
        email_domain=spec.email_domain,
        name=spec.org_name,
    )


def _weighted_scenario_key(rng: SeededRandom) -> str:
    keys = tuple(_SCENARIO_WEIGHTS)
    weights = tuple(_SCENARIO_WEIGHTS[k] for k in keys)
    return rng.weighted_choice(keys, weights)


def _knobs_for(rng: SeededRandom, key: str) -> dict[str, Any]:
    axis = _DIFFICULTY[key]
    if axis is None:
        return {}
    name, choices = axis
    return {name: rng.choice(choices)}


# ---------------------------------------------------------------------------- one file


def _write_benign(
    *,
    background: list[Any],
    org: Org,
    window: TimeWindow,
    split_seed: int,
    out_dir: Path,
    base_name: str,
    scenario_id: str,
    root: SeededRandom,
) -> list[Path]:
    """The pure false-positive control: background traffic, nothing injected on top."""
    tag_n = min(_BENIGN_TAG_SAMPLE, len(background))
    for record in root.substream("tag").sample(background, tag_n):
        record.scenario_id = scenario_id  # already malicious=False by construction

    victim = org.pick_user(root.substream("entity"))
    gt = GroundTruth(
        scenario_id=scenario_id,
        technique=None,
        primary_entity=EntityRef(type="user", value=victim.principal),
        expected_detectors=[],
        expected_disposition="benign",
        must_correlate_into_one_incident=False,
        notes="pure benign background, no scenario events injected",
    )
    return corpus.write_labeled_files(
        stream=background,
        ground_truths=[gt],
        org=org,
        seed=split_seed,
        window=window,
        out_dir=out_dir,
        base_name=base_name,
    )


def _build_one_file(
    *,
    scenario_key: str,
    file_index: int,
    attempt: int,
    type_index: int,
    org: Org,
    window: TimeWindow,
    split_seed: int,
    out_dir: Path,
    base_name: str,
    total_events: int,
    knobs: dict[str, Any],
) -> list[Path]:
    """Mirrors `corpus.run_scenario`'s body, except the RNG root varies per *file* (and per retry
    `attempt`), not just per scenario key. `run_scenario` derives its root from
    `(cli_seed, ROLE_EVAL)` alone, which is exactly right for its own contract (one file per
    scenario key per `all` run) but would make every file in a many-files-per-key split share
    byte-identical background traffic if reused here unchanged — and folding in `attempt` means a
    retry after a failed acceptance check draws genuinely fresh background, not a replay of the
    same draw under a different scenario label."""
    root = SeededRandom(corpus.role_seed(split_seed, f"file:{file_index:04d}:{attempt}"))
    background = corpus.generate_scenario_background(
        org, root.substream("benign"), window, (SourceType.ZSCALER,), total_events
    )
    scenario_id = f"{scenario_key}_{type_index:03d}"

    if scenario_key == "benign":
        return _write_benign(
            background=background,
            org=org,
            window=window,
            split_seed=split_seed,
            out_dir=out_dir,
            base_name=base_name,
            scenario_id=scenario_id,
            root=root,
        )

    scenario_cls = get_scenario(scenario_key)
    scenario = scenario_cls(**knobs)
    scenario_rng = root.substream(f"scenario:{scenario_key}:{type_index}")
    ctx = ScenarioContext(
        org=org, rng=scenario_rng, window=window, stream=background, scenario_id=scenario_id
    )
    gt = scenario.inject(ctx)
    return corpus.write_labeled_files(
        stream=ctx.stream,
        ground_truths=[gt],
        org=org,
        seed=split_seed,
        window=window,
        out_dir=out_dir,
        base_name=base_name,
    )


def _allocate_counts(total_files: int, splits: tuple[SplitSpec, ...]) -> list[int]:
    """`int(total * fraction)` per split, remainder absorbed by the last split — the same
    truncate-then-absorb rule `generate_corpus.py`'s `main()` used for 70/20/10."""
    counts = [int(total_files * s.fraction) for s in splits[:-1]]
    counts.append(total_files - sum(counts))
    return counts


def _forced_coverage_keys(spec: SplitSpec, count: int) -> dict[int, str]:
    """`{slot: scenario_key}` for the train split's first `len(_SCENARIO_WEIGHTS)` slots, empty
    for every other split. See `build_labeled_corpus`'s comment for why."""
    if spec.name != DEFAULT_SPLITS[0].name:
        return {}
    keys = tuple(_SCENARIO_WEIGHTS)
    return dict(enumerate(keys[:count]))


# ---------------------------------------------------------------------------- driver


def build_labeled_corpus(
    root_out: Path,
    *,
    total_files: int = 1000,
    events_per_file: int = _DEFAULT_EVENTS_PER_FILE,
    splits: tuple[SplitSpec, ...] = DEFAULT_SPLITS,
) -> dict[str, Any]:
    """Write the labeled train/validation/golden corpus and `manifest.json`.

    `manifest.json`'s shape (`splits`, `scenario_counts`, `files`) matches
    `evals/validation-run/corpus-manifest-summary.json`, produced by the file this replaces.
    """
    if total_files < len(splits):
        raise ValueError(f"total_files must be >= {len(splits)} (one per split)")

    manifest: dict[str, Any] = {"splits": {}, "scenario_counts": {}, "files": []}
    counts = _allocate_counts(total_files, splits)

    for spec, count in zip(splits, counts, strict=True):
        org = build_split_org(spec)
        window = TimeWindow.of_days(corpus.DEFAULT_WINDOW_DAYS)
        out_dir = root_out / spec.out_subdir
        plan_root = SeededRandom(corpus.role_seed(spec.seed, "plan"))
        type_counts: dict[str, int] = {}
        # The largest split reserves its first slots, one per scenario identity, so a small
        # `--files` run still proves every scenario type parses instead of leaving weighted-random
        # selection to maybe skip `prompt_injection_canary` (weight 0.03) entirely — a real risk
        # at corpus sizes far below 1000. Every other slot in every split is still weighted-random.
        forced_keys = _forced_coverage_keys(spec, count)

        log.info("split.start", split=spec.name, count=count, org=org.name)
        for i in range(count):
            written = _generate_one_slot(
                plan_root=plan_root,
                slot=i,
                org=org,
                window=window,
                split=spec,
                out_dir=out_dir,
                events_per_file=events_per_file,
                type_counts=type_counts,
                forced_key=forced_keys.get(i),
            )
            log_path = next(p for p in written if p.suffix == ".log")
            labels_path = next(p for p in written if p.name.endswith(".labels.json"))
            labels = LabelSet.from_json(labels_path.read_text())
            gt = labels.scenarios[0]
            scenario_key = gt.scenario_id.rsplit("_", 1)[0]
            manifest["scenario_counts"][scenario_key] = (
                manifest["scenario_counts"].get(scenario_key, 0) + 1
            )
            manifest["files"].append(
                {
                    "scenario_id": gt.scenario_id,
                    "scenario": scenario_key,
                    "split": spec.name,
                    "technique": gt.technique,
                    "total_lines": labels.total_lines,
                    "expected_disposition": gt.expected_disposition,
                    "log_file": str(log_path.relative_to(root_out)),
                }
            )
        manifest["splits"][spec.name] = {
            "count": count,
            "org": org.name,
            "seed": spec.seed,
            "users": len(org.principals),
            "dir": f"data/{spec.out_subdir}",
        }
        log.info("split.done", split=spec.name, count=count)

    (root_out / "corpus").mkdir(parents=True, exist_ok=True)
    (root_out / "corpus" / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def _generate_one_slot(
    *,
    plan_root: SeededRandom,
    slot: int,
    org: Org,
    window: TimeWindow,
    split: SplitSpec,
    out_dir: Path,
    events_per_file: int,
    type_counts: dict[str, int],
    forced_key: str | None,
) -> list[Path]:
    """Pick a scenario + knobs for file `slot` and build it, falling back to a `benign` file if
    the scenario's own acceptance check can't be satisfied for this particular RNG draw (the
    statistically-verified scenarios — seasonal deviation, peer-group deviation, low-and-slow
    exfil — raise rather than silently emit an unverified file; a corpus build should not crash
    over one unlucky draw, so it retries with fresh randomness and then degrades to `benign`).
    `forced_key`, when given, pins the scenario identity across every retry (coverage slots must
    still produce that scenario, not a random substitute) — only the content RNG varies attempt
    to attempt."""
    plan_rng = plan_root.substream(f"pick:{slot:04d}")
    for attempt in range(_MAX_INJECT_ATTEMPTS):
        key = forced_key or _weighted_scenario_key(plan_rng.substream(f"attempt:{attempt}"))
        type_counts[key] = type_counts.get(key, 0) + 1
        knobs = _knobs_for(plan_rng.substream(f"knob:{attempt}"), key)
        base_name = f"{split.name}_{slot:04d}_{key}"
        try:
            return _build_one_file(
                scenario_key=key,
                file_index=slot,
                attempt=attempt,
                type_index=type_counts[key],
                org=org,
                window=window,
                split_seed=split.seed,
                out_dir=out_dir,
                base_name=base_name,
                total_events=max(events_per_file, _MIN_EVENTS_FOR_SCENARIO.get(key, 0)),
                knobs=knobs,
            )
        except Exception:  # deliberately broad — see docstring
            type_counts[key] -= 1
            log.warning(
                "split.slot.retry", split=split.name, slot=slot, scenario=key, attempt=attempt
            )

    if forced_key is not None:
        # `benign` cannot itself fail its acceptance check (it has none), so this is always the
        # last word for a slot rather than a fourth unprotected attempt — a coverage gap for one
        # scenario identity is preferable to a crashed corpus build.
        log.warning("split.slot.coverage_gap", split=split.name, slot=slot, scenario=forced_key)

    key = "benign"
    type_counts[key] = type_counts.get(key, 0) + 1
    base_name = f"{split.name}_{slot:04d}_{key}"
    return _build_one_file(
        scenario_key=key,
        file_index=slot,
        attempt=_MAX_INJECT_ATTEMPTS,
        type_index=type_counts[key],
        org=org,
        window=window,
        split_seed=split.seed,
        out_dir=out_dir,
        base_name=base_name,
        total_events=events_per_file,
        knobs={},
    )


# ---------------------------------------------------------------------------- baseline


# Six months of per-entity rollups, loaded into `baseline_*` tables. Ported from
# `generate_corpus.py`'s `build_baseline` onto the real `Org`/`User` model: `events_per_day`,
# `work_hours`, and `domain_affinity` already carry what its parallel `DEPT_PROFILE` table stood
# in for, one fewer hand-authored table to drift out of sync with the org model it describes.
_BASELINE_START: Final[datetime] = datetime(2025, 9, 1, tzinfo=UTC)


def _off_hours_fraction(user: User) -> float:
    span = user.work_hours.end_h - user.work_hours.start_h
    return max(0.0, min(1.0, (24.0 - span) / 24.0))


def _user_profile(user: User) -> dict[str, float]:
    """Deterministic per-user behavioural ratios — no hand-authored per-department table, derived
    instead from the user's own already-modeled `work_hours`/`is_service_account`, plus a stable
    hash of department name so departments still separate from one another without a table
    someone has to remember to extend when `org.py`'s department list changes."""
    jitter = (stable_hash(user.department) % 1000) / 1000.0
    if user.is_service_account:
        return {
            "post_ratio": 0.35 + 0.10 * jitter,
            "off_hours_ratio": 0.9,
            "automation_ua_ratio": 0.95,
            "direct_ip_ratio": 0.03 * jitter,
        }
    return {
        "post_ratio": 0.08 + 0.12 * jitter,
        "off_hours_ratio": _off_hours_fraction(user),
        "automation_ua_ratio": 0.02 + 0.05 * jitter,
        "direct_ip_ratio": 0.01 * jitter,
    }


def build_baseline(org: Org, out_dir: Path, seed: int, *, months: int = 6) -> dict[str, int]:
    """Write `baseline_windows.jsonl` / `baseline_profiles.json` / `baseline_contacts.json`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    root = SeededRandom(corpus.role_seed(seed, "baseline"))
    n_windows = months * 30 * 24

    contacts: dict[tuple[str, str], int] = {}
    windows: list[dict[str, Any]] = []
    for user in org.principals:
        rng = root.substream(f"user:{user.username}")
        profile = _user_profile(user)
        for domain in user.domain_affinity:
            contacts[(user.email, domain)] = contacts.get((user.email, domain), 0) + rng.randint(
                200, 9000
            )

        daily_mean = max(1, user.events_per_day)
        for w in range(0, n_windows, 6):
            ts = _BASELINE_START + timedelta(hours=w)
            local_hour = (ts.hour + user.work_hours.tz_offset_h) % 24
            is_off_hours = not (user.work_hours.start_h <= local_hour < user.work_hours.end_h)
            weight = profile["off_hours_ratio"] if is_off_hours else 1.0
            if weight < 0.05 and rng.random() > 0.15:
                continue
            n_events = max(1, int(abs(rng.normal(daily_mean / 4.0 * weight, daily_mean / 8.0 + 1))))
            windows.append(
                {
                    "entity_type": "user",
                    "entity_value": user.email,
                    "window_start": ts.isoformat(),
                    "features": {
                        "n_events": n_events,
                        "n_unique_domains": max(1, int(n_events * rng.uniform(0.10, 0.35))),
                        "bytes_out": int(abs(rng.normal(2_400_000, 900_000)) * weight + 1_000),
                        "bytes_in": int(abs(rng.normal(28_000_000, 9_000_000)) * weight + 5_000),
                        "post_ratio": round(
                            min(0.9, abs(rng.normal(profile["post_ratio"], 0.05))), 4
                        ),
                        "blocked_ratio": round(min(0.5, abs(rng.normal(0.05, 0.02))), 4),
                        "off_hours_ratio": round(
                            min(1.0, abs(rng.normal(profile["off_hours_ratio"], 0.04))), 4
                        ),
                        "automation_ua_ratio": round(
                            min(1.0, abs(rng.normal(profile["automation_ua_ratio"], 0.03))), 4
                        ),
                        "direct_ip_ratio": round(
                            min(1.0, abs(rng.normal(profile["direct_ip_ratio"], 0.01))), 4
                        ),
                    },
                }
            )

    profiles: dict[str, dict[str, Any]] = {}
    for metric in ("n_events", "bytes_out", "bytes_in", "n_unique_domains"):
        by_user: dict[str, list[float]] = {}
        for w in windows:
            by_user.setdefault(w["entity_value"], []).append(w["features"][metric])
        for uname, vals in by_user.items():
            vals.sort()
            n = len(vals)
            median = vals[n // 2]
            profiles[f"{uname}|{metric}"] = {
                "entity_type": "user",
                "entity_value": uname,
                "metric": metric,
                "p50": median,
                "p95": vals[int(n * 0.95)],
                "p99": vals[int(n * 0.99)],
                "mean": sum(vals) / n,
                "mad": sorted(abs(v - median) for v in vals)[n // 2],
                "n_windows": n,
            }

    (out_dir / "baseline_windows.jsonl").write_text("\n".join(json.dumps(w) for w in windows))
    (out_dir / "baseline_profiles.json").write_text(json.dumps(profiles, indent=2))
    (out_dir / "baseline_contacts.json").write_text(
        json.dumps(
            [
                {"scope": "user", "scope_value": u, "domain": d, "contact_count": c}
                for (u, d), c in contacts.items()
            ],
            indent=2,
        )
    )
    return {"windows": len(windows), "profiles": len(profiles), "contacts": len(contacts)}
