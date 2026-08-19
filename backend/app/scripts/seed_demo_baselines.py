"""Six months of baseline history for the demo tenant, derived from the demo logs themselves.

## Why this exists

`GET /overview`'s "volume vs. baseline" and the Evidence tab's percentile annotations both read
the baseline store (`app.baseline.resolve`), and both were showing `insufficient history (n=0)`:
the destructive migration round trip dropped and recreated the three baseline tables, and the
exact-tree deploy then removed the generated `data/baseline/*` files that could have reloaded
them. Restoring from the generator is no longer possible — see below — so this script derives a
baseline from the committed demo logs instead.

## Why the datagen path cannot be used

`make gen-data`'s baseline is built from `build_split_org(train)`, and the demo scenarios in
`data/demo5` / `data/demo5_tiny` were generated from a *different* org. Their labels record
`seed: 900` and an `org_fingerprint`, but no role/seed combination in today's generator
reproduces that fingerprint — `datagen/` has not changed since the files were committed, so they
were produced by an even older working state that no longer exists. A baseline for the train
org would leave every user the demo actually renders at `insufficient_history` forever, which is
exactly the symptom being fixed.

## What "derived from the logs" means

The scenario labels mark every malicious line. The benign remainder of each log *is* a sample of
each principal's normal behaviour — who they are, which domains they routinely touch, how much
they move, what their URL paths look like. This script treats that sample as the observable
slice of a six-month history and simulates the rest of it consistently (seeded, deterministic):

* **Windows are daily**, `2025-09-01` through the day before the earliest demo event. Daily
  rather than the generator's hourly, deliberately: the Overview compares each user's
  *analysis-total* event count against these percentiles, while burst/STL evidence compares
  *hourly* counts. No single granularity serves both exactly; daily keeps benign users
  mid-distribution on the Overview (a 4-event user is unremarkable against a ~5-events/day
  history) while a real burst — 28 events in one hour from a 3-events/day principal — still
  clears the evidence layer's nomination threshold against the same rows.
* **Malicious lines are excluded from every statistic.** Attack domains stay first-contact,
  exfil volume stays extreme against the history, and injected URL paths do not inflate the
  entropy baseline. This is what makes the demo's signals *stay* signals after the baseline
  loads.
* **Entropy uses the evidence layer's own `shannon_entropy`** over the same `url_path` slice,
  so the baseline and the thing compared against it are the same quantity by construction.

Profiles cover every `(entity_type, metric)` pair the code actually queries — enumerated from
`app.api.analyses._compute_notable_users` and every `BaselineQuery` in
`app.detection.evidence.*`: `user × {n_events, bytes_out, bytes_in, n_unique_domains}`,
`src_ip × {n_events, beaconing_requests, url_path_entropy}`, and `org × n_events`.

Output goes through `app.baseline.loader.load_baseline` — the same idempotent upsert path as
the real generator's files, into the live tenant. Re-running is safe and converges.

    python -m app.scripts.seed_demo_baselines [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import tempfile
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from app.baseline.loader import load_baseline
from app.core.db import get_session_factory
from app.core.logging import get_logger
from app.detection.features import shannon_entropy
from app.models.tenant import get_or_create_live_tenant

log = get_logger(__name__)

_SEED: Final[int] = 900  # the demo scenarios' own recorded seed — determinism, and provenance
_BASELINE_START: Final[datetime] = datetime(2025, 9, 1, tzinfo=UTC)
_DEMO_DIRS: Final[tuple[str, ...]] = ("data/demo5", "data/demo5_tiny")

# Header of the ZScaler NSS TSV the demo logs use.
_COLS: Final[tuple[str, ...]] = (
    "datetime", "user", "clientip", "serverip", "host", "url", "requestmethod",
    "status", "requestsize", "responsesize", "useragent", "action", "urlcategory", "urls",
)


class _EntityStats:
    __slots__ = ("events", "bytes_out", "bytes_in", "domains", "days", "entropies")

    def __init__(self) -> None:
        self.events = 0
        self.bytes_out = 0
        self.bytes_in = 0
        self.domains: dict[str, int] = defaultdict(int)
        self.days: set[str] = set()
        self.entropies: list[float] = []


def _malicious_lines(labels_path: Path) -> set[int]:
    doc = json.loads(labels_path.read_text(encoding="utf-8"))
    out: set[int] = set()
    for scenario in doc.get("scenarios", []):
        out.update(int(n) for n in scenario.get("malicious_line_numbers", []))
    return out


def _observe(root: Path) -> tuple[dict[str, _EntityStats], dict[str, _EntityStats], datetime]:
    """Benign-only stats per user and per src_ip across every demo log, plus the earliest
    event timestamp seen anywhere (malicious included — the baseline must end before *all*
    demo traffic, or 'history' would overlap the events it is history for)."""
    users: dict[str, _EntityStats] = defaultdict(_EntityStats)
    src_ips: dict[str, _EntityStats] = defaultdict(_EntityStats)
    earliest = datetime(9999, 1, 1, tzinfo=UTC)

    n_logs = 0
    for dir_name in _DEMO_DIRS:
        for log_path in sorted((root / dir_name).glob("*.log")):
            labels_path = log_path.parent / (log_path.name[: -len(".log")] + ".labels.json")
            malicious = _malicious_lines(labels_path) if labels_path.exists() else set()
            n_logs += 1
            with log_path.open(encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < len(_COLS) or parts[0] == "datetime":
                        continue
                    row = dict(zip(_COLS, parts, strict=False))
                    try:
                        ts = datetime.fromisoformat(row["datetime"].replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    earliest = min(earliest, ts)
                    if line_no in malicious:
                        continue  # attack traffic contributes nothing to "normal"

                    path = urlsplit(row["url"]).path if row["url"].startswith("http") else row["url"]
                    entropy = shannon_entropy(list(path)) if path else 0.0
                    for stats in (users[row["user"]], src_ips[row["clientip"]]):
                        stats.events += 1
                        stats.bytes_out += int(row["requestsize"] or 0)
                        stats.bytes_in += int(row["responsesize"] or 0)
                        stats.domains[row["host"]] += 1
                        stats.days.add(ts.date().isoformat())
                        stats.entropies.append(entropy)

    log.info("observe.done", logs=n_logs, users=len(users), src_ips=len(src_ips))
    return users, src_ips, earliest


def _percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    n = len(ordered)

    def pct(p: float) -> float:
        return ordered[min(n - 1, max(0, math.ceil(p * n) - 1))]

    mean = statistics.fmean(ordered)
    med = statistics.median(ordered)
    mad = statistics.median([abs(v - med) for v in ordered]) or 1.0
    return {"p50": med, "p95": pct(0.95), "p99": pct(0.99), "mean": mean, "mad": mad}


def _simulate_entity(
    rng: random.Random, stats: _EntityStats, n_days: int
) -> dict[str, list[float]]:
    """One value per metric per simulated day, drawn around the entity's own observed benign
    rates. Weekdays carry full weight, weekends ~15% — enough seasonality to look like a real
    org without inventing structure the logs don't support."""
    observed_days = max(1, len(stats.days))
    daily_events = max(1.0, stats.events / observed_days)
    out_per_event = stats.bytes_out / max(1, stats.events)
    in_per_event = stats.bytes_in / max(1, stats.events)
    mean_entropy = statistics.fmean(stats.entropies) if stats.entropies else 3.5

    series: dict[str, list[float]] = defaultdict(list)
    day = _BASELINE_START
    for i in range(n_days):
        weekend = (day + timedelta(days=i)).weekday() >= 5
        rate = daily_events * (0.15 if weekend else 1.0)
        n = _poisson(rng, max(0.2, rate))
        if n == 0:
            continue  # a day with no traffic is no window, matching how real windows form
        series["n_events"].append(float(n))
        series["bytes_out"].append(sum(_lognormalish(rng, out_per_event) for _ in range(n)))
        series["bytes_in"].append(sum(_lognormalish(rng, in_per_event) for _ in range(n)))
        series["n_unique_domains"].append(float(min(len(stats.domains), 1 + _poisson(rng, 1.5))))
        series["beaconing_requests"].append(float(n))
        series["url_path_entropy"].append(max(0.5, rng.gauss(mean_entropy, 0.25)))
    return series


def _poisson(rng: random.Random, lam: float) -> int:
    # Knuth's method; lam here is tiny (per-day rates), so this is fine.
    threshold, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= threshold:
            return k
        k += 1


def _lognormalish(rng: random.Random, mean: float) -> float:
    return max(64.0, rng.lognormvariate(math.log(max(mean, 64.0)) - 0.125, 0.5))


_USER_METRICS: Final[tuple[str, ...]] = ("n_events", "bytes_out", "bytes_in", "n_unique_domains")
_SRC_IP_METRICS: Final[tuple[str, ...]] = ("n_events", "beaconing_requests", "url_path_entropy")


def build_files(root: Path, out_dir: Path) -> dict[str, int]:
    rng = random.Random(_SEED)
    users, src_ips, earliest = _observe(root)
    if not users:
        raise RuntimeError(f"no demo logs found under {[str(root / d) for d in _DEMO_DIRS]}")

    baseline_end = (earliest - timedelta(days=1)).replace(hour=23, minute=0, second=0, microsecond=0)
    n_days = (baseline_end - _BASELINE_START).days
    log.info("simulate.period", start=str(_BASELINE_START), end=str(baseline_end), days=n_days)

    windows: list[dict[str, Any]] = []
    profiles: dict[str, dict[str, Any]] = {}
    org_daily: defaultdict[int, float] = defaultdict(float)

    def emit_profiles(entity_type: str, entity_value: str, metrics: tuple[str, ...],
                      series: dict[str, list[float]]) -> None:
        for metric in metrics:
            values = series.get(metric, [])
            if len(values) < 20:  # resolve.MIN_WINDOWS_FOR_BASELINE
                continue
            profiles[f"{entity_type}|{entity_value}|{metric}"] = {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "metric": metric,
                "n_windows": len(values),
                **_percentiles(values),
            }

    for email, stats in sorted(users.items()):
        series = _simulate_entity(random.Random(rng.random()), stats, n_days)
        emit_profiles("user", email, _USER_METRICS, series)
        for i, n in enumerate(series["n_events"]):
            org_daily[i] += n
        # Two window rows per user — the period bounds — not one per simulated day. Nothing in
        # the codebase reads the `baseline_windows` *table* (verified: only `baseline_profiles`
        # and `baseline_contacts` are queried, via `app.baseline.resolve`); the loader needs the
        # windows *file* solely to derive every contact's first/last_seen from its min/max
        # `window_start`. The first version emitted all ~170 daily rows per user (~8,000 total)
        # for self-consistency with the profiles, but after this store's disk-full outage the
        # write footprint is kept to what the readers actually consume: ~130 bound rows instead.
        # The full daily series still exists in memory above — the profiles' percentiles and
        # n_windows are computed from it and remain honest statements about the simulation.
        first_idx, last_idx = 0, len(series["n_events"]) - 1
        for i, idx in ((0, first_idx), (last_idx, last_idx)):
            windows.append({
                "entity_type": "user",
                "entity_value": email,
                "window_start": (_BASELINE_START + timedelta(days=idx)).isoformat(),
                "features": {
                    "n_events": series["n_events"][i],
                    "n_unique_domains": series["n_unique_domains"][i],
                    "bytes_out": series["bytes_out"][i],
                    "bytes_in": series["bytes_in"][i],
                    "post_ratio": 0.2, "blocked_ratio": 0.0, "off_hours_ratio": 0.1,
                    "automation_ua_ratio": 0.0, "direct_ip_ratio": 0.0,
                },
            })

    for ip, stats in sorted(src_ips.items()):
        series = _simulate_entity(random.Random(rng.random()), stats, n_days)
        emit_profiles("src_ip", ip, _SRC_IP_METRICS, series)

    org_values = [v for _, v in sorted(org_daily.items())]
    emit_profiles("org", "org", ("n_events",), {"n_events": org_values})

    contacts: list[dict[str, Any]] = []
    for email, stats in sorted(users.items()):
        observed_days = max(1, len(stats.days))
        for domain, count in sorted(stats.domains.items()):
            # Scale the observed benign contact rate to the simulated period; floor at 3 so a
            # domain a user touched even once in the demo window is decisively *not* first-seen.
            contacts.append({
                "scope": "user",
                "scope_value": email,
                "domain": domain,
                "contact_count": max(3, round(count / observed_days * n_days * 0.7)),
            })

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "baseline_windows.jsonl").open("w", encoding="utf-8") as f:
        for w in windows:
            f.write(json.dumps(w) + "\n")
    (out_dir / "baseline_profiles.json").write_text(json.dumps(profiles), encoding="utf-8")
    (out_dir / "baseline_contacts.json").write_text(json.dumps(contacts), encoding="utf-8")
    return {
        "users": len(users), "src_ips": len(src_ips), "windows": len(windows),
        "profiles": len(profiles), "contacts": len(contacts), "days": n_days,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="build files, skip the DB load")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="demo_baseline_") as tmp:
        stats = build_files(root, Path(tmp))
        log.info("build.done", **stats)
        if args.dry_run:
            print(json.dumps({"dry_run": True, **stats}))
            return
        session = get_session_factory()()
        try:
            tenant = get_or_create_live_tenant(session)
            summary = load_baseline(session, tenant.id, Path(tmp))
            session.commit()
        finally:
            session.close()
        print(json.dumps({**stats, "loaded": {
            "windows": summary.windows_loaded,
            "profiles": summary.profiles_loaded,
            "contacts_user": summary.contacts_user_loaded,
            "contacts_org": summary.contacts_org_loaded,
        }}))


if __name__ == "__main__":
    main()
