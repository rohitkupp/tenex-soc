"""Volumetric burst (docs/04 §L2 "Volumetric burst").

```
Per (entity, 5-minute bucket), robust z:
  z = 0.6745 * (x - median) / MAD
Flag |z| > 3.5.
```

Both the formula and the flag threshold are given verbatim and reused verbatim via
`app.detection.features.robust_z` (canonical -- CLAUDE.md: "Do not reimplement it"). What docs/04
leaves unstated is the *population* `z` is measured against and which `entity` dimension(s) to
bucket by. Both are load-bearing choices, made explicitly here rather than guessed silently:

## Population: an entity's own *active* buckets, not every 5-minute slot in the analysis

The naive reading -- lay a dense, zero-filled 5-minute grid across the entire analysis window
and z-score every slot, including the (overwhelming majority of) slots where the entity did
nothing -- collides directly with `robust_z`'s own documented MAD==0 policy. Most entities are
idle in most 5-minute windows of a multi-day file, so the *median* bucket count for almost any
entity is 0 and the *MAD* is 0 too (mostly-zero data has zero median absolute deviation from a
median of zero). Per `robust_z`'s policy, any bucket with `x != 0` then scores `z = inf` --
which would flag literally every single active period, VPN check-in and O365 login sync alike,
because the *idle* time was allowed to define "normal." That is precisely the failure mode
`robust_z`'s docstring calls out for a different feature (`off_hours_ratio`): "a zero-spread
population made any other value an unbounded outlier by construction," applied here to a
population that is only degenerate because it was built wrong, not because the entity's real
behavior has no spread.

The population used below is instead an entity's own *nonzero*-count buckets only -- "given how
much this entity typically generates in a 5-minute window when it is doing something, is this
particular active window abnormally large." An entity needs at least `BURST_MIN_ACTIVE_BUCKETS`
such buckets before it is scored at all (mirrors beaconing's `n >= 8` floor: fewer than that and
there is no real distribution to be an outlier against).

## Entity dimension: both `user` (principal) and `src_ip`, scored independently

docs/04 says "entity" without naming which one. Both plausible readings are real attack
surfaces this detector should catch — a user's own upload volume spiking (data exfil, docs/11
scenario 2/7) and a source IP's request volume spiking (a noisy scanner or an aggressive
beacon/upload burst, docs/11 scenario 1/2) — so this module runs the identical bucketing/scoring
logic once per dimension rather than picking one and missing the other.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from app.detection.features import robust_z
from app.detection.signal.constants import (
    BURST_BUCKET_SECONDS,
    BURST_MIN_ACTIVE_BUCKETS,
    BURST_Z_THRESHOLD,
    ENTITY_SRC_IP,
    ENTITY_USER,
    SIGNAL_BURST,
)
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow

__all__ = ["detect_burst"]


def _bucket_start(ts: datetime, bucket_seconds: int = BURST_BUCKET_SECONDS) -> int:
    """Epoch-aligned bucket start, in whole seconds. Fixed-grid (not per-entity-relative) so
    two entities' buckets line up, which correlation (docs/05, not this milestone) will want."""
    epoch = int(ts.timestamp())
    return (epoch // bucket_seconds) * bucket_seconds


def _confidence_from_z(z: float) -> float:
    """Placeholder squash of an unbounded z-score into `[0, 1]` for `signals.confidence` until
    M10's isotonic calibration exists (see `drafts.py`'s module docstring) -- `robust_z` can
    legitimately return `math.inf` (its own documented MAD==0 policy), which cannot be used as
    a probability directly."""
    if z == float("inf") or z == float("-inf"):
        return 1.0
    return max(0.0, min(1.0, abs(z) / 10.0))


def _detect_for_entity(
    rows: Sequence[EventRow],
    *,
    entity_type: str,
    entity_value_of: Callable[[EventRow], str | None],
) -> list[SignalDraft]:
    by_entity: dict[str, dict[int, list[EventRow]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        value = entity_value_of(row)
        if value is None:
            continue
        by_entity[value][_bucket_start(row.ts)].append(row)

    drafts: list[SignalDraft] = []
    for entity_value, buckets in by_entity.items():
        if len(buckets) < BURST_MIN_ACTIVE_BUCKETS:
            continue
        counts = [len(v) for v in buckets.values()]
        median = statistics.median(counts)
        mad = statistics.median([abs(c - median) for c in counts])

        for bucket_epoch, bucket_rows in buckets.items():
            x = float(len(bucket_rows))
            z = robust_z(counts, x)
            if abs(z) <= BURST_Z_THRESHOLD:
                continue

            bucket_start = datetime.fromtimestamp(bucket_epoch, tz=UTC)
            bucket_end = datetime.fromtimestamp(bucket_epoch + BURST_BUCKET_SECONDS, tz=UTC)
            evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in bucket_rows])
            explanation: dict[str, Any] = {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "bucket_start": bucket_start.isoformat(),
                "bucket_end": bucket_end.isoformat(),
                "count": int(x),
                "median": median,
                "mad": mad,
                "z": z if z not in (float("inf"), float("-inf")) else None,
                "z_is_infinite": z in (float("inf"), float("-inf")),
                "threshold": BURST_Z_THRESHOLD,
                "n_active_buckets": len(buckets),
                "evidence_truncated": truncated,
            }
            drafts.append(
                SignalDraft(
                    detector_key=SIGNAL_BURST,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    # Postgres `real` stores +/-Infinity natively (verified against the live
                    # DB), so `robust_z`'s own inf sentinel round-trips without a magic number.
                    raw_score=z,
                    confidence_raw=_confidence_from_z(z),
                    window_start=bucket_start,
                    window_end=bucket_end,
                    evidence_event_ids=evidence_ids,
                    explanation=explanation,
                )
            )
    return drafts


def detect_burst(rows: Sequence[EventRow]) -> list[SignalDraft]:
    by_user = _detect_for_entity(
        rows, entity_type=ENTITY_USER, entity_value_of=lambda r: r.principal
    )
    by_src_ip = _detect_for_entity(
        rows, entity_type=ENTITY_SRC_IP, entity_value_of=lambda r: r.src_ip
    )
    return by_user + by_src_ip
