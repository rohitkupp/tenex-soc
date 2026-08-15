"""Beaconing (docs/04 §L2 "Beaconing", ATT&CK T1071.001).

```
Group by (src_ip, domain). Require >= 8 events.

delta = sorted inter-arrival deltas (seconds)
CV = std(delta) / mean(delta)
MADj = median(|delta - median(delta)|) / median(delta)
regularity = 1 - min(CV, 1)
score = regularity * min(n/50, 1) * min(duration_hours/4, 1)
```

`CV` uses population standard deviation (`sqrt(mean((d - mean)**2))`, divide by `n` not `n-1`)
-- not because sample vs. population is normatively the "right" choice here, but because
`datagen/scenarios/s01_c2_beaconing.py`'s own `_dispersion` helper computes it that way when it
writes the "measured cv=..." note into scenario 1's ground truth, and matching that exactly is
what lets the M7 verification report compare this detector's `cv` against the generator's own
self-reported value as an independent cross-check, not just eyeball two numbers that happen to
be close.

## The autocorrelation cross-check

docs/04: "Also compute bucketed autocorrelation at the dominant lag as a cross-check." A group's
inter-arrival timestamps are binned into fixed-width buckets (`_ACF_BUCKET_DIVISOR` buckets per
expected interval, capped at `BEACONING_ACF_MAX_BUCKETS` total so a fast, long-running beacon
can't blow up the `numpy.correlate(mode="full")` call below), producing a per-bucket event-count
series; `dominant_lag` is the lag (in seconds) at which that series' own autocorrelation peaks,
excluding lag 0. For a genuinely periodic beacon this lands close to `mean_interval` -- computed
via an entirely different route (a frequency-domain-flavored peak search over binned counts,
rather than CV's time-domain statistic over raw deltas), which is exactly what makes it a real
cross-check and not the same number computed twice.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from itertools import pairwise
from typing import Any

import numpy as np

from app.detection.signal.constants import (
    BEACONING_ACF_BUCKET_DIVISOR,
    BEACONING_ACF_MAX_BUCKETS,
    BEACONING_ACF_MIN_BUCKET_SECONDS,
    BEACONING_MIN_EVENTS,
    BEACONING_SCORE_THRESHOLD,
    ENTITY_SRC_IP,
    SIGNAL_BEACONING,
)
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow, rows_with_domain

__all__ = ["detect_beaconing"]


def _dispersion(deltas: Sequence[float]) -> tuple[float, float, float]:
    """`(cv, mad_jitter, median)` of inter-arrival `deltas`, exactly docs/04's formulas.

    Degenerate cases (all-zero or duplicate-timestamp deltas) resolve to `cv = 1.0` (maximum
    irregularity -> `regularity = 0`) rather than raising or dividing by zero -- a group whose
    mean inter-arrival is <= 0 cannot be "regular" by any reading of the formula, so scoring it
    as the least regular possible case is the safe direction to fail in, not a crash.
    """
    n = len(deltas)
    mean = statistics.fmean(deltas)
    if mean <= 0:
        return 1.0, 0.0, 0.0
    cv = math.sqrt(sum((d - mean) ** 2 for d in deltas) / n) / mean
    median = statistics.median(deltas)
    if median <= 0:
        return cv, 0.0, median
    mad = statistics.median([abs(d - median) for d in deltas])
    return cv, mad / median, median


def _dominant_lag(
    timestamps: Sequence[datetime], mean_interval: float
) -> tuple[float, float, int, float]:
    """`(dominant_lag_seconds, acf_peak, n_buckets, bucket_width_s)`.

    Returns `(0.0, 0.0, 0, 0.0)` when there is no meaningful series to correlate -- a zero-span
    group, or one whose bucketed counts have no variance (e.g. exactly one event per bucket
    throughout, which mean-centers to an all-zero series) -- rather than a NaN/inf from dividing
    by a zero-power `acf[0]`.
    """
    span = (timestamps[-1] - timestamps[0]).total_seconds()
    if span <= 0 or mean_interval <= 0:
        return 0.0, 0.0, 0, 0.0

    bucket_width = max(
        mean_interval / BEACONING_ACF_BUCKET_DIVISOR, BEACONING_ACF_MIN_BUCKET_SECONDS
    )
    n_buckets = min(math.floor(span / bucket_width) + 1, BEACONING_ACF_MAX_BUCKETS)
    if n_buckets < 2:
        return 0.0, 0.0, n_buckets, bucket_width
    bucket_width = span / n_buckets  # re-spread so `n_buckets` bins cover the span exactly

    t0 = timestamps[0]
    counts = np.zeros(n_buckets, dtype=np.float64)
    for ts in timestamps:
        idx = min(int((ts - t0).total_seconds() // bucket_width), n_buckets - 1)
        counts[idx] += 1.0

    centered = counts - counts.mean()
    if np.allclose(centered, 0.0):
        return 0.0, 0.0, n_buckets, bucket_width

    corr = np.correlate(centered, centered, mode="full")
    acf = corr[len(corr) // 2 :]
    if acf[0] <= 0:
        return 0.0, 0.0, n_buckets, bucket_width
    acf_norm = acf / acf[0]
    if len(acf_norm) <= 1:
        return 0.0, 0.0, n_buckets, bucket_width

    lag_star = int(np.argmax(acf_norm[1:])) + 1
    return float(lag_star * bucket_width), float(acf_norm[lag_star]), n_buckets, bucket_width


def detect_beaconing(rows: Sequence[EventRow]) -> list[SignalDraft]:
    groups: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in rows_with_domain(rows):
        if row.src_ip is None:
            continue
        groups[(row.src_ip, row.domain or "")].append(row)

    drafts: list[SignalDraft] = []
    for (src_ip, domain), group in groups.items():
        if len(group) < BEACONING_MIN_EVENTS:
            continue
        ordered = sorted(group, key=lambda r: r.ts)
        timestamps = [r.ts for r in ordered]
        deltas = [(b - a).total_seconds() for a, b in pairwise(timestamps)]

        cv, mad_jitter, _median = _dispersion(deltas)
        mean_interval = statistics.fmean(deltas)
        regularity = 1.0 - min(cv, 1.0)
        duration_h = (timestamps[-1] - timestamps[0]).total_seconds() / 3600.0
        n = len(ordered)
        score = regularity * min(n / 50.0, 1.0) * min(duration_h / 4.0, 1.0)

        if score < BEACONING_SCORE_THRESHOLD:
            continue

        dominant_lag, acf_peak, n_buckets, bucket_width = _dominant_lag(timestamps, mean_interval)

        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered])
        explanation: dict[str, Any] = {
            # docs/04's exact explanation shape:
            "mean_interval": mean_interval,
            "cv": cv,
            "mad_jitter": mad_jitter,
            "n_events": n,
            "duration_h": duration_h,
            "dominant_lag": dominant_lag,
            # additional context for the UI / a human triaging this signal:
            "src_ip": src_ip,
            "domain": domain,
            "regularity": regularity,
            "autocorrelation_at_dominant_lag": acf_peak,
            "acf_bucket_width_s": bucket_width,
            "acf_n_buckets": n_buckets,
            "score_threshold": BEACONING_SCORE_THRESHOLD,
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_BEACONING,
                entity_type=ENTITY_SRC_IP,
                entity_value=src_ip,
                raw_score=score,
                confidence_raw=score,
                window_start=timestamps[0],
                window_end=timestamps[-1],
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts
