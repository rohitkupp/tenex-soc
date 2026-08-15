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
be close. **This math is unchanged** (docs/04, REWRITTEN §L2: the published jitter-degradation
curve depends on it) -- only the cross-check below was replaced.

## The FFT periodicity cross-check (REWRITTEN, docs/04 §L2 "Beaconing")

docs/04 now specifies a frequency-domain cross-check as *primary*, replacing the earlier bucketed
autocorrelation at a single guessed lag: "autocorrelation only tests the lags it is told to test,
and a beacon period that does not land on a bucket boundary is invisible to it, while the FFT
scans every candidate period in one pass." The group's event counts are binned into a uniform
`BEACONING_FFT_BUCKET_SECONDS`-wide (1-minute, docs literal) time series, zero-filled across the
group's full span so the sampling grid is regular (an FFT assumes uniform sampling; the
autocorrelation approach's variable, mean-interval-scaled bucket width doesn't need to). A real
FFT (`numpy.fft.rfft`) of that series concentrates power in one frequency bin for a truly
periodic beacon; interleaved human browsing does not concentrate power anywhere. `_fft_periodicity`
reports the period (in seconds) of the strongest non-DC bin and the ratio of that bin's power to
the mean power of every other non-DC bin -- a ratio at or above `BEACONING_FFT_POWER_RATIO_K`
(`k=6`, docs literal, "tuned on the beaconing difficulty sweep, docs/11") is what docs/04 calls a
"dominant peak." Like the autocorrelation check it replaces, this is a cross-check reported in
`explanation`, not a second gate on top of the CV/duration/volume score above -- the two can
disagree, and that disagreement is itself useful information for a human triaging the signal.
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
    BEACONING_FFT_BUCKET_SECONDS,
    BEACONING_FFT_MAX_BUCKETS,
    BEACONING_FFT_POWER_RATIO_K,
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


def _fft_periodicity(
    timestamps: Sequence[datetime],
    *,
    bucket_seconds: int = BEACONING_FFT_BUCKET_SECONDS,
    max_buckets: int = BEACONING_FFT_MAX_BUCKETS,
) -> tuple[float, float, int, float]:
    """`(dominant_period_s, fft_peak_power_ratio, n_buckets, bucket_width_s)` -- module docstring
    "The FFT periodicity cross-check."

    Returns `(0.0, 0.0, 0, 0.0)` when there is no meaningful series to transform -- a zero-span
    group, or one whose bucketed counts have no variance (a flat series has no spectrum to speak
    of) -- rather than a division by a zero-power denominator.
    """
    span = (timestamps[-1] - timestamps[0]).total_seconds()
    if span <= 0:
        return 0.0, 0.0, 0, 0.0

    bucket_width = float(bucket_seconds)
    n_buckets = min(math.floor(span / bucket_width) + 1, max_buckets)
    if n_buckets < 2:
        return 0.0, 0.0, n_buckets, bucket_width

    t0 = timestamps[0]
    counts = np.zeros(n_buckets, dtype=np.float64)
    for ts in timestamps:
        idx = int((ts - t0).total_seconds() // bucket_width)
        if idx >= n_buckets:
            # Only reachable when `span / bucket_width` exceeded `max_buckets` and the series
            # was truncated to the first `max_buckets` buckets (module docstring's defensive
            # cap) -- events past the truncated window are simply outside this transform's
            # window, the same way a truncated ACF bucket count used to bound its own array.
            continue
        counts[idx] += 1.0

    if np.allclose(counts, counts[0]):
        return 0.0, 0.0, n_buckets, bucket_width

    power = np.abs(np.fft.rfft(counts)) ** 2
    if len(power) <= 1:
        return 0.0, 0.0, n_buckets, bucket_width

    non_dc = power[1:]  # bin 0 is the DC (mean-level) component, not a periodicity
    peak_offset = int(np.argmax(non_dc))
    peak_idx = peak_offset + 1
    peak_power = float(non_dc[peak_offset])

    rest = np.delete(non_dc, peak_offset)
    rest_mean = float(rest.mean()) if rest.size else 0.0
    if rest_mean > 0:
        ratio = peak_power / rest_mean
    elif peak_power > 0:
        ratio = math.inf
    else:
        ratio = 0.0

    period_s = (n_buckets * bucket_width) / peak_idx
    return period_s, ratio, n_buckets, bucket_width


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

        dominant_period_s, fft_peak_power_ratio, n_buckets, bucket_width = _fft_periodicity(
            timestamps
        )

        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered])
        explanation: dict[str, Any] = {
            # docs/04's exact explanation shape:
            "mean_interval": mean_interval,
            "cv": cv,
            "mad_jitter": mad_jitter,
            "n_events": n,
            "duration_h": duration_h,
            "dominant_period_s": dominant_period_s,
            "fft_peak_power_ratio": fft_peak_power_ratio,
            # additional context for the UI / a human triaging this signal:
            "src_ip": src_ip,
            "domain": domain,
            "regularity": regularity,
            "fft_has_dominant_peak": fft_peak_power_ratio >= BEACONING_FFT_POWER_RATIO_K,
            "fft_power_ratio_threshold": BEACONING_FFT_POWER_RATIO_K,
            "fft_bucket_width_s": bucket_width,
            "fft_n_buckets": n_buckets,
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
