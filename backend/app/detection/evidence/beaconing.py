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

## Evidence extraction (docs/v2_migration change 2)

`raw_evidence_beaconing` reuses `_dispersion`/`_fft_periodicity` verbatim -- the same numbers, not
a second computation -- and repackages them into the migration's own worked example shape almost
field-for-field: `measurements = {requests, median_interval_s, interval_cv, mad_s,
dominant_period_s, spectral_strength}`. Two differences from the `SignalDraft` explanation above,
both deliberate:

* **`median_interval_s`, not mean.** `_dispersion` already computes the deltas' median (used
  internally for `mad_jitter`) but the pre-existing `explanation["mean_interval"]` reports the
  *mean* -- docs/v2_migration's own worked example names the median explicitly
  (`"median_interval_s": 60.1`), and a median is the more robust of the two against the same
  occasional huge gap that would drag a mean sideways. `mad_s` (absolute seconds) is recovered as
  `mad_jitter * median` -- `_dispersion` only returns the *median-normalized* ratio, since that's
  what `regularity`'s scoring path wants, but the evidence payload wants raw seconds a human can
  read directly next to `median_interval_s`.
* **`spectral_strength`, not `fft_peak_power_ratio`.** The migration's own example
  (`"spectral_strength": 0.94`) is a *bounded* `[0, 1]` quantity -- "94% of the beacon's spectral
  power sits in one frequency bin" -- not the unbounded ratio-to-the-*mean*-of-the-rest
  `fft_peak_power_ratio` already uses for the `k=6` threshold check (that ratio can run into the
  hundreds for a near-perfect beacon, which reads fine as a threshold cutoff but poorly as "how
  strong is this" to a human or an LLM). `_fft_periodicity` computes both from the same spectrum
  in one pass rather than transforming the series twice.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from typing import Any

import numpy as np

from app.detection.evidence.constants import (
    BEACONING_FFT_BUCKET_SECONDS,
    BEACONING_FFT_MAX_BUCKETS,
    BEACONING_FFT_POWER_RATIO_K,
    BEACONING_MIN_EVENTS,
    BEACONING_SCORE_THRESHOLD,
    ENTITY_SRC_IP,
    EXTRACTOR_BEACONING,
    SIGNAL_BEACONING,
)
from app.detection.evidence.drafts import SignalDraft, cap_evidence, cap_evidence_rows
from app.detection.evidence.events_dao import EventRow, rows_with_domain
from app.detection.evidence.payload import BaselineQuery, RawEvidence

__all__ = ["detect_beaconing", "raw_evidence_beaconing"]

# docs/v2_migration change 2's own worked example percentile key.
_HISTORICAL_PREFIX = "beaconing"
# No baseline metric literally named "beaconing" exists in `baseline_profiles` today (the
# generator only populates `n_events`/`bytes_out`/`bytes_in`/`n_unique_domains`, all keyed
# `entity_type="user"`, `docs/v2_migration/generate_corpus.py::build_baseline`) -- this queries
# request volume specifically, the one beaconing measurement with a real historical analogue
# ("does this src_ip normally generate this many requests"), against `entity_type="src_ip"`
# (matching this detector's own entity dimension). Reports `insufficient_history` honestly
# against today's seeded baseline (no `src_ip`-keyed profile rows exist yet) rather than
# silently falling back to a different, less meaningful metric that happens to resolve.
_BASELINE_METRIC = "beaconing_requests"


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


@dataclass(frozen=True, slots=True)
class FFTResult:
    """Module docstring, "The FFT periodicity cross-check" -- both quantities `_fft_periodicity`
    reports come off the *same* spectrum in one pass: `peak_power_ratio` (unbounded, peak vs. the
    *mean* of every other bin -- what the `k=6` threshold gates on) and `spectral_strength`
    (bounded `[0, 1]`, peak vs. the *total* non-DC power -- what a human/LLM reads as "how
    concentrated is this")."""

    dominant_period_s: float
    peak_power_ratio: float
    n_buckets: int
    bucket_width_s: float
    spectral_strength: float


_NULL_FFT_RESULT = FFTResult(0.0, 0.0, 0, 0.0, 0.0)


def _fft_periodicity(
    timestamps: Sequence[datetime],
    *,
    bucket_seconds: int = BEACONING_FFT_BUCKET_SECONDS,
    max_buckets: int = BEACONING_FFT_MAX_BUCKETS,
) -> FFTResult:
    """`FFTResult` -- module docstring "The FFT periodicity cross-check."

    Returns `_NULL_FFT_RESULT` when there is no meaningful series to transform -- a zero-span
    group, or one whose bucketed counts have no variance (a flat series has no spectrum to speak
    of) -- rather than a division by a zero-power denominator.
    """
    span = (timestamps[-1] - timestamps[0]).total_seconds()
    if span <= 0:
        return _NULL_FFT_RESULT

    bucket_width = float(bucket_seconds)
    n_buckets = min(math.floor(span / bucket_width) + 1, max_buckets)
    if n_buckets < 2:
        return FFTResult(0.0, 0.0, n_buckets, bucket_width, 0.0)

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
        return FFTResult(0.0, 0.0, n_buckets, bucket_width, 0.0)

    power = np.abs(np.fft.rfft(counts)) ** 2
    if len(power) <= 1:
        return FFTResult(0.0, 0.0, n_buckets, bucket_width, 0.0)

    non_dc = power[1:]  # bin 0 is the DC (mean-level) component, not a periodicity
    peak_offset = int(np.argmax(non_dc))
    peak_idx = peak_offset + 1
    peak_power = float(non_dc[peak_offset])
    total_non_dc_power = float(non_dc.sum())
    spectral_strength = peak_power / total_non_dc_power if total_non_dc_power > 0 else 0.0

    rest = np.delete(non_dc, peak_offset)
    rest_mean = float(rest.mean()) if rest.size else 0.0
    if rest_mean > 0:
        ratio = peak_power / rest_mean
    elif peak_power > 0:
        ratio = math.inf
    else:
        ratio = 0.0

    period_s = (n_buckets * bucket_width) / peak_idx
    return FFTResult(period_s, ratio, n_buckets, bucket_width, spectral_strength)


@dataclass(frozen=True, slots=True)
class _BeaconFinding:
    """Everything both `detect_beaconing` (the `SignalDraft` path) and `raw_evidence_beaconing`
    (the `EvidencePayload` path) need about one `(src_ip, domain)` group that cleared
    `BEACONING_SCORE_THRESHOLD` -- computed once in `_beacon_findings` so the two output shapes
    never risk drifting apart on the underlying numbers."""

    src_ip: str
    domain: str
    ordered: list[EventRow]
    timestamps: list[datetime]
    n: int
    cv: float
    mad_jitter: float
    median_interval_s: float
    mean_interval: float
    regularity: float
    duration_h: float
    score: float
    fft: FFTResult


def _beacon_findings(rows: Sequence[EventRow]) -> list[_BeaconFinding]:
    groups: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in rows_with_domain(rows):
        if row.src_ip is None:
            continue
        groups[(row.src_ip, row.domain or "")].append(row)

    findings: list[_BeaconFinding] = []
    for (src_ip, domain), group in groups.items():
        if len(group) < BEACONING_MIN_EVENTS:
            continue
        ordered = sorted(group, key=lambda r: r.ts)
        timestamps = [r.ts for r in ordered]
        deltas = [(b - a).total_seconds() for a, b in pairwise(timestamps)]

        cv, mad_jitter, median_interval_s = _dispersion(deltas)
        mean_interval = statistics.fmean(deltas)
        regularity = 1.0 - min(cv, 1.0)
        duration_h = (timestamps[-1] - timestamps[0]).total_seconds() / 3600.0
        n = len(ordered)
        score = regularity * min(n / 50.0, 1.0) * min(duration_h / 4.0, 1.0)

        if score < BEACONING_SCORE_THRESHOLD:
            continue

        fft = _fft_periodicity(timestamps)
        findings.append(
            _BeaconFinding(
                src_ip=src_ip,
                domain=domain,
                ordered=ordered,
                timestamps=timestamps,
                n=n,
                cv=cv,
                mad_jitter=mad_jitter,
                median_interval_s=median_interval_s,
                mean_interval=mean_interval,
                regularity=regularity,
                duration_h=duration_h,
                score=score,
                fft=fft,
            )
        )
    return findings


def detect_beaconing(rows: Sequence[EventRow]) -> list[SignalDraft]:
    drafts: list[SignalDraft] = []
    for f in _beacon_findings(rows):
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in f.ordered])
        explanation: dict[str, Any] = {
            # docs/04's exact explanation shape:
            "mean_interval": f.mean_interval,
            "cv": f.cv,
            "mad_jitter": f.mad_jitter,
            "n_events": f.n,
            "duration_h": f.duration_h,
            "dominant_period_s": f.fft.dominant_period_s,
            "fft_peak_power_ratio": f.fft.peak_power_ratio,
            # additional context for the UI / a human triaging this signal:
            "src_ip": f.src_ip,
            "domain": f.domain,
            "regularity": f.regularity,
            "fft_has_dominant_peak": f.fft.peak_power_ratio >= BEACONING_FFT_POWER_RATIO_K,
            "fft_power_ratio_threshold": BEACONING_FFT_POWER_RATIO_K,
            "fft_bucket_width_s": f.fft.bucket_width_s,
            "fft_n_buckets": f.fft.n_buckets,
            "fft_spectral_strength": f.fft.spectral_strength,
            "score_threshold": BEACONING_SCORE_THRESHOLD,
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_BEACONING,
                entity_type=ENTITY_SRC_IP,
                entity_value=f.src_ip,
                raw_score=f.score,
                confidence_raw=f.score,
                window_start=f.timestamps[0],
                window_end=f.timestamps[-1],
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def raw_evidence_beaconing(rows: Sequence[EventRow]) -> list[RawEvidence]:
    """`EvidencePayload` measurements for every group `detect_beaconing` would also fire a
    `signals` row for -- evidence generation deliberately rides the same `BEACONING_SCORE_
    THRESHOLD` gate rather than a separate population, per CLAUDE.md rule 1 ("the LLM never sees
    raw log volume; every stage must reduce volume before the next") -- there is no reason to
    hand the LLM evidence for a group nothing downstream considered signal-worthy in the first
    place. Reuses `_beacon_findings` (shared with `detect_beaconing`) so the numbers in a
    `signals` row and its sibling `EvidencePayload` for the same group are computed once, not
    twice.
    """
    raw: list[RawEvidence] = []
    for f in _beacon_findings(rows):
        mad_s = f.mad_jitter * f.median_interval_s
        _event_ids, line_numbers, truncated = cap_evidence_rows(f.ordered)
        measurements: dict[str, Any] = {
            "requests": f.n,
            "median_interval_s": f.median_interval_s,
            "interval_cv": f.cv,
            "mad_s": mad_s,
            "dominant_period_s": f.fft.dominant_period_s,
            "spectral_strength": f.fft.spectral_strength,
            "evidence_truncated": truncated,
        }
        raw.append(
            RawEvidence(
                extractor=EXTRACTOR_BEACONING,
                entity={"type": ENTITY_SRC_IP, "value": f.src_ip, "domain": f.domain},
                window=(f.timestamps[0], f.timestamps[-1]),
                measurements=measurements,
                contributing_line_numbers=line_numbers,
                baseline_queries=(
                    BaselineQuery(
                        entity_type=ENTITY_SRC_IP,
                        entity_value=f.src_ip,
                        metric=_BASELINE_METRIC,
                        value=float(f.n),
                        historical_prefix=_HISTORICAL_PREFIX,
                    ),
                ),
            )
        )
    return raw
