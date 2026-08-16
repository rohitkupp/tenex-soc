"""Unit tests for `app.detection.evidence.beaconing.detect_beaconing` -- CLAUDE.md's "every
detector needs a synthetic fixture that must fire and one that must not," against pure
`EventRow` lists (no DB, no fitted artifact -- beaconing has neither).
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from app.detection.evidence.beaconing import detect_beaconing, raw_evidence_beaconing
from app.detection.evidence.constants import (
    BEACONING_SCORE_THRESHOLD,
    EXTRACTOR_BEACONING,
    SIGNAL_BEACONING,
)
from app.detection.evidence.events_dao import EventRow

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _rows(
    *, n: int, interval_s: float, src_ip: str, domain: str, jitter_s: float = 0.0, seed: int = 1
) -> list[EventRow]:
    rng = random.Random(seed)
    ts = _T0
    rows: list[EventRow] = []
    for i in range(n):
        rows.append(
            EventRow(id=i, ts=ts, src_ip=src_ip, domain=domain, principal="victim@corp.example")
        )
        step = interval_s + (rng.uniform(-jitter_s, jitter_s) if jitter_s else 0.0)
        ts = ts + timedelta(seconds=max(0.001, step))
    return rows


def test_regular_beacon_fires() -> None:
    # 60 check-ins, exactly 240s apart: n/50 factor saturates at 1.0, duration is ~3.93h
    # (duration_h/4 factor ~0.98), and cv == 0 (regularity == 1.0) -- comfortably above
    # BEACONING_SCORE_THRESHOLD without having been tuned to just barely clear it.
    rows = _rows(n=60, interval_s=240.0, src_ip="10.0.0.5", domain="abcdefgh.top")

    drafts = detect_beaconing(rows)

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.detector_key == SIGNAL_BEACONING
    assert draft.entity_type == "src_ip"
    assert draft.entity_value == "10.0.0.5"
    assert draft.raw_score > BEACONING_SCORE_THRESHOLD
    assert draft.explanation["cv"] == 0.0
    assert draft.explanation["n_events"] == 60
    assert draft.explanation["domain"] == "abcdefgh.top"
    # docs/04's exact (REWRITTEN, FFT) explanation shape must be present.
    for key in (
        "mean_interval",
        "cv",
        "mad_jitter",
        "n_events",
        "duration_h",
        "dominant_period_s",
        "fft_peak_power_ratio",
    ):
        assert key in draft.explanation
    # A near-perfectly-regular 240s beacon is exactly the shape the FFT cross-check exists to
    # confirm: one dominant frequency bin, comfortably above the k=6 power-ratio bar.
    assert draft.explanation["fft_has_dominant_peak"] is True
    assert draft.explanation["dominant_period_s"] == pytest.approx(240.0, rel=0.1)


def test_irregular_browsing_does_not_fire() -> None:
    # Mostly-tiny gaps (a burst of clicks) punctuated by occasional huge ones (the user walked
    # away) -- a *uniform* jitter can't push CV much past ~0.58 (bounded by construction), but
    # this heavy-tailed mix pushes CV comfortably past 1.0, so regularity clips to exactly 0 and
    # the score collapses to 0 regardless of volume/duration -- not just "probably below
    # threshold," but deterministically so.
    rng = random.Random(7)
    ts = _T0
    rows: list[EventRow] = []
    for i in range(60):
        rows.append(
            EventRow(id=i, ts=ts, src_ip="10.0.0.9", domain="news.example", principal="u@corp")
        )
        step = rng.uniform(5000, 20000) if rng.random() < 0.1 else rng.uniform(0.5, 2.0)
        ts = ts + timedelta(seconds=step)

    drafts = detect_beaconing(rows)

    assert drafts == []


def test_group_below_minimum_event_count_does_not_fire() -> None:
    # Perfectly regular, but only 5 events -- below the n >= 8 floor docs/04 requires before a
    # group is even eligible for scoring.
    rows = _rows(n=5, interval_s=60.0, src_ip="10.0.0.7", domain="fast-beacon.top")

    assert detect_beaconing(rows) == []


def test_events_without_src_ip_or_domain_are_ignored() -> None:
    rows = [
        EventRow(id=1, ts=_T0, src_ip=None, domain="example.com", principal="u"),
        EventRow(id=2, ts=_T0, src_ip="10.0.0.1", domain=None, principal="u"),
    ]
    assert detect_beaconing(rows) == []


def test_different_src_ip_domain_pairs_are_scored_independently() -> None:
    regular = _rows(n=60, interval_s=240.0, src_ip="10.0.0.5", domain="beacon-one.top")
    other_regular = _rows(n=60, interval_s=90.0, src_ip="10.0.0.6", domain="beacon-two.top")

    drafts = detect_beaconing(regular + other_regular)

    entity_values = {d.entity_value for d in drafts}
    assert entity_values == {"10.0.0.5", "10.0.0.6"}


def test_fft_periodicity_finds_no_dominant_peak_in_random_browsing() -> None:
    """docs/04's own claim for the FFT cross-check: "interleaved human browsing does not
    concentrate power anywhere." Directly exercises `_fft_periodicity` (not gated behind the
    CV-based score threshold, which this traffic shape wouldn't clear anyway) against a Poisson-
    like random arrival process -- no single frequency bin should dominate.

    A periodogram's per-bin power under a white-noise null is itself exponentially distributed,
    so the *maximum* bin's power over *many* bins grows with bin count by ordinary extreme-value
    statistics, independent of any real periodicity (verified empirically while building this
    test: a several-thousand-bucket random series routinely exceeds `k=6` on power alone). This
    is exactly why docs/04's own `k=6` is stated as tuned empirically against realistic candidate-
    group shapes (docs/11's difficulty sweep) rather than derived analytically -- this test picks
    a fixed seed at a realistic candidate-group scale (a couple hundred one-minute buckets, the
    same order of magnitude `test_regular_beacon_fires` and `test_irregular_browsing_does_not_
    fire` use) and asserts the concrete, reproducible outcome for it, rather than a statistical
    claim that holds for every seed at every scale.
    """
    from app.detection.evidence.beaconing import _fft_periodicity

    rng = random.Random(11)
    ts = _T0
    timestamps = []
    for _ in range(120):
        timestamps.append(ts)
        ts += timedelta(seconds=rng.expovariate(1 / 90.0))  # mean 90s, exponential inter-arrival

    fft = _fft_periodicity(timestamps)
    assert fft.n_buckets > 1
    assert fft.peak_power_ratio < 6.0  # BEACONING_FFT_POWER_RATIO_K -- no dominant peak
    # No dominant peak -> spectral power is spread thin, not concentrated in one bin.
    assert fft.spectral_strength < 0.5


def test_fft_periodicity_finds_dominant_peak_for_a_regular_beacon() -> None:
    from app.detection.evidence.beaconing import _fft_periodicity

    ts = _T0
    timestamps = []
    for _ in range(200):
        timestamps.append(ts)
        ts += timedelta(seconds=120.0)

    fft = _fft_periodicity(timestamps)
    assert fft.peak_power_ratio >= 6.0
    assert fft.dominant_period_s == pytest.approx(120.0, rel=0.1)
    # A perfectly regular beacon concentrates most spectral power in the dominant bin -- not all
    # of it: a train of narrow, evenly-spaced spikes is spectrally broad by nature (every harmonic
    # of the fundamental carries some power too, the same reason a delta train's DTFT is itself a
    # delta train, not one line), so a real measured value comfortably above the random-browsing
    # case (`test_fft_periodicity_finds_no_dominant_peak_in_random_browsing`'s `< 0.5`) is the
    # right bar, not "close to 1.0".
    assert fft.spectral_strength > 0.7


def test_jitter_degrades_the_score_monotonically() -> None:
    # A sanity check on the shape of the degradation curve the M7 verification report measures
    # against real generated data: more jitter (as a fraction of the interval) should never
    # produce a *higher* score than less jitter, for the same volume/duration.
    scores = []
    for jitter_pct in (0.0, 0.1, 0.3, 0.6):
        rows = _rows(
            n=80,
            interval_s=60.0,
            jitter_s=60.0 * jitter_pct,
            src_ip="10.0.0.20",
            domain="jitter-test.top",
            seed=42,
        )
        drafts = detect_beaconing(rows)
        scores.append(drafts[0].raw_score if drafts else 0.0)

    assert scores == sorted(scores, reverse=True)


def test_raw_evidence_beaconing_mirrors_the_fired_signal() -> None:
    rows = _rows(n=60, interval_s=240.0, src_ip="10.0.0.5", domain="abcdefgh.top")

    (raw,) = raw_evidence_beaconing(rows)

    assert raw.extractor == EXTRACTOR_BEACONING
    assert raw.entity == {"type": "src_ip", "value": "10.0.0.5", "domain": "abcdefgh.top"}
    for key in (
        "requests",
        "median_interval_s",
        "interval_cv",
        "mad_s",
        "dominant_period_s",
        "spectral_strength",
    ):
        assert key in raw.measurements
    assert raw.measurements["requests"] == 60
    assert raw.measurements["interval_cv"] == 0.0
    assert 0.0 <= raw.measurements["spectral_strength"] <= 1.0
    assert raw.contributing_line_numbers
    (query,) = raw.baseline_queries
    assert query.entity_type == "src_ip"
    assert query.entity_value == "10.0.0.5"
    assert query.value == 60.0


def test_raw_evidence_beaconing_only_covers_groups_that_also_fire_as_signals() -> None:
    # Irregular browsing -- score never clears BEACONING_SCORE_THRESHOLD -- must produce neither
    # a `SignalDraft` nor a `RawEvidence` (module docstring: evidence rides the same gate).
    rng = random.Random(7)
    ts = _T0
    rows: list[EventRow] = []
    for i in range(60):
        rows.append(
            EventRow(id=i, ts=ts, src_ip="10.0.0.9", domain="news.example", principal="u@corp")
        )
        step = rng.uniform(5000, 20000) if rng.random() < 0.1 else rng.uniform(0.5, 2.0)
        ts = ts + timedelta(seconds=step)

    assert detect_beaconing(rows) == []
    assert raw_evidence_beaconing(rows) == []
