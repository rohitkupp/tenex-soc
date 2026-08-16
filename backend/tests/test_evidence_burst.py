"""Unit tests for `app.detection.evidence.burst.detect_burst`. Pure `EventRow` fixtures; no DB.

Buckets are 5 minutes (`BURST_BUCKET_SECONDS`) and epoch-aligned, so each fixture places its
events at `T0 + bucket_index * BURST_BUCKET_SECONDS + small_offset` to land deterministically in
a chosen bucket without depending on wall-clock alignment.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.detection.evidence.burst import detect_burst, raw_evidence_burst
from app.detection.evidence.constants import (
    BURST_BUCKET_SECONDS,
    BURST_MIN_ACTIVE_BUCKETS,
    BURST_Z_THRESHOLD,
    EXTRACTOR_BURST,
    SIGNAL_BURST,
)
from app.detection.evidence.events_dao import EventRow

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _bucketed_rows(
    counts: list[int], *, principal: str | None = "alice@corp.example", src_ip: str | None = None
) -> list[EventRow]:
    rows: list[EventRow] = []
    next_id = 0
    for bucket_idx, count in enumerate(counts):
        bucket_start = _T0 + timedelta(seconds=bucket_idx * BURST_BUCKET_SECONDS)
        for offset in range(count):
            rows.append(
                EventRow(
                    id=next_id,
                    ts=bucket_start + timedelta(seconds=offset),
                    src_ip=src_ip,
                    domain=None,
                    principal=principal,
                )
            )
            next_id += 1
    return rows


def test_extreme_spike_against_a_flat_baseline_fires() -> None:
    # Five quiet buckets of 2 events, one bucket of 100 -- MAD of [2,2,2,2,2,100] is 0 (five of
    # six values equal the median exactly), so `robust_z`'s documented MAD==0 policy makes the
    # spike bucket score `+inf`, not just "large."
    assert BURST_MIN_ACTIVE_BUCKETS <= 5
    rows = _bucketed_rows([2, 2, 2, 2, 2, 100])

    drafts = detect_burst(rows)

    fired = [d for d in drafts if d.entity_type == "user"]
    assert len(fired) == 1
    draft = fired[0]
    assert draft.detector_key == SIGNAL_BURST
    assert draft.entity_value == "alice@corp.example"
    assert draft.raw_score == float("inf")
    assert draft.confidence_raw == 1.0
    assert draft.explanation["count"] == 100
    assert draft.explanation["z_is_infinite"] is True
    assert draft.explanation["threshold"] == BURST_Z_THRESHOLD


def test_mild_natural_variation_does_not_fire() -> None:
    # Ordinary day-to-day fluctuation, nothing more than 2x the median -- well inside the
    # |z| > 3.5 flag threshold.
    rows = _bucketed_rows([3, 4, 5, 4, 3, 5, 4, 6, 5, 4])

    assert detect_burst(rows) == []


def test_entity_with_too_few_active_buckets_is_not_scored() -> None:
    # Only 2 active buckets (below BURST_MIN_ACTIVE_BUCKETS) -- there isn't enough of this
    # entity's own history to call anything an outlier against, no matter how spiky.
    rows = _bucketed_rows([1, 500])

    assert detect_burst(rows) == []


def test_src_ip_dimension_is_scored_independently_of_user() -> None:
    rows = _bucketed_rows([2, 2, 2, 2, 2, 100], principal=None, src_ip="203.0.113.9")

    drafts = detect_burst(rows)

    assert len(drafts) == 1
    assert drafts[0].entity_type == "src_ip"
    assert drafts[0].entity_value == "203.0.113.9"


def test_events_missing_the_scored_dimension_are_skipped() -> None:
    rows = _bucketed_rows([2, 2, 2, 2, 2, 100], principal=None, src_ip=None)
    assert detect_burst(rows) == []


def test_raw_evidence_burst_mirrors_the_fired_signal_for_the_user_dimension() -> None:
    rows = _bucketed_rows([2, 2, 2, 2, 2, 100])

    raw = raw_evidence_burst(rows)
    fired = [r for r in raw if r.entity["type"] == "user"]

    assert len(fired) == 1
    r = fired[0]
    assert r.extractor == EXTRACTOR_BURST
    assert r.entity == {"type": "user", "value": "alice@corp.example"}
    for key in ("requests_per_min", "bytes_per_min", "unique_domains_per_min"):
        assert key in r.measurements
    assert r.measurements["requests_per_min"] == pytest.approx(100 / 5.0)
    # Three-scope lookup for the user dimension: user, (maybe) department, org.
    prefixes = {q.historical_prefix for q in r.baseline_queries}
    assert "user" in prefixes
    assert "org" in prefixes


def test_raw_evidence_burst_uses_a_single_scope_for_the_src_ip_dimension() -> None:
    rows = _bucketed_rows([2, 2, 2, 2, 2, 100], principal=None, src_ip="203.0.113.9")

    raw = raw_evidence_burst(rows)

    assert len(raw) == 1
    assert raw[0].entity == {"type": "src_ip", "value": "203.0.113.9"}
    prefixes = {q.historical_prefix for q in raw[0].baseline_queries}
    assert prefixes == {"src_ip"}


def test_raw_evidence_burst_only_covers_buckets_that_also_fire_as_signals() -> None:
    rows = _bucketed_rows([3, 4, 5, 4, 3, 5, 4, 6, 5, 4])
    assert detect_burst(rows) == []
    assert raw_evidence_burst(rows) == []
