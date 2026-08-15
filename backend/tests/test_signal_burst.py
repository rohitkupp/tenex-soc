"""Unit tests for `app.detection.signal.burst.detect_burst`. Pure `EventRow` fixtures; no DB.

Buckets are 5 minutes (`BURST_BUCKET_SECONDS`) and epoch-aligned, so each fixture places its
events at `T0 + bucket_index * BURST_BUCKET_SECONDS + small_offset` to land deterministically in
a chosen bucket without depending on wall-clock alignment.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.detection.signal.burst import detect_burst
from app.detection.signal.constants import (
    BURST_BUCKET_SECONDS,
    BURST_MIN_ACTIVE_BUCKETS,
    BURST_Z_THRESHOLD,
    SIGNAL_BURST,
)
from app.detection.signal.events_dao import EventRow

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
