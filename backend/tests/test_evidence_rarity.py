"""Unit tests for `app.detection.evidence.rarity.detect_rarity`. Pure `EventRow` fixtures; no DB."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.detection.evidence.constants import (
    EXTRACTOR_RARITY,
    RARITY_MAX_ORG_EVENT_COUNT,
    SIGNAL_RARITY,
)
from app.detection.evidence.events_dao import EventRow
from app.detection.evidence.rarity import detect_rarity, raw_evidence_rarity

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _rows_for_domain(
    domain: str, principal_counts: dict[str, int], *, start: datetime = _T0
) -> list[EventRow]:
    rows: list[EventRow] = []
    next_id = 0
    ts = start
    for principal, count in principal_counts.items():
        for _ in range(count):
            rows.append(
                EventRow(id=next_id, ts=ts, src_ip="10.0.0.1", domain=domain, principal=principal)
            )
            next_id += 1
            ts = ts + timedelta(seconds=1)
    return rows


def test_rare_domain_fires() -> None:
    rows = _rows_for_domain("abcdefgh.top", {"alice@corp.example": 3})

    drafts = detect_rarity(rows)

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.detector_key == SIGNAL_RARITY
    assert draft.entity_type == "user"
    assert draft.entity_value == "alice@corp.example"
    assert draft.raw_score == 1.0 / (1.0 + 3.0)
    assert draft.explanation["domain"] == "abcdefgh.top"
    assert draft.explanation["org_wide_event_count"] == 3
    assert draft.explanation["user_novelty"] is True
    assert draft.explanation["n_events_by_principal"] == 3


def test_popular_domain_does_not_fire_even_for_a_first_time_visitor() -> None:
    # google.com gets hit by many principals; well past RARITY_MAX_ORG_EVENT_COUNT org-wide,
    # so bob's own first-ever visit to it still should not be signal-worthy.
    counts = {f"user{i}@corp.example": 5 for i in range(50)}  # 250 events, org-wide
    counts["bob@corp.example"] = 1
    rows = _rows_for_domain("google.com", counts)

    drafts = detect_rarity(rows)

    assert drafts == []


def test_threshold_boundary_is_inclusive() -> None:
    exactly_at_threshold = _rows_for_domain(
        "at-threshold.example", {"u@corp.example": RARITY_MAX_ORG_EVENT_COUNT}
    )
    one_over_threshold = _rows_for_domain(
        "over-threshold.example", {"u@corp.example": RARITY_MAX_ORG_EVENT_COUNT + 1}
    )

    assert len(detect_rarity(exactly_at_threshold)) == 1
    assert detect_rarity(one_over_threshold) == []


def test_multiple_principals_on_the_same_rare_domain_each_get_their_own_signal() -> None:
    rows = _rows_for_domain("rare-shared.top", {"alice@corp.example": 2, "bob@corp.example": 1})

    drafts = detect_rarity(rows)

    entity_values = {d.entity_value for d in drafts}
    assert entity_values == {"alice@corp.example", "bob@corp.example"}
    # org_wide_event_count is shared across both -- 3 total events on this domain.
    for draft in drafts:
        assert draft.explanation["org_wide_event_count"] == 3


def test_events_missing_principal_or_domain_are_ignored() -> None:
    rows = [
        EventRow(id=1, ts=_T0, src_ip="10.0.0.1", domain="example.com", principal=None),
        EventRow(id=2, ts=_T0, src_ip="10.0.0.1", domain=None, principal="alice@corp.example"),
    ]
    assert detect_rarity(rows) == []


def test_raw_evidence_rarity_mirrors_the_fired_signal() -> None:
    rows = _rows_for_domain("abcdefgh.top", {"alice@corp.example": 3})

    (raw,) = raw_evidence_rarity(rows)

    assert raw.extractor == EXTRACTOR_RARITY
    assert raw.entity == {"type": "user", "value": "alice@corp.example", "domain": "abcdefgh.top"}
    assert raw.measurements["n_events_by_principal"] == 3
    assert raw.contact_query is not None
    assert raw.contact_query.user == "alice@corp.example"
    assert raw.contact_query.domain == "abcdefgh.top"
    assert raw.baseline_queries == ()
    assert raw.contributing_line_numbers


def test_raw_evidence_rarity_only_covers_pairs_that_also_fire_as_signals() -> None:
    counts = {f"user{i}@corp.example": 5 for i in range(50)}
    counts["bob@corp.example"] = 1
    rows = _rows_for_domain("google.com", counts)

    assert detect_rarity(rows) == []
    assert raw_evidence_rarity(rows) == []
