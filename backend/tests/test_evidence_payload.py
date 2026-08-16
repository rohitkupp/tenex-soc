"""Unit tests for `app.detection.evidence.payload` -- the pure half of the three-stage evidence
pipeline (`RawEvidence -> EvidenceDraft -> EvidencePayload`, that module's own docstring).
`finalize_evidence` (evidence_id assignment + nomination de-duplication) needs no database, so
every test here builds `EvidenceDraft`s directly rather than going through a real extractor.
`tests/test_evidence_resolve.py` covers the DB-touching `resolve_evidence` stage.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)
from app.detection.evidence.payload import EvidenceDraft, EvidencePayload, finalize_evidence

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _draft(
    *,
    extractor: str,
    entity_type: str = "src_ip",
    entity_value: str = "10.0.0.1",
    window_start: datetime = _T0,
    window_end: datetime | None = None,
    measurements: dict | None = None,
    historical: dict | None = None,
    nomination_eligible: bool = False,
    nomination_score: float | None = None,
) -> EvidenceDraft:
    return EvidenceDraft(
        extractor=extractor,
        entity={"type": entity_type, "value": entity_value},
        window=(window_start, window_end or window_start + timedelta(hours=1)),
        measurements=measurements or {"x": 1.0},
        historical=historical or {},
        contributing_line_numbers=[1, 2, 3],
        nomination_eligible=nomination_eligible,
        nomination_score=nomination_score,
    )


# --------------------------------------------------------------------------------- payload shape


def test_payload_shape_is_valid_for_all_six_extractors() -> None:
    drafts = [
        _draft(
            extractor=EXTRACTOR_BEACONING,
            measurements={"requests": 63, "median_interval_s": 60.1, "spectral_strength": 0.94},
            historical={"beaconing_percentile": 99.7, "beaconing_baseline_status": "ok"},
        ),
        _draft(
            extractor=EXTRACTOR_DGA,
            entity_type="domain",
            entity_value="zvqxjkpl.top",
            measurements={"probability": 0.98, "shannon_entropy": 3.9},
            historical={},  # dga: "probability is already the answer" -- no baseline lookup
        ),
        _draft(
            extractor=EXTRACTOR_BURST,
            entity_type="user",
            entity_value="alice@corp.example",
            measurements={"requests_per_min": 20.0, "bytes_per_min": None},
            historical={"user_percentile": None, "user_baseline_status": "insufficient_history"},
        ),
        _draft(
            extractor=EXTRACTOR_RARITY,
            entity_type="user",
            entity_value="alice@corp.example",
            measurements={"user_contact_count": 0, "org_contact_count": 4},
            historical={"user_first_seen": True, "org_first_seen": False},
        ),
        _draft(
            extractor=EXTRACTOR_STL,
            measurements={"observed": 30, "residual": 12.5, "model": "stl_daily_weekly"},
            historical={"residual_z": 4.1, "residual_percentile": 99.9},
        ),
        _draft(
            extractor=EXTRACTOR_URL_ENTROPY,
            measurements={
                "path": "/api/v2/c7f3a9e1b2a4f093/checkin",
                "path_depth": 3,
                "encoded_param_flag": False,
            },
            historical={"entropy_percentile": 99.8},
        ),
    ]

    payloads = finalize_evidence(drafts)

    assert len(payloads) == 6
    assert {p.extractor for p in payloads} == {
        EXTRACTOR_BEACONING,
        EXTRACTOR_DGA,
        EXTRACTOR_BURST,
        EXTRACTOR_RARITY,
        EXTRACTOR_STL,
        EXTRACTOR_URL_ENTROPY,
    }
    for p in payloads:
        assert isinstance(p, EvidencePayload)
        assert p.evidence_id.startswith("EVIDENCE-")
        assert isinstance(p.window[0], datetime)
        assert isinstance(p.contributing_line_numbers, list)
    # url_entropy's literal path string survives Pydantic's `dict[str, Any]` measurements field.
    url_evidence = next(p for p in payloads if p.extractor == EXTRACTOR_URL_ENTROPY)
    assert url_evidence.measurements["path"] == "/api/v2/c7f3a9e1b2a4f093/checkin"
    # dga's historical is genuinely empty, not silently populated with a placeholder.
    dga_evidence = next(p for p in payloads if p.extractor == EXTRACTOR_DGA)
    assert dga_evidence.historical == {}


# --------------------------------------------------------------------------------- evidence_id


def test_evidence_id_ordering_is_extractor_then_entity_then_window() -> None:
    drafts = [
        _draft(extractor=EXTRACTOR_STL, entity_value="10.0.0.9"),
        _draft(extractor=EXTRACTOR_BEACONING, entity_value="10.0.0.5"),
        _draft(extractor=EXTRACTOR_BEACONING, entity_value="10.0.0.1"),
    ]

    payloads = finalize_evidence(drafts)

    # EXTRACTOR_ORDER puts beaconing before stl; within beaconing, entity value sorts "10.0.0.1"
    # before "10.0.0.5".
    assert [(p.extractor, p.entity["value"]) for p in payloads] == [
        (EXTRACTOR_BEACONING, "10.0.0.1"),
        (EXTRACTOR_BEACONING, "10.0.0.5"),
        (EXTRACTOR_STL, "10.0.0.9"),
    ]
    assert [p.evidence_id for p in payloads] == ["EVIDENCE-1", "EVIDENCE-2", "EVIDENCE-3"]


def test_evidence_id_is_stable_and_deterministic_across_two_runs() -> None:
    drafts = [
        _draft(extractor=EXTRACTOR_URL_ENTROPY, entity_value="10.0.2.99"),
        _draft(extractor=EXTRACTOR_RARITY, entity_type="user", entity_value="bob@corp.example"),
        _draft(extractor=EXTRACTOR_BEACONING, entity_value="10.0.0.5"),
    ]

    first_run = finalize_evidence(list(drafts))
    # Same drafts, different input order -- `finalize_evidence` re-sorts internally, so the
    # *input* order must not matter to the assigned ids.
    second_run = finalize_evidence(list(reversed(drafts)))

    first_by_key = {(p.extractor, p.entity["value"]): p.evidence_id for p in first_run}
    second_by_key = {(p.extractor, p.entity["value"]): p.evidence_id for p in second_run}
    assert first_by_key == second_by_key


# --------------------------------------------------------------------------------- nomination


def test_nomination_fires_when_eligible_and_no_prior_claim() -> None:
    drafts = [
        _draft(extractor=EXTRACTOR_BEACONING, nomination_eligible=True, nomination_score=0.999)
    ]

    (payload,) = finalize_evidence(drafts)

    assert payload.nominates_candidate is True
    assert payload.nomination_score == 0.999


def test_nomination_does_not_fire_when_not_eligible() -> None:
    drafts = [_draft(extractor=EXTRACTOR_BEACONING, nomination_eligible=False)]

    (payload,) = finalize_evidence(drafts)

    assert payload.nominates_candidate is False
    assert payload.nomination_score is None


def test_nomination_does_not_duplicate_an_entity_window_a_prior_draft_already_claimed() -> None:
    # Two extractors, same entity, overlapping windows, both eligible -- only the first in
    # deterministic order (beaconing precedes stl in EXTRACTOR_ORDER) should nominate.
    overlapping_start = _T0 + timedelta(minutes=10)
    drafts = [
        _draft(
            extractor=EXTRACTOR_STL,
            entity_value="10.0.0.5",
            window_start=overlapping_start,
            window_end=overlapping_start + timedelta(hours=1),
            nomination_eligible=True,
            nomination_score=0.999,
        ),
        _draft(
            extractor=EXTRACTOR_BEACONING,
            entity_value="10.0.0.5",
            window_start=_T0,
            window_end=_T0 + timedelta(hours=2),
            nomination_eligible=True,
            nomination_score=0.997,
        ),
    ]

    payloads = finalize_evidence(drafts)

    beaconing = next(p for p in payloads if p.extractor == EXTRACTOR_BEACONING)
    stl = next(p for p in payloads if p.extractor == EXTRACTOR_STL)
    assert beaconing.nominates_candidate is True
    assert stl.nominates_candidate is False
    assert stl.nomination_score is None


def test_nomination_is_independent_across_different_entities() -> None:
    drafts = [
        _draft(
            extractor=EXTRACTOR_BEACONING,
            entity_value="10.0.0.5",
            nomination_eligible=True,
            nomination_score=0.999,
        ),
        _draft(
            extractor=EXTRACTOR_STL,
            entity_value="10.0.0.9",  # different entity -- same window, no overlap concern
            nomination_eligible=True,
            nomination_score=0.998,
        ),
    ]

    payloads = finalize_evidence(drafts)

    assert all(p.nominates_candidate for p in payloads)


def test_nomination_respects_existing_candidate_windows_from_outside_this_run() -> None:
    drafts = [
        _draft(
            extractor=EXTRACTOR_BEACONING,
            entity_type="src_ip",
            entity_value="10.0.0.5",
            window_start=_T0,
            window_end=_T0 + timedelta(hours=1),
            nomination_eligible=True,
            nomination_score=0.999,
        )
    ]
    existing = [("src_ip", "10.0.0.5", _T0, _T0 + timedelta(hours=2))]

    (payload,) = finalize_evidence(drafts, existing_candidate_windows=existing)

    assert payload.nominates_candidate is False


def test_nomination_does_not_fire_for_non_overlapping_windows_on_the_same_entity() -> None:
    drafts = [
        _draft(
            extractor=EXTRACTOR_BEACONING,
            entity_value="10.0.0.5",
            window_start=_T0,
            window_end=_T0 + timedelta(hours=1),
            nomination_eligible=True,
            nomination_score=0.999,
        ),
        _draft(
            extractor=EXTRACTOR_STL,
            entity_value="10.0.0.5",
            window_start=_T0 + timedelta(days=1),
            window_end=_T0 + timedelta(days=1, hours=1),
            nomination_eligible=True,
            nomination_score=0.998,
        ),
    ]

    payloads = finalize_evidence(drafts)

    assert all(p.nominates_candidate for p in payloads)
