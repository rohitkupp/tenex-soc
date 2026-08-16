"""`app.schemas.evidence` — pure, DB-free unit tests for change 11's enforcement function
(`highlight_line_violations`) and the `EvidencePayload` -> `EvidencePayloadOut` wire converter.
No Postgres needed: everything here is plain dataclass/Pydantic construction, same "fast unit
test" bar `app.detection.evidence`'s own extractor tests hold (see e.g.
`tests/test_evidence_payload.py`).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.detection.evidence.payload import EvidencePayload
from app.schemas.evidence import evidence_payload_out, highlight_line_violations

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _payload(
    *,
    evidence_id: str = "EVIDENCE-1",
    contributing_line_numbers: list[int] | None = None,
) -> EvidencePayload:
    return EvidencePayload(
        evidence_id=evidence_id,
        extractor="beaconing",
        entity={"type": "src_ip", "value": "10.0.0.1"},
        window=(_T0, _T0),
        measurements={"requests": 60},
        historical={"beaconing_percentile": 99.7},
        contributing_line_numbers=contributing_line_numbers or [10, 20, 30],
        nominates_candidate=False,
    )


# ------------------------------------------------------------------ highlight_line_violations


def test_no_violations_when_every_citation_is_inside_the_attribution_set() -> None:
    narrative = [{"step": 1, "claim": "beacon detected", "evidence_ids": ["LOG-10", "LOG-30"]}]
    assert highlight_line_violations(narrative, [10, 20, 30]) == []


def test_a_log_citation_outside_the_attribution_set_is_a_violation() -> None:
    """change 11: "if the presenter references a line outside the set, it is a scope
    violation." A `LOG-n` citation for a line no evidence extractor ever nominated must be
    reported, not silently accepted."""
    narrative = [
        {"step": 1, "claim": "beacon detected", "evidence_ids": ["LOG-10", "LOG-9999"]},
    ]
    assert highlight_line_violations(narrative, [10, 20, 30]) == [9999]


def test_violations_are_deduplicated_and_sorted_across_steps() -> None:
    narrative = [
        {"step": 1, "claim": "a", "evidence_ids": ["LOG-500", "LOG-100"]},
        {"step": 2, "claim": "b", "evidence_ids": ["LOG-500"]},
    ]
    assert highlight_line_violations(narrative, []) == [100, 500]


def test_non_log_citations_are_ignored_not_flagged() -> None:
    """`EVIDENCE-n`/`BASELINE-n`/`MITRE-*`/`ZSCALER-KB-*` citations don't reference a raw line
    number at all — they must never be treated as an out-of-scope line."""
    narrative = [
        {
            "step": 1,
            "claim": "c2",
            "evidence_ids": ["EVIDENCE-14", "BASELINE-3", "MITRE-T1071.001", "ZSCALER-KB-threat"],
        }
    ]
    assert highlight_line_violations(narrative, [1, 2, 3]) == []


def test_malformed_narrative_entries_are_skipped_not_raised() -> None:
    """`narrative` is LLM-authored JSONB — one malformed step or citation must cost that entry,
    not the whole computation (same "tolerant on purpose" policy as
    `app.api.incident_detail._technique_ids`)."""
    narrative = [
        "not-a-dict",  # type: ignore[list-item]
        {"step": 1, "claim": "ok", "evidence_ids": ["LOG-not-a-number", "LOG-42", None, 7]},
    ]
    assert highlight_line_violations(narrative, []) == [42]  # type: ignore[arg-type]


def test_missing_narrative_is_no_violations() -> None:
    assert highlight_line_violations(None, [1, 2, 3]) == []
    assert highlight_line_violations([], [1, 2, 3]) == []


def test_empty_highlight_lines_means_every_log_citation_is_a_violation() -> None:
    """An incident whose evidence layer nominated nothing at all (`highlight_lines == []`) but
    whose narrative still cites a `LOG-n` — every one of those citations is out of scope."""
    narrative = [{"step": 1, "claim": "x", "evidence_ids": ["LOG-1"]}]
    assert highlight_line_violations(narrative, []) == [1]


# ------------------------------------------------------------------ evidence_payload_out


def test_evidence_payload_out_flattens_entity_and_window() -> None:
    payload = _payload()
    incident_id = uuid.uuid4()
    out = evidence_payload_out(payload, incident_ids=[incident_id])

    assert out.evidence_id == "EVIDENCE-1"
    assert out.extractor == "beaconing"
    assert out.entity_type == "src_ip"
    assert out.entity_value == "10.0.0.1"
    assert out.window_start == _T0
    assert out.window_end == _T0
    assert out.contributing_line_numbers == [10, 20, 30]
    assert out.incident_ids == [incident_id]


def test_evidence_payload_out_defaults_incident_ids_to_empty() -> None:
    """change 16: "including evidence that never formed an incident" — the common, expected
    case, not missing data."""
    out = evidence_payload_out(_payload())
    assert out.incident_ids == []


def test_evidence_payload_out_passes_cold_start_historical_through_verbatim() -> None:
    """CLAUDE.md: "a percentile from four windows must not look like one from six months" —
    `baseline_status`/`n_windows` must survive the wire conversion untouched."""
    payload = EvidencePayload(
        evidence_id="EVIDENCE-2",
        extractor="rarity",
        entity={"type": "user", "value": "alice@corp.example"},
        window=(_T0, _T0),
        measurements={"contact_count": 0},
        historical={
            "user_percentile": None,
            "user_baseline_status": "insufficient_history",
            "user_n_windows": 4,
        },
        contributing_line_numbers=[1],
        nominates_candidate=False,
    )
    out = evidence_payload_out(payload)
    assert out.historical["user_baseline_status"] == "insufficient_history"
    assert out.historical["user_n_windows"] == 4
    assert out.historical["user_percentile"] is None
