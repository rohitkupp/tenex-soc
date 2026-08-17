"""Unit tests for `app.graph.summary.summary_for_incident`. Exact-string assertions, same
discipline as `tests/test_graph_titling.py` — this template is deterministic and its output is
part of this task's own acceptance criteria ("show the actual tags and summaries produced")."""

from __future__ import annotations

from datetime import UTC, datetime

from app.graph.incidents import SignalRef
from app.graph.summary import summary_for_incident

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_T1 = datetime(2026, 1, 1, 12, 30, tzinfo=UTC)


def _signal(
    signal_id: int,
    *,
    detector_layer: str = "rule",
    evidence_event_ids: tuple[int, ...] = (1,),
    window_start: datetime | None = _T0,
    window_end: datetime | None = _T0,
) -> SignalRef:
    return SignalRef(
        signal_id=signal_id,
        detector_key="sigma.blocked_then_allowed",
        detector_layer=detector_layer,
        confidence=0.8,
        entity_type="user",
        entity_value="alice@corp.example",
        mitre_technique="T1090",
        evidence_event_ids=evidence_event_ids,
        window_start=window_start,
        window_end=window_end,
    )


def test_single_signal_single_instant_window_with_technique() -> None:
    summary = summary_for_incident(
        signals=[_signal(1)],
        entity_type_counts={"user": 1},
        top_technique_id="T1090",
        severity="high",
    )
    assert summary == (
        "1 signal from the rule layer fired on 1 user at 2026-01-01T12:00 UTC. "
        "1 event supports this finding; top technique Proxy (T1090). "
        "Fused severity: high."
    )


def test_two_signals_two_layers_range_window_no_technique() -> None:
    signals = [
        _signal(
            1, detector_layer="rule", evidence_event_ids=(1, 2), window_start=_T0, window_end=_T0
        ),
        _signal(
            2, detector_layer="signal", evidence_event_ids=(2, 3), window_start=_T1, window_end=_T1
        ),
    ]
    summary = summary_for_incident(
        signals=signals,
        entity_type_counts={"user": 1, "domain": 2},
        top_technique_id=None,
        severity="critical",
    )
    assert summary == (
        "2 signals from the rule and signal layers fired on 2 domains and 1 user "
        "between 2026-01-01T12:00 and 2026-01-01T12:30 UTC. "
        "3 events support this finding; no MITRE technique was identified among these signals. "
        "Fused severity: critical."
    )


def test_no_window_on_any_signal_omits_the_window_clause() -> None:
    summary = summary_for_incident(
        signals=[_signal(1, window_start=None, window_end=None)],
        entity_type_counts={"src_ip": 1},
        top_technique_id="T1090",
        severity="low",
    )
    assert summary == (
        "1 signal from the rule layer fired on 1 src_ip. "
        "1 event supports this finding; top technique Proxy (T1090). "
        "Fused severity: low."
    )


def test_empty_entity_counts_falls_back_to_generic_phrase() -> None:
    summary = summary_for_incident(
        signals=[_signal(1)],
        entity_type_counts={},
        top_technique_id="T1090",
        severity="medium",
    )
    assert "an unspecified set of entities" in summary


def test_country_pluralizes_irregularly() -> None:
    summary = summary_for_incident(
        signals=[_signal(1)],
        entity_type_counts={"country": 2},
        top_technique_id="T1090",
        severity="medium",
    )
    assert "2 countries" in summary
    assert "2 countrys" not in summary


def test_unrecognized_technique_id_falls_back_to_the_raw_id_never_a_fabricated_name() -> None:
    summary = summary_for_incident(
        signals=[_signal(1)],
        entity_type_counts={"user": 1},
        top_technique_id="T9999.999",
        severity="high",
    )
    assert "top technique T9999.999 (T9999.999)" in summary


def test_deterministic_across_repeated_calls() -> None:
    kwargs = {
        "signals": [_signal(1)],
        "entity_type_counts": {"user": 1},
        "top_technique_id": "T1090",
        "severity": "high",
    }
    assert summary_for_incident(**kwargs) == summary_for_incident(**kwargs)  # type: ignore[arg-type]


def test_no_signals_returns_a_safe_fallback_rather_than_crashing() -> None:
    summary = summary_for_incident(
        signals=[], entity_type_counts={}, top_technique_id=None, severity="low"
    )
    assert summary == "No signals were recorded for this incident."
