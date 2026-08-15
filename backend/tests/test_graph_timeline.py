"""Unit tests for `app.graph.timeline.build_timeline` (docs/05 "Timeline")."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.graph.incidents import SignalRef
from app.graph.timeline import build_timeline

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(
    signal_id: int,
    *,
    window_start: datetime | None,
    evidence_event_ids: tuple[int, ...],
    mitre_technique: str | None = None,
    detector_key: str = "signal.beaconing",
) -> SignalRef:
    return SignalRef(
        signal_id=signal_id,
        detector_key=detector_key,
        detector_layer="signal",
        confidence=0.9,
        entity_type="user",
        entity_value="alice@corp.example",
        mitre_technique=mitre_technique,
        evidence_event_ids=evidence_event_ids,
        window_start=window_start,
        window_end=window_start,
    )


def test_timeline_is_ordered_by_window_start() -> None:
    late = _signal(1, window_start=_T0 + timedelta(hours=2), evidence_event_ids=(3,))
    early = _signal(2, window_start=_T0, evidence_event_ids=(1,))
    middle = _signal(3, window_start=_T0 + timedelta(hours=1), evidence_event_ids=(2,))
    phases = build_timeline([late, early, middle])
    assert [p.event_ids for p in phases] == [[1], [2], [3]]


def test_timeline_falls_back_to_lowest_evidence_id_when_no_window() -> None:
    no_window_late = _signal(1, window_start=None, evidence_event_ids=(50,))
    no_window_early = _signal(2, window_start=None, evidence_event_ids=(5,))
    phases = build_timeline([no_window_late, no_window_early])
    assert [p.event_ids for p in phases] == [[5], [50]]


def test_windowed_phases_sort_before_windowless_ones() -> None:
    windowless = _signal(1, window_start=None, evidence_event_ids=(1,))
    windowed = _signal(2, window_start=_T0 + timedelta(days=1), evidence_event_ids=(2,))
    phases = build_timeline([windowless, windowed])
    assert phases[0].event_ids == [2]
    assert phases[1].event_ids == [1]


def test_known_technique_maps_to_a_real_tactic_not_a_placeholder() -> None:
    s = _signal(1, window_start=_T0, evidence_event_ids=(1,), mitre_technique="T1567.002")
    phases = build_timeline([s])
    assert phases[0].tactic == "Exfiltration"
    assert phases[0].tactic_is_placeholder is False


def test_missing_technique_is_a_declared_placeholder() -> None:
    s = _signal(1, window_start=_T0, evidence_event_ids=(1,), mitre_technique=None)
    phases = build_timeline([s])
    assert phases[0].tactic_is_placeholder is True


def test_summary_is_deterministic_and_references_detector_and_entity() -> None:
    s = _signal(1, window_start=_T0, evidence_event_ids=(1,), detector_key="signal.beaconing")
    phases = build_timeline([s])
    assert phases[0].summary == "signal.beaconing on user alice@corp.example"


def test_phase_carries_detector_layer_confidence_and_mitre_technique_through() -> None:
    """M15: `app.api.incident_detail.get_analysis_timeline` needs these straight off the phase
    (docs/09's confidence-score requirement) — `build_timeline` must pass them through from the
    source signal, not just use them internally for the `tactic` lookup."""
    s = _signal(1, window_start=_T0, evidence_event_ids=(1,), mitre_technique="T1071.001")
    phases = build_timeline([s])
    assert phases[0].detector_layer == "signal"
    assert phases[0].confidence == pytest.approx(0.9)
    assert phases[0].mitre_technique == "T1071.001"
