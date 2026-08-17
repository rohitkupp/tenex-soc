"""Unit tests for `app.graph.tags.compute_incident_tags`. Pure `SignalRef` fixtures, no DB --
mirrors `tests/test_graph_incidents.py`'s own style for the same module family."""

from __future__ import annotations

from datetime import UTC, datetime

from app.graph.incidents import SignalRef
from app.graph.tags import (
    TAG_DETECTOR_PREFIX,
    TAG_LAYER_PREFIX,
    TAG_MULTI_LAYER,
    TAG_TECHNIQUE_PREFIX,
    compute_incident_tags,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(
    signal_id: int,
    *,
    detector_key: str = "sigma.blocked_then_allowed",
    detector_layer: str = "rule",
    mitre_technique: str | None = "T1090",
) -> SignalRef:
    return SignalRef(
        signal_id=signal_id,
        detector_key=detector_key,
        detector_layer=detector_layer,
        confidence=0.8,
        entity_type="user",
        entity_value="alice@corp.example",
        mitre_technique=mitre_technique,
        evidence_event_ids=(signal_id,),
        window_start=_T0,
        window_end=_T0,
    )


def test_allowlisted_technique_becomes_a_tag() -> None:
    tags = compute_incident_tags(
        [_signal(1, mitre_technique="T1090")],
    )
    assert f"{TAG_TECHNIQUE_PREFIX}T1090" in tags


def test_two_distinct_allowlisted_techniques_both_tagged() -> None:
    """ "an incident whose signals carry 2+ techniques gets both tags" (this task's test list)."""
    signals = [
        _signal(1, mitre_technique="T1090"),
        _signal(2, mitre_technique="T1105"),
    ]
    tags = compute_incident_tags(
        signals,
    )
    assert f"{TAG_TECHNIQUE_PREFIX}T1090" in tags
    assert f"{TAG_TECHNIQUE_PREFIX}T1105" in tags


def test_technique_outside_allowlist_is_dropped_not_passed_through() -> None:
    """T1552.001 (`credentials-in-url.yml`'s own tag) is not one of the 13 proxy-observable
    allowlisted techniques -- CLAUDE.md: technique ids outside the allowlist are "a bug to
    report, not to pass through."."""
    tags = compute_incident_tags(
        [_signal(1, mitre_technique="T1552.001")],
    )
    assert f"{TAG_TECHNIQUE_PREFIX}T1552.001" not in tags
    assert not any(t.startswith(TAG_TECHNIQUE_PREFIX) for t in tags)


def test_malformed_technique_missing_t_prefix_is_dropped() -> None:
    """The exact live-data malformation this environment's Sigma rules currently produce
    (`app/detection/sigma/rule.py`'s `mitre_techniques` strips the leading 'T') -- a bare "1090"
    must not be silently treated as the allowlisted "T1090"."""
    tags = compute_incident_tags(
        [_signal(1, mitre_technique="1090")],
    )
    assert not any(t.startswith(TAG_TECHNIQUE_PREFIX) for t in tags)


def test_no_technique_produces_no_technique_tag_but_does_not_crash() -> None:
    tags = compute_incident_tags(
        [_signal(1, mitre_technique=None)],
    )
    assert not any(t.startswith(TAG_TECHNIQUE_PREFIX) for t in tags)


def test_layer_and_detector_tags_always_present() -> None:
    tags = compute_incident_tags(
        [_signal(1, detector_key="sigma.blocked_then_allowed", detector_layer="rule")],
    )
    assert f"{TAG_LAYER_PREFIX}rule" in tags
    assert f"{TAG_DETECTOR_PREFIX}sigma.blocked_then_allowed" in tags


def test_multi_layer_tag_present_when_two_distinct_layers() -> None:
    """ "an incident with signals from 2 layers gets a multi-layer tag" (this task's test list)."""
    signals = [
        _signal(1, detector_key="signal.beaconing", detector_layer="signal"),
        _signal(2, detector_key="sigma.large_post_to_new_domain", detector_layer="rule"),
    ]
    tags = compute_incident_tags(
        signals,
    )
    assert TAG_MULTI_LAYER in tags


def test_multi_layer_tag_absent_when_single_layer() -> None:
    """ "...and a single-layer one does not" (this task's test list)."""
    signals = [
        _signal(1, detector_key="sigma.blocked_then_allowed", detector_layer="rule"),
        _signal(2, detector_key="sigma.large_post_to_new_domain", detector_layer="rule"),
    ]
    tags = compute_incident_tags(
        signals,
    )
    assert TAG_MULTI_LAYER not in tags


def test_tags_are_sorted_and_deduplicated() -> None:
    signals = [
        _signal(
            1,
            detector_key="sigma.blocked_then_allowed",
            detector_layer="rule",
            mitre_technique="T1090",
        ),
        _signal(
            2,
            detector_key="sigma.blocked_then_allowed",
            detector_layer="rule",
            mitre_technique="T1090",
        ),
    ]
    tags = compute_incident_tags(
        signals,
    )
    assert tags == sorted(set(tags))
    assert tags.count(f"{TAG_TECHNIQUE_PREFIX}T1090") == 1


def test_empty_signal_list_produces_no_tags_without_crashing() -> None:
    assert compute_incident_tags([]) == []
