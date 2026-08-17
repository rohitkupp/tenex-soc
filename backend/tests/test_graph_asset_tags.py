"""Unit tests for `app.graph.asset_tags.compute_asset_tags`. Pure `AssetEvent` fixtures, no DB --
mirrors `tests/test_graph_tags.py`'s own style for the same module family."""

from __future__ import annotations

from app.graph.asset_tags import (
    TAG_BYPASSED_CLIENT_CONNECTOR,
    TAG_SHARED_DEVICE,
    AssetEvent,
    compute_asset_tags,
)


def _event(**overrides: object) -> AssetEvent:
    defaults: dict[str, object] = {
        "principal": "jsmith@corp.example",
        "hostname": None,
        "os_type": None,
        "os_version": None,
        "device_owner": None,
        "department": None,
        "location": None,
        "app_name": None,
        "risk_score": None,
        "bypassed_traffic": None,
        "flow_type": None,
        "ua_os_type": None,
        "ua_os_version": None,
    }
    defaults.update(overrides)
    return AssetEvent(**defaults)  # type: ignore[arg-type]


def test_device_tag_keyed_on_hostname_not_device_name() -> None:
    tags = compute_asset_tags([_event(hostname="THINKPADSMITH")])
    assert "device:THINKPADSMITH" in tags


def test_os_type_tag_present_when_set() -> None:
    tags = compute_asset_tags([_event(os_type="windows")])
    assert "os:windows" in tags


def test_os_type_falls_back_to_useragent_derived_value_when_device_field_absent() -> None:
    """Precedence: explicit device field wins; useragent fallback only fires when it is `None`
    (`app.graph.asset_tags`'s own module docstring)."""
    tags = compute_asset_tags([_event(os_type=None, ua_os_type="linux")])
    assert "os:linux" in tags


def test_os_type_explicit_device_field_wins_over_useragent_fallback() -> None:
    tags = compute_asset_tags([_event(os_type="windows", ua_os_type="linux")])
    assert "os:windows" in tags
    assert "os:linux" not in tags


def test_os_version_normalized_to_major_minor() -> None:
    tags = compute_asset_tags([_event(os_version="Version 10.14.2 (Build 18C54)")])
    assert "os_version:10.14" in tags
    assert not any(t.startswith("os_version:") and t != "os_version:10.14" for t in tags)


def test_os_version_bare_major_only_still_tags() -> None:
    tags = compute_asset_tags([_event(os_version="14")])
    assert "os_version:14" in tags


def test_dept_and_location_tags() -> None:
    tags = compute_asset_tags([_event(department="Sales", location="US-CA")])
    assert "dept:Sales" in tags
    assert "location:US-CA" in tags


def test_app_tag() -> None:
    tags = compute_asset_tags([_event(app_name="Dropbox")])
    assert "app:Dropbox" in tags


def test_risk_band_critical() -> None:
    tags = compute_asset_tags([_event(risk_score=95)])
    assert "risk:critical" in tags


def test_risk_band_high() -> None:
    tags = compute_asset_tags([_event(risk_score=80)])
    assert "risk:high" in tags


def test_risk_band_medium() -> None:
    tags = compute_asset_tags([_event(risk_score=50)])
    assert "risk:medium" in tags


def test_risk_band_low() -> None:
    tags = compute_asset_tags([_event(risk_score=10)])
    assert "risk:low" in tags


def test_risk_score_zero_produces_no_risk_tag() -> None:
    """docs/v1/zscaler-nss-web-fields.md's own bucketing: 0 is "None", not a band."""
    tags = compute_asset_tags([_event(risk_score=0)])
    assert not any(t.startswith("risk:") for t in tags)


def test_flow_type_tag_is_slugified() -> None:
    tags = compute_asset_tags([_event(flow_type="VPN Tunnel")])
    assert "flow:vpn-tunnel" in tags


def test_bypassed_traffic_true_tags_bypassed_client_connector() -> None:
    tags = compute_asset_tags([_event(bypassed_traffic=True)])
    assert TAG_BYPASSED_CLIENT_CONNECTOR in tags


def test_bypassed_traffic_false_does_not_tag() -> None:
    tags = compute_asset_tags([_event(bypassed_traffic=False)])
    assert TAG_BYPASSED_CLIENT_CONNECTOR not in tags


def test_bypassed_traffic_none_does_not_tag() -> None:
    tags = compute_asset_tags([_event(bypassed_traffic=None)])
    assert TAG_BYPASSED_CLIENT_CONNECTOR not in tags


def test_shared_device_tag_when_owner_diverges_from_login() -> None:
    tags = compute_asset_tags([_event(principal="jsmith@corp.example", device_owner="contractor1")])
    assert TAG_SHARED_DEVICE in tags


def test_shared_device_tag_absent_when_owner_matches_login_local_part() -> None:
    tags = compute_asset_tags([_event(principal="jsmith@corp.example", device_owner="jsmith")])
    assert TAG_SHARED_DEVICE not in tags


def test_shared_device_comparison_is_case_insensitive() -> None:
    tags = compute_asset_tags([_event(principal="JSmith@corp.example", device_owner="jsmith")])
    assert TAG_SHARED_DEVICE not in tags


def test_shared_device_tag_absent_when_owner_missing() -> None:
    tags = compute_asset_tags([_event(principal="jsmith@corp.example", device_owner=None)])
    assert TAG_SHARED_DEVICE not in tags


def test_tags_are_sorted_and_deduplicated_across_events() -> None:
    events = [
        _event(hostname="HOST1", department="Sales"),
        _event(hostname="HOST1", department="Sales"),
    ]
    tags = compute_asset_tags(events)
    assert tags == sorted(set(tags))
    assert tags.count("device:HOST1") == 1


def test_empty_event_list_produces_no_tags_without_crashing() -> None:
    assert compute_asset_tags([]) == []


def test_event_with_every_field_none_produces_no_tags() -> None:
    assert compute_asset_tags([_event()]) == []
