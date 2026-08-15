"""Unit tests for `app.graph.titling` (docs/05 "Incident titling")."""

from __future__ import annotations

from app.graph.titling import short_entity_value, technique_name, title_for_incident


def test_technique_name_known_id() -> None:
    assert technique_name("T1071.001") == "Application Layer Protocol: Web Protocols"


def test_technique_name_unknown_id_falls_back_to_the_raw_id() -> None:
    assert technique_name("T9999.999") == "T9999.999"


def test_technique_name_none_falls_back_to_generic_label() -> None:
    assert technique_name(None) == "Suspicious Activity"


def test_short_entity_value_shortens_email_to_local_part() -> None:
    assert short_entity_value("user", "u_8f3a91@corp.example") == "u_8f3a91"


def test_short_entity_value_truncates_long_non_email_values() -> None:
    value = "a" * 40
    result = short_entity_value("domain", value, max_len=24)
    assert len(result) == 24
    assert result.endswith("...")


def test_title_for_incident_matches_docs_example_shape() -> None:
    title = title_for_incident(
        top_technique_id="T1071",
        primary_entity_type="user",
        primary_entity_value="u_8f3a91@corp.example",
    )
    assert title == "Application Layer Protocol — user u_8f3a91"


def test_title_is_deterministic_across_repeated_calls() -> None:
    kwargs = {
        "top_technique_id": "T1567.002",
        "primary_entity_type": "user",
        "primary_entity_value": "csallie@corp.example",
    }
    assert title_for_incident(**kwargs) == title_for_incident(**kwargs)


def test_title_with_no_technique_uses_generic_label() -> None:
    title = title_for_incident(
        top_technique_id=None, primary_entity_type="src_ip", primary_entity_value="10.0.0.5"
    )
    assert title == "Suspicious Activity — src_ip 10.0.0.5"
