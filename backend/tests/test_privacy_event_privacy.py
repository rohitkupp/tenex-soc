"""app/privacy/event_privacy.py -- applies docs/06's pseudonymize/do-NOT-pseudonymize list
to a hot-column-shaped event. This is the module's own explicit verification-bar item:
"Prove the do-NOT-pseudonymize list is respected -- domains must survive intact, or every
threat-intel and DGA detector downstream breaks."
"""

from __future__ import annotations

from app.privacy.event_privacy import anonymize_event, anonymize_events
from app.privacy.pseudonymize import pseudonymize

SALT = b"tenant-a-salt"

FULL_EVENT = {
    "principal": "alice@corp.example",
    "src_ip": "198.51.100.11",
    "dst_ip": "45.32.10.10",
    "domain": "totally-legit-bank.com",
    "url_path": "/login?user=alice",
    "action": "allowed",
    "http_method": "GET",
    "status_code": 200,
    "bytes_in": 4096,
    "bytes_out": 512,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
    "event_key": "GET:general:allowed:2xx",
    "ts": "2026-02-15T00:11:18Z",
}


def test_principal_and_ips_are_pseudonymized() -> None:
    out = anonymize_event(FULL_EVENT, tenant_id="tenant-a", salt=SALT).event
    assert out["principal"] == pseudonymize("alice@corp.example", "user", SALT)
    assert out["src_ip"] == pseudonymize("198.51.100.11", "ip", SALT)
    assert out["dst_ip"] == pseudonymize("45.32.10.10", "ip", SALT)


def test_domain_survives_completely_unpseudonymized() -> None:
    """The load-bearing assertion: a downstream DGA/threat-intel detector reading
    `events.domain` must see the real domain, not a pseudonym."""
    out = anonymize_event(FULL_EVENT, tenant_id="tenant-a", salt=SALT).event
    assert out["domain"] == "totally-legit-bank.com"


def test_every_do_not_pseudonymize_field_survives_unchanged() -> None:
    out = anonymize_event(FULL_EVENT, tenant_id="tenant-a", salt=SALT).event
    assert out["domain"] == FULL_EVENT["domain"]
    assert out["user_agent"] == FULL_EVENT["user_agent"]
    assert out["http_method"] == FULL_EVENT["http_method"]
    assert out["status_code"] == FULL_EVENT["status_code"]
    assert out["bytes_in"] == FULL_EVENT["bytes_in"]
    assert out["bytes_out"] == FULL_EVENT["bytes_out"]
    assert out["ts"] == FULL_EVENT["ts"]
    assert out["action"] == FULL_EVENT["action"]
    assert out["url_path"] == FULL_EVENT["url_path"]
    assert out["event_key"] == FULL_EVENT["event_key"]


def test_input_mapping_is_never_mutated() -> None:
    before = dict(FULL_EVENT)
    anonymize_event(FULL_EVENT, tenant_id="tenant-a", salt=SALT)
    assert before == FULL_EVENT


def test_missing_optional_pseudonymizable_fields_are_skipped_not_errored() -> None:
    sparse = {"domain": "example.com", "user_agent": "curl/8.7.1"}
    result = anonymize_event(sparse, tenant_id="tenant-a", salt=SALT)
    assert result.event == sparse
    assert result.reverse_entries == ()


def test_none_and_empty_string_values_are_left_alone() -> None:
    event = {"principal": None, "src_ip": "", "dst_ip": "10.0.0.1"}
    result = anonymize_event(event, tenant_id="tenant-a", salt=SALT)
    assert result.event["principal"] is None
    assert result.event["src_ip"] == ""
    assert result.event["dst_ip"] == pseudonymize("10.0.0.1", "ip", SALT)


def test_reverse_entries_carry_the_original_value_and_tenant() -> None:
    result = anonymize_event(FULL_EVENT, tenant_id="tenant-a", salt=SALT)
    by_kind = {e.kind: e for e in result.reverse_entries}
    assert by_kind["user"].original_value == "alice@corp.example"
    assert by_kind["user"].tenant_id == "tenant-a"
    assert by_kind["user"].pseudonym == result.event["principal"]
    assert {"user", "ip"} <= set(by_kind)


def test_same_principal_across_two_events_gets_the_same_pseudonym() -> None:
    """Deterministic within a tenant -- entities stay correlatable across an analysis
    (docs/06)."""
    event_a = {"principal": "alice@corp.example", "domain": "a.example"}
    event_b = {"principal": "alice@corp.example", "domain": "b.example"}
    out_a = anonymize_event(event_a, tenant_id="tenant-a", salt=SALT).event
    out_b = anonymize_event(event_b, tenant_id="tenant-a", salt=SALT).event
    assert out_a["principal"] == out_b["principal"]


def test_forward_compatible_hostname_session_device_fields_pseudonymize_when_present() -> None:
    """These three kinds have no live parser field yet (see module docstring) but must
    already work the moment one exists."""
    event = {"hostname": "WORKSTATION-42", "session_id": "sess-abc123", "device_id": "dev-xyz"}
    out = anonymize_event(event, tenant_id="tenant-a", salt=SALT).event
    assert out["hostname"] == pseudonymize("WORKSTATION-42", "host", SALT)
    assert out["session_id"] == pseudonymize("sess-abc123", "session", SALT)
    assert out["device_id"] == pseudonymize("dev-xyz", "device", SALT)


def test_anonymize_events_batch_preserves_order() -> None:
    events = [{"principal": "a@x.com"}, {"principal": "b@x.com"}, {"principal": "c@x.com"}]
    results = anonymize_events(events, tenant_id="tenant-a", salt=SALT)
    assert [r.event["principal"] for r in results] == [
        pseudonymize("a@x.com", "user", SALT),
        pseudonymize("b@x.com", "user", SALT),
        pseudonymize("c@x.com", "user", SALT),
    ]
