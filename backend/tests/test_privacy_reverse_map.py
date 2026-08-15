"""app/privacy/reverse_map.py -- the tenant-scoped reverse map docs/06 says exists only to
render values in the UI for that tenant's own users, and must never enter a prompt, a Tier 2
record, or a log line."""

from __future__ import annotations

import pytest

from app.privacy.reverse_map import PseudonymReverseMap, ReverseMapEntry


def test_record_then_resolve_round_trips() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-a",
            kind="user",
            pseudonym="u_abc",
            original_value="alice@corp.example",
        )
    )
    assert rm.resolve("tenant-a", "u_abc") == "alice@corp.example"


def test_unknown_pseudonym_resolves_to_none() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    assert rm.resolve("tenant-a", "u_does_not_exist") is None


def test_resolve_never_crosses_a_tenant_boundary() -> None:
    """The load-bearing guarantee: a pseudonym recorded under one tenant is invisible to a
    lookup under a different tenant, even when the pseudonym string is identical."""
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-a",
            kind="user",
            pseudonym="u_abc",
            original_value="alice@corp.example",
        )
    )

    assert rm.resolve("tenant-b", "u_abc") is None


def test_two_tenants_can_hold_different_values_under_the_same_pseudonym_string() -> None:
    """Not just "isolated" -- genuinely independent namespaces. (In practice two tenants'
    salts differ so this collision wouldn't occur naturally, but the map's isolation must
    not depend on that; it holds even in the adversarial case where it does collide.)"""
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-a",
            kind="user",
            pseudonym="u_abc",
            original_value="alice@corp.example",
        )
    )
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-b", kind="user", pseudonym="u_abc", original_value="bob@other.example"
        )
    )

    assert rm.resolve("tenant-a", "u_abc") == "alice@corp.example"
    assert rm.resolve("tenant-b", "u_abc") == "bob@other.example"


def test_recording_the_same_pseudonym_with_the_same_value_twice_is_a_no_op() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    entry = ReverseMapEntry(
        tenant_id="tenant-a", kind="user", pseudonym="u_abc", original_value="alice@corp.example"
    )
    rm.record(entry)
    rm.record(entry)
    assert len(rm) == 1


def test_recording_the_same_pseudonym_with_a_different_value_raises() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-a",
            kind="user",
            pseudonym="u_abc",
            original_value="alice@corp.example",
        )
    )
    with pytest.raises(ValueError, match="reverse map collision"):
        rm.record(
            ReverseMapEntry(
                tenant_id="tenant-a",
                kind="user",
                pseudonym="u_abc",
                original_value="mallory@evil.example",
            )
        )


def test_record_many_bulk_loads_entries() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    entries = [
        ReverseMapEntry(
            tenant_id="tenant-a",
            kind="user",
            pseudonym=f"u_{i}",
            original_value=f"user{i}@corp.example",
        )
        for i in range(5)
    ]
    rm.record_many(entries)
    assert len(rm) == 5
    assert rm.resolve("tenant-a", "u_3") == "user3@corp.example"


def test_len_counts_across_tenants() -> None:
    rm: PseudonymReverseMap[str] = PseudonymReverseMap()
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-a", kind="user", pseudonym="u_1", original_value="a@x.com"
        )
    )
    rm.record(
        ReverseMapEntry(
            tenant_id="tenant-b", kind="user", pseudonym="u_2", original_value="b@x.com"
        )
    )
    assert len(rm) == 2
