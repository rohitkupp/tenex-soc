"""Focused, DB-independent tests for `app.tier2.hashing` — the two HMAC constructions
`app.tier2.__init__`'s docstring documents the tradeoff of. Broader end-to-end proof that
the tradeoff actually delivers the feature lives in
`tests/test_tier2_indicator_overlap.py`; this file is the unit-level property check.
"""

from __future__ import annotations

import uuid

from app.privacy.pseudonymize import indicator_hash
from app.tier2.hashing import tenant_hash


def test_tenant_hash_is_deterministic() -> None:
    tenant_id = uuid.uuid4()
    salt = b"a-per-tenant-salt"
    assert tenant_hash(tenant_id, salt) == tenant_hash(tenant_id, salt)


def test_tenant_hash_differs_by_tenant_id_even_with_the_same_salt() -> None:
    salt = b"same-salt-two-tenants-should-not-share"
    assert tenant_hash(uuid.uuid4(), salt) != tenant_hash(uuid.uuid4(), salt)


def test_tenant_hash_differs_by_salt_even_for_the_same_tenant_id() -> None:
    tenant_id = uuid.uuid4()
    assert tenant_hash(tenant_id, b"salt-one") != tenant_hash(tenant_id, b"salt-two")


def test_tenant_hash_is_not_the_raw_tenant_id() -> None:
    tenant_id = uuid.uuid4()
    result = tenant_hash(tenant_id, b"some-salt")
    assert str(tenant_id) not in result
    assert tenant_id.hex not in result


def test_tenant_hash_has_a_recognizable_prefix_distinct_from_pseudonymize_prefixes() -> None:
    """`th_` -- distinct from `u_`/`ip_`/`h_`/`sess_`/`dev_` (`app.privacy.pseudonymize.
    PREFIX`) and from indicator_hash's `d_`/`ip_`, so a `tenant_hash` value is never
    mistakable for one of those at a glance."""
    result = tenant_hash(uuid.uuid4(), b"salt")
    assert result.startswith("th_")


def test_indicator_hash_is_the_shared_salt_construction_reexported_unmodified() -> None:
    """`app.tier2.hashing.indicator_hash` must be the literal same function as
    `app.privacy.pseudonymize.indicator_hash` — re-exported, never reimplemented (see
    that module's docstring for why duplicating the HMAC construction would risk drift)."""
    from app.tier2.hashing import indicator_hash as reexported

    assert reexported is indicator_hash


def test_same_value_same_shared_salt_produces_the_same_indicator_hash_across_calls() -> None:
    shared_salt = b"the-one-shared-cross-tenant-salt"
    assert indicator_hash("evil.example.com", "domain", shared_salt) == indicator_hash(
        "evil.example.com", "domain", shared_salt
    )


def test_different_shared_salts_break_cross_tenant_correlation() -> None:
    """The concrete failure mode CLAUDE.md calls "silently destroys the feature": if two
    tenants' indicator hashing ever used different salts (e.g. by accident, per-tenant),
    the same real-world domain would never appear to overlap."""
    assert indicator_hash("evil.example.com", "domain", b"salt-a") != indicator_hash(
        "evil.example.com", "domain", b"salt-b"
    )
