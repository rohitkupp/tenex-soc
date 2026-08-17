"""Task 2 — "This C2 domain appeared in 3 other tenants" without any tenant seeing
another's raw data. Simulates two tenants end to end: sync a signature for each (through
the real `sync_incident_to_tier2`, not a hand-built row) that both observed the same C2
domain, then prove the overlap surfaces via `app.tier2.indicator_overlap` while neither
tenant's raw indicator value or identity is ever recoverable from the other's view.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.core.db import get_session_factory
from app.models.tier2_signature import Tier2Signature
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.indicator_overlap import (
    get_overview,
    list_indicator_overlap,
    list_overlap_distribution,
)
from app.tier2.signature_sync import sync_incident_to_tier2
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_triage_verdict
from tests.fixtures.tier2 import (
    make_entity,
    tier2_signature_cleanup,  # noqa: F401 -- imported for pytest fixture registration, used by name as a parameter below
    tier2_tenant_cleanup,  # noqa: F401 -- same as above
)

_SHARED_SALT_SETTINGS = Settings(
    _env_file=None, tier2_indicator_salt="the-one-shared-indicator-salt-for-this-test"
)

_SHARED_C2_DOMAIN = "c2.two-tenant-overlap-test.example"


@pytest.fixture
def two_tenants(tier2_tenant_cleanup: list[uuid.UUID]):  # noqa: F811
    """Tenant A and Tenant B, each with their own upload/analysis, each having seen the
    *same* C2 domain independently -- the minimal scenario the whole feature exists for."""
    tenants = {}
    for label in ("a", "b"):
        tenant = make_tenant(name=f"Overlap Test Tenant {label.upper()}")
        tier2_tenant_cleanup.append(tenant.id)
        user = make_user(tenant_id=tenant.id, email=f"overlap-{label}-{uuid.uuid4()}@test.local")
        analysis = make_analysis(tenant_id=tenant.id, user_id=user.id, detected_sources=["zscaler"])
        tenants[label] = {"tenant": tenant, "user": user, "analysis": analysis}
    return tenants


def _sync_signature_for_tenant(tenant_ctx: dict, domain: str) -> Tier2Signature:
    tenant, analysis = tenant_ctx["tenant"], tenant_ctx["analysis"]
    entity = make_entity(analysis_id=analysis.id, entity_type="domain", value=domain)
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[entity.id], fused_score=0.88
    )
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    session = get_session_factory()()
    try:
        signature = sync_incident_to_tier2(
            session,
            incident=incident,
            verdict=verdict,
            tenant=tenant,
            settings=_SHARED_SALT_SETTINGS,
        )
        assert signature is not None
        session.commit()
        session.refresh(signature)
        return signature
    finally:
        session.close()


def test_two_tenants_seeing_the_same_domain_produce_the_same_indicator_hash(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    sig_a = _sync_signature_for_tenant(two_tenants["a"], _SHARED_C2_DOMAIN)
    sig_b = _sync_signature_for_tenant(two_tenants["b"], _SHARED_C2_DOMAIN)
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])

    # The whole mechanism, in one assertion: same domain, shared salt -> same hash,
    # independent of which tenant hashed it.
    assert sig_a.indicator_hashes == sig_b.indicator_hashes
    # But their tenant identities are provably distinct, and non-reversible to each other.
    assert sig_a.tenant_hash != sig_b.tenant_hash


def test_overlap_surfaces_across_the_two_tenants(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    sig_a = _sync_signature_for_tenant(two_tenants["a"], _SHARED_C2_DOMAIN)
    sig_b = _sync_signature_for_tenant(two_tenants["b"], _SHARED_C2_DOMAIN)
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])
    shared_hash = sig_a.indicator_hashes[0]

    session = get_session_factory()()
    try:
        rows = list_indicator_overlap(session, min_tenants=2, limit=50)
    finally:
        session.close()

    matching = [r for r in rows if r.indicator_hash == shared_hash]
    assert len(matching) == 1, "the shared indicator must appear exactly once in the overlap view"
    row = matching[0]
    assert row.tenant_count == 2
    assert row.signature_count == 2


def test_a_tenant_seen_indicator_alone_does_not_appear_as_overlap(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The negative case: an indicator only tenant A has ever seen must not show up in the
    min_tenants=2 overlap listing at all -- overlap means *cross*-tenant, not "any
    signature exists."""
    sig_a = _sync_signature_for_tenant(two_tenants["a"], "only-tenant-a-ever-saw-this.example")
    tier2_signature_cleanup.append(sig_a.id)
    lonely_hash = sig_a.indicator_hashes[0]

    session = get_session_factory()()
    try:
        rows = list_indicator_overlap(session, min_tenants=2, limit=200)
    finally:
        session.close()

    assert lonely_hash not in {r.indicator_hash for r in rows}


def test_neither_tenants_raw_indicator_value_is_recoverable_from_the_other_view(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The privacy half of the milestone brief: "neither tenant's raw indicator values are
    recoverable from the other's view." Everything the overlap query returns is checked
    for the literal raw domain string -- it must never appear anywhere in the row."""
    sig_a = _sync_signature_for_tenant(two_tenants["a"], _SHARED_C2_DOMAIN)
    sig_b = _sync_signature_for_tenant(two_tenants["b"], _SHARED_C2_DOMAIN)
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])

    session = get_session_factory()()
    try:
        rows = list_indicator_overlap(session, min_tenants=2, limit=50)
        overview = get_overview(session)
    finally:
        session.close()

    serialized_overlap = repr(rows)
    serialized_overview = repr(overview)
    assert _SHARED_C2_DOMAIN not in serialized_overlap
    assert _SHARED_C2_DOMAIN not in serialized_overview
    # And the hash genuinely isn't the plaintext domain either, just to make the assertion
    # above meaningful rather than vacuous.
    assert sig_a.indicator_hashes[0] != _SHARED_C2_DOMAIN


def test_neither_tenants_identity_is_recoverable_from_tenant_hash_alone(two_tenants: dict) -> None:
    """The other half of "neither tenant sees another's raw data": `tenant_hash` alone
    (what the overlap/overview queries expose) must not let you recompute `tenant_id`
    without also knowing that tenant's own `pseudonym_salt` -- which per-tenant salt this
    test proves is genuinely different per tenant, so guessing one salt doesn't help with
    the other."""
    tenant_a, tenant_b = two_tenants["a"]["tenant"], two_tenants["b"]["tenant"]
    assert tenant_a.pseudonym_salt != tenant_b.pseudonym_salt

    hash_a = tenant_hash(tenant_a.id, tenant_a.pseudonym_salt)
    # Attempting to "verify" tenant A's identity using tenant B's salt must not match --
    # i.e. tenant_hash is not something a party without tenant A's own salt can forge or
    # confirm.
    forged_with_wrong_salt = tenant_hash(tenant_a.id, tenant_b.pseudonym_salt)
    assert hash_a != forged_with_wrong_salt


def test_overview_totals_reflect_both_tenants(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    sig_a = _sync_signature_for_tenant(two_tenants["a"], _SHARED_C2_DOMAIN)
    sig_b = _sync_signature_for_tenant(two_tenants["b"], "second-domain-only-b.example")
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])

    session = get_session_factory()()
    try:
        overview = get_overview(session)
    finally:
        session.close()

    assert overview.total_signatures >= 2
    assert overview.total_tenants >= 2
    incident_types = {row.incident_type for row in overview.by_incident_type}
    assert "c2_beaconing" in incident_types


def test_overlap_distribution_buckets_a_two_tenant_indicator_under_the_two_bucket(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """Tier 2 chart 1: an indicator seen by exactly two tenants must land in the `"2"`
    bucket, and a lonely, single-tenant indicator must land in `"1"` -- always three
    buckets present (`"1"`, `"2"`, `"3+"`), even when one of them is zero for this run."""
    sig_a = _sync_signature_for_tenant(two_tenants["a"], _SHARED_C2_DOMAIN)
    sig_b = _sync_signature_for_tenant(two_tenants["b"], _SHARED_C2_DOMAIN)
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])

    session = get_session_factory()()
    try:
        dist = list_overlap_distribution(session)
    finally:
        session.close()

    assert [b.bucket for b in dist.buckets] == ["1", "2", "3+"]
    assert dist.total_indicators == sum(b.indicator_count for b in dist.buckets)
    two_bucket = next(b for b in dist.buckets if b.bucket == "2")
    assert two_bucket.indicator_count >= 1


def test_shared_salt_is_what_makes_overlap_detectable_at_all(
    two_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The negative control that proves the salt tradeoff is load-bearing, not incidental:
    hashing the same domain with two genuinely different salts (simulating the mistake
    CLAUDE.md warns about -- per-tenant salt on an indicator) produces two different
    hashes, which is exactly the silent feature-destroying failure mode the shared salt
    exists to avoid."""
    shared_salt = _SHARED_SALT_SETTINGS.tier2_indicator_salt.get_secret_value().encode()
    tenant_a_salt = two_tenants["a"]["tenant"].pseudonym_salt
    tenant_b_salt = two_tenants["b"]["tenant"].pseudonym_salt

    correct_a = indicator_hash(_SHARED_C2_DOMAIN, "domain", shared_salt)
    correct_b = indicator_hash(_SHARED_C2_DOMAIN, "domain", shared_salt)
    assert correct_a == correct_b  # the feature, working

    wrong_a = indicator_hash(_SHARED_C2_DOMAIN, "domain", tenant_a_salt)
    wrong_b = indicator_hash(_SHARED_C2_DOMAIN, "domain", tenant_b_salt)
    assert wrong_a != wrong_b  # the bug CLAUDE.md warns "getting this backwards" causes
