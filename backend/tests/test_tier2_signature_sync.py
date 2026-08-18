"""Task 1 — docs/13 M14: "After an incident is triaged, emit a tier2_signatures row."

Runs against the live Postgres (`tests/conftest.py`'s convention, not a mock) so the
persisted row's actual column values are what's asserted, not a hand-rolled stand-in.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.core.db import get_session_factory, get_tier2_session_factory, init_tier2_schema
from app.models.base import tenant_scope
from app.models.tier2_signature import Tier2Signature
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.signature_sync import (
    build_signature,
    derive_indicators,
    derive_source_types,
    should_sync_to_tier2,
    sync_incident_to_tier2,
)
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_triage_verdict
from tests.fixtures.tier2 import (
    make_entity,
    tier2_signature_cleanup,  # noqa: F401 -- imported for pytest fixture registration, used by name as a parameter below
    tier2_tenant_cleanup,  # noqa: F401 -- same as above
)

_REAL_SALT_SETTINGS = Settings(_env_file=None, tier2_indicator_salt="a-real-shared-indicator-salt")


@pytest.fixture
def ctx(tier2_tenant_cleanup: list[uuid.UUID]):  # noqa: F811
    tenant = make_tenant(name="Tier2 Sync Test Tenant")
    tier2_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"tier2sync-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id, detected_sources=["zscaler"])
    return {"tenant": tenant, "user": user, "analysis": analysis}


# ---------------------------------------------------------------------------- should_sync_to_tier2


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        ("true_positive", True),
        ("needs_review", True),
        ("false_positive", False),
        ("benign", False),
    ],
)
def test_should_sync_gate(disposition: str, expected: bool, ctx: dict) -> None:
    incident = make_incident(tenant_id=ctx["tenant"].id, analysis_id=ctx["analysis"].id)
    verdict = make_triage_verdict(
        incident_id=incident.id, recommended_actions=[], disposition=disposition
    )
    assert should_sync_to_tier2(verdict) is expected


# ---------------------------------------------------------------------------- build_signature


def test_build_signature_uses_per_tenant_salt_for_tenant_hash(ctx: dict) -> None:
    """The salt-direction assertion CLAUDE.md calls load-bearing: `tenant_hash` must use
    the tenant's OWN `pseudonym_salt`, never the shared indicator salt."""
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.77)
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=["zscaler"],
        indicators=[],
        settings=_REAL_SALT_SETTINGS,
    )

    assert signature.tenant_hash == tenant_hash(tenant.id, tenant.pseudonym_salt)
    # And *not* computable from the shared indicator salt -- proves the two are genuinely
    # different code paths, not the same HMAC with a relabeled input.
    wrong = tenant_hash(
        tenant.id, _REAL_SALT_SETTINGS.tier2_indicator_salt.get_secret_value().encode()
    )
    assert signature.tenant_hash != wrong


def test_build_signature_uses_shared_salt_for_indicator_hashes(ctx: dict) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
    shared_salt = _REAL_SALT_SETTINGS.tier2_indicator_salt.get_secret_value().encode()

    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=["zscaler"],
        indicators=[("domain", "evil.example.com"), ("ip", "203.0.113.9")],
        settings=_REAL_SALT_SETTINGS,
    )

    expected = {
        indicator_hash("evil.example.com", "domain", shared_salt),
        indicator_hash("203.0.113.9", "ip", shared_salt),
    }
    assert set(signature.indicator_hashes) == expected
    # Never computed with the tenant's own per-tenant salt -- the other half of the same
    # load-bearing assertion, from the opposite direction.
    wrong = indicator_hash("evil.example.com", "domain", tenant.pseudonym_salt)
    assert wrong not in signature.indicator_hashes


def test_build_signature_confidence_is_fused_score_not_llm_confidence(ctx: dict) -> None:
    """CLAUDE.md rule 5: the LLM does not set priority. `tier2_signatures.confidence` must come
    from the calibrated `incident.fused_score`, never from the LLM's own opinion of the incident
    -- and since docs/v2_migration change 3, the LLM doesn't even have a float opinion to leak
    anymore: `verdict.threat_confidence` is a low/moderate/high enum, not a number, so it could
    not populate this column even by accident. The fixture's `threat_confidence="high"` default
    is deliberately the opposite "temperature" of the incident's own low `fused_score=0.42`, so a
    regression that somehow derived `signature.confidence` from disposition/threat_confidence
    instead of `fused_score` would be caught by the value, not just the type."""
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.42)
    verdict = make_triage_verdict(
        incident_id=incident.id, recommended_actions=[], threat_confidence="high"
    )

    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=[],
        indicators=[],
        settings=_REAL_SALT_SETTINGS,
    )
    assert signature.confidence == pytest.approx(0.42)
    assert isinstance(signature.confidence, float)
    assert verdict.threat_confidence == "high"


@pytest.mark.parametrize(
    ("technique_id", "expected_type"),
    [
        ("T1071.001", "c2_beaconing"),
        ("T1567.002", "data_exfiltration"),
        ("T1567", "data_exfiltration"),
        ("T1530", "insider_mass_download"),
        ("T1078", "peer_group_deviation"),
        ("T1029", "seasonal_deviation"),
        ("T9999.999", "uncategorized"),
    ],
)
def test_build_signature_incident_type_from_mitre_technique(
    technique_id: str, expected_type: str, ctx: dict
) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    session = get_session_factory()()
    try:
        verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
        verdict.mitre_techniques = [{"id": technique_id, "name": "x", "rationale": "y"}]
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
    finally:
        session.close()

    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=[],
        indicators=[],
        settings=_REAL_SALT_SETTINGS,
    )
    assert signature.incident_type == expected_type


def test_build_signature_observed_at_is_incident_created_at_not_verdict(ctx: dict) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=[],
        indicators=[],
        settings=_REAL_SALT_SETTINGS,
    )
    assert signature.observed_at == incident.created_at
    assert signature.observed_at != datetime.now(UTC)  # sanity: not "now"


def test_build_signature_rejects_mismatched_incident_and_verdict(ctx: dict) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    other_incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    verdict = make_triage_verdict(incident_id=other_incident.id, recommended_actions=[])

    with pytest.raises(ValueError, match="belongs to incident"):
        build_signature(
            incident=incident,
            verdict=verdict,
            tenant=tenant,
            source_types=[],
            indicators=[],
            settings=_REAL_SALT_SETTINGS,
        )


def test_build_signature_rejects_mismatched_incident_and_tenant(
    ctx: dict,
    tier2_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    other_tenant = make_tenant(name="Some Other Tenant")
    tier2_tenant_cleanup.append(other_tenant.id)
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    with pytest.raises(ValueError, match="belongs to tenant"):
        build_signature(
            incident=incident,
            verdict=verdict,
            tenant=other_tenant,
            source_types=[],
            indicators=[],
            settings=_REAL_SALT_SETTINGS,
        )


# ---------------------------------------------------------------------------- derive_* helpers


def test_derive_indicators_only_domain_and_dst_ip(ctx: dict) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    e_domain = make_entity(analysis_id=analysis.id, entity_type="domain", value="c2.example.com")
    e_dst_ip = make_entity(analysis_id=analysis.id, entity_type="dst_ip", value="203.0.113.5")
    e_user = make_entity(analysis_id=analysis.id, entity_type="user", value="u_deadbeef")
    e_src_ip = make_entity(analysis_id=analysis.id, entity_type="src_ip", value="10.0.0.5")
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_ids=[e_domain.id, e_dst_ip.id, e_user.id, e_src_ip.id],
    )

    session = get_session_factory()()
    try:
        indicators = derive_indicators(session, incident)
    finally:
        session.close()

    assert set(indicators) == {("domain", "c2.example.com"), ("ip", "203.0.113.5")}


def test_derive_source_types_from_upload(ctx: dict) -> None:
    tenant = ctx["tenant"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=ctx["analysis"].id)
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            source_types = derive_source_types(session, incident)
    finally:
        session.close()
    assert source_types == ["zscaler"]


# ---------------------------------------------------------------------------- sync_incident_to_tier2 (end to end)


def test_sync_incident_to_tier2_persists_a_real_row(
    ctx: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    e_domain = make_entity(analysis_id=analysis.id, entity_type="domain", value="beacon.evil.test")
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[e_domain.id], fused_score=0.91
    )
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    # Two sessions: the reads come from the primary database, the signature write goes to the
    # Tier 2 one. They are different engines over different databases.
    init_tier2_schema()
    session = get_session_factory()()
    tier2 = get_tier2_session_factory()()
    try:
        signature = sync_incident_to_tier2(
            session,
            tier2_session=tier2,
            incident=incident,
            verdict=verdict,
            tenant=tenant,
            settings=_REAL_SALT_SETTINGS,
        )
        assert signature is not None
        tier2_signature_cleanup.append(signature.id)
        tier2.commit()
        session.commit()
    finally:
        tier2.close()
        session.close()

    # Re-fetch independently -- proves it was actually committed, not just an in-memory object.
    # From the Tier 2 engine: that is where the row now lives.
    verify = get_tier2_session_factory()()
    try:
        row = verify.execute(
            select(Tier2Signature).where(Tier2Signature.id == signature.id)
        ).scalar_one()
    finally:
        verify.close()

    assert row.tenant_hash == tenant_hash(tenant.id, tenant.pseudonym_salt)
    assert row.incident_type == "c2_beaconing"
    assert row.mitre_techniques == ["T1071.001"]
    assert row.source_types == ["zscaler"]
    assert row.confidence == pytest.approx(0.91)
    assert len(row.indicator_hashes) == 1
    assert row.indicator_hashes[0] != "beacon.evil.test"  # never the raw value
    assert row.observed_at == incident.created_at


def test_sync_incident_to_tier2_skips_benign_and_writes_nothing(
    ctx: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    verdict = make_triage_verdict(
        incident_id=incident.id, recommended_actions=[], disposition="benign"
    )

    init_tier2_schema()
    session = get_session_factory()()
    tier2 = get_tier2_session_factory()()
    try:
        before = tier2.execute(select(Tier2Signature.id)).all()
        result = sync_incident_to_tier2(
            session,
            tier2_session=tier2,
            incident=incident,
            verdict=verdict,
            tenant=tenant,
            settings=_REAL_SALT_SETTINGS,
        )
        tier2.commit()
        session.commit()
        after = tier2.execute(select(Tier2Signature.id)).all()
    finally:
        tier2.close()
        session.close()

    assert result is None
    assert before == after
