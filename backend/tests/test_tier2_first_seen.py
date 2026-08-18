"""Tier 2 chart 4 — for indicators seen by 2+ tenants, when each tenant first observed it.
Builds three tenants seeing the same domain at different times and proves
`list_first_seen_propagation` reports each tenant's own first-seen timestamp, sorted
earliest-first, and never a raw domain value.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.core.db import (
    get_session_factory,
    get_tier2_session_factory,
    init_tier2_schema,
)
from app.models.tier2_signature import Tier2Signature
from app.tier2.first_seen import list_first_seen_propagation
from app.tier2.signature_sync import sync_incident_to_tier2
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_triage_verdict
from tests.fixtures.tier2 import (
    make_entity,
    tier2_signature_cleanup,  # noqa: F401 -- pytest fixture registration
    tier2_tenant_cleanup,  # noqa: F401 -- pytest fixture registration
)

_SHARED_SALT_SETTINGS = Settings(_env_file=None, tier2_indicator_salt="first-seen-test-shared-salt")
_DOMAIN = "first-seen-propagation-test.example"


@pytest.fixture
def three_tenants(tier2_tenant_cleanup: list[uuid.UUID]):  # noqa: F811
    tenants = {}
    for label in ("a", "b", "c"):
        tenant = make_tenant(name=f"First Seen Test Tenant {label.upper()}")
        tier2_tenant_cleanup.append(tenant.id)
        user = make_user(tenant_id=tenant.id, email=f"firstseen-{label}-{uuid.uuid4()}@test.local")
        analysis = make_analysis(tenant_id=tenant.id, user_id=user.id, detected_sources=["zscaler"])
        tenants[label] = {"tenant": tenant, "analysis": analysis}
    return tenants


def _sync_at(tenant_ctx: dict, *, observed_at: datetime) -> Tier2Signature:
    tenant, analysis = tenant_ctx["tenant"], tenant_ctx["analysis"]
    entity = make_entity(analysis_id=analysis.id, entity_type="domain", value=_DOMAIN)
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[entity.id], fused_score=0.9
    )
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
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
            settings=_SHARED_SALT_SETTINGS,
        )
        assert signature is not None
        signature.observed_at = observed_at
        tier2.add(signature)
        tier2.commit()
        tier2.refresh(signature)
        session.commit()
        return signature
    finally:
        tier2.close()
        session.close()


def test_reports_each_tenants_own_first_seen_timestamp_sorted_ascending(
    three_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    now = datetime.now(UTC)
    sig_a = _sync_at(three_tenants["a"], observed_at=now - timedelta(days=10))
    sig_b = _sync_at(three_tenants["b"], observed_at=now - timedelta(days=6))
    sig_c = _sync_at(three_tenants["c"], observed_at=now - timedelta(days=1))
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id, sig_c.id])
    shared_hash = sig_a.indicator_hashes[0]

    session = get_tier2_session_factory()()
    try:
        items = list_first_seen_propagation(session, min_tenants=2)
    finally:
        session.close()

    row = next(item for item in items if item.indicator_hash == shared_hash)
    assert row.tenant_count == 3
    assert len(row.observations) == 3
    # Earliest-seen tenant (A) first, latest (C) last -- the early-warning story this chart
    # exists to tell.
    timestamps = [obs.first_observed_at for obs in row.observations]
    assert timestamps == sorted(timestamps)
    tenant_hashes = {obs.tenant_hash for obs in row.observations}
    assert len(tenant_hashes) == 3  # three genuinely distinct tenants, never collapsed


def test_no_raw_domain_value_is_recoverable_from_the_response(
    three_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    now = datetime.now(UTC)
    sig_a = _sync_at(three_tenants["a"], observed_at=now - timedelta(days=2))
    sig_b = _sync_at(three_tenants["b"], observed_at=now)
    tier2_signature_cleanup.extend([sig_a.id, sig_b.id])

    session = get_tier2_session_factory()()
    try:
        items = list_first_seen_propagation(session, min_tenants=2)
    finally:
        session.close()

    assert _DOMAIN not in repr(items)


def test_an_indicator_seen_by_only_one_tenant_is_excluded(
    three_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    lonely_domain_ctx = three_tenants["a"]
    tenant, analysis = lonely_domain_ctx["tenant"], lonely_domain_ctx["analysis"]
    entity = make_entity(
        analysis_id=analysis.id, entity_type="domain", value="only-one-tenant-ever.example"
    )
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[entity.id], fused_score=0.9
    )
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
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
            settings=_SHARED_SALT_SETTINGS,
        )
        assert signature is not None
        tier2.commit()
        tier2.refresh(signature)
        session.commit()
    finally:
        tier2.close()
        session.close()
    tier2_signature_cleanup.append(signature.id)
    lonely_hash = signature.indicator_hashes[0]

    session = get_tier2_session_factory()()
    try:
        items = list_first_seen_propagation(session, min_tenants=2)
    finally:
        session.close()

    assert lonely_hash not in {item.indicator_hash for item in items}
