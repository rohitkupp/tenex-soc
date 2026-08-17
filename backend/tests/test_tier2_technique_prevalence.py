"""Tier 2 chart 2 — "which ATT&CK techniques appear in how many tenants." Builds real
`tier2_signatures` rows through `sync_incident_to_tier2` (same helper
`tests/test_tier2_indicator_overlap.py` uses), not hand-inserted rows, then proves
`list_technique_prevalence` counts distinct tenants per allowlisted technique correctly and
never fabricates or drops a technique id.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.core.db import get_session_factory
from app.models.tier2_signature import Tier2Signature
from app.tier2.signature_sync import sync_incident_to_tier2
from app.tier2.technique_prevalence import list_technique_prevalence
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_triage_verdict
from tests.fixtures.tier2 import (
    make_entity,
    tier2_signature_cleanup,  # noqa: F401 -- pytest fixture registration
    tier2_tenant_cleanup,  # noqa: F401 -- pytest fixture registration
)

_SHARED_SALT_SETTINGS = Settings(
    _env_file=None, tier2_indicator_salt="technique-prevalence-test-shared-salt"
)


def _make_tenant_ctx(label: str, tier2_tenant_cleanup: list[uuid.UUID]) -> dict:  # noqa: F811
    tenant = make_tenant(name=f"Technique Prevalence Test Tenant {label}")
    tier2_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"techprev-{label}-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id, detected_sources=["zscaler"])
    return {"tenant": tenant, "user": user, "analysis": analysis}


def _sync_signature(
    tenant_ctx: dict, *, domain: str, technique_id: str, technique_name: str
) -> Tier2Signature:
    tenant, analysis = tenant_ctx["tenant"], tenant_ctx["analysis"]
    entity = make_entity(analysis_id=analysis.id, entity_type="domain", value=domain)
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[entity.id], fused_score=0.9
    )
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
    # `make_triage_verdict` hardcodes T1071.001 -- override to the technique this test needs.
    session = get_session_factory()()
    try:
        verdict.mitre_techniques = [
            {"id": technique_id, "name": technique_name, "rationale": "test"}
        ]
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
    finally:
        session.close()

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


@pytest.fixture
def three_tenants(tier2_tenant_cleanup: list[uuid.UUID]):  # noqa: F811
    return {label: _make_tenant_ctx(label, tier2_tenant_cleanup) for label in ("A", "B", "C")}


def test_returns_all_thirteen_allowlisted_techniques_even_with_zero_signatures() -> None:
    session = get_session_factory()()
    try:
        result = list_technique_prevalence(session)
    finally:
        session.close()
    assert len(result.items) == 13
    assert {item.technique_id for item in result.items} <= _all_allowlisted_ids()
    for item in result.items:
        assert item.tenant_count >= 0
        assert item.signature_count >= 0


def _all_allowlisted_ids() -> set[str]:
    from app.tier2.mitre_allowlist import load_allowlisted_techniques

    return set(load_allowlisted_techniques().keys())


def test_a_technique_seen_by_three_tenants_reports_tenant_count_three(
    three_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    sigs = [
        _sync_signature(
            three_tenants[label],
            domain=f"techprev-{label.lower()}.example",
            technique_id="T1595",
            technique_name="Active Scanning",
        )
        for label in ("A", "B", "C")
    ]
    tier2_signature_cleanup.extend(s.id for s in sigs)

    session = get_session_factory()()
    try:
        result = list_technique_prevalence(session)
    finally:
        session.close()

    row = next(item for item in result.items if item.technique_id == "T1595")
    assert row.tenant_count >= 3
    assert row.signature_count >= 3


def test_a_signature_with_no_indicators_does_not_count_toward_prevalence(
    three_tenants: dict,
    tier2_signature_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """Signatures synced from an incident with no domain/dst-IP entity carry an empty
    `indicator_hashes` array -- `list_technique_prevalence` excludes those (module docstring:
    "restricted to indicator-bearing signatures"), so a technique observed only that way must
    not move the count. Compares before/after (rather than asserting an absolute value) since
    unrelated pre-existing rows for this same technique may already exist in this environment's
    shared database."""
    session = get_session_factory()()
    try:
        before = next(
            item
            for item in list_technique_prevalence(session).items
            if item.technique_id == "T1204"
        )
    finally:
        session.close()

    tenant, analysis = three_tenants["A"]["tenant"], three_tenants["A"]["analysis"]
    # No entities at all -- build_signature/should_sync_to_tier2 still syncs a true_positive
    # incident, but with an empty indicator_hashes array (no domain/IP entity to hash).
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.9)
    verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
    session = get_session_factory()()
    try:
        verdict.mitre_techniques = [{"id": "T1204", "name": "User Execution", "rationale": "test"}]
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
        signature = sync_incident_to_tier2(
            session,
            incident=incident,
            verdict=verdict,
            tenant=tenant,
            settings=_SHARED_SALT_SETTINGS,
        )
        assert signature is not None
        assert signature.indicator_hashes == []
        session.commit()
        session.refresh(signature)
    finally:
        session.close()
    tier2_signature_cleanup.append(signature.id)

    session = get_session_factory()()
    try:
        after = next(
            item
            for item in list_technique_prevalence(session).items
            if item.technique_id == "T1204"
        )
    finally:
        session.close()

    assert after.signature_count == before.signature_count
    assert after.tenant_count == before.tenant_count
