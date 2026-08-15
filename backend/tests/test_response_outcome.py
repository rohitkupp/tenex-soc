"""`app.response.outcome` — post-execution containment verification and the autonomous
containment rate, docs/08's "loop closure." Runs against the live Postgres."""

from __future__ import annotations

import uuid

import pytest

from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.models.response_plan import ResponsePlan
from app.response import outcome, state
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import (  # noqa: F401
    make_incident,
    make_signal,
    response_tenant_cleanup,
)


@pytest.fixture
def tenant_and_analysis(response_tenant_cleanup: list[uuid.UUID]) -> tuple[uuid.UUID, uuid.UUID]:  # noqa: F811
    tenant = make_tenant(name="Response Outcome Test Tenant")
    response_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"outcome-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    return tenant.id, analysis.id


# ---------------------------------------------------------------------------- per-signal resolution


def test_user_signal_resolves_when_sessions_revoked(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    signal = make_signal(
        tenant_id=tenant_id, analysis_id=analysis_id, entity_type="user", entity_value="alice"
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            unresolved = outcome._resolve_signal(session, tenant_id, signal)
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_OKTA_SESSION,
                "alice",
                {
                    "sessions": [{"id": "s1", "active": False}],
                    "credential_reset_required": False,
                    "account_status": "active",
                },
            )
            session.commit()
            resolved = outcome._resolve_signal(session, tenant_id, signal)
    finally:
        session.close()

    assert unresolved.resolved is False
    assert resolved.resolved is True


def test_domain_signal_resolves_when_blocked(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    signal = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="evil.example.com",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            unresolved = outcome._resolve_signal(session, tenant_id, signal)
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "evil.example.com",
                {"kind": "domain", "blocked": True, "allowlisted": False},
            )
            session.commit()
            resolved = outcome._resolve_signal(session, tenant_id, signal)
    finally:
        session.close()

    assert unresolved.resolved is False
    assert resolved.resolved is True


def test_dst_ip_signal_resolves_when_blocked(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    signal = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="dst_ip",
        entity_value="203.0.113.9",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "203.0.113.9",
                {"kind": "dst_ip", "blocked": True, "allowlisted": False},
            )
            session.commit()
            resolved = outcome._resolve_signal(session, tenant_id, signal)
    finally:
        session.close()

    assert resolved.resolved is True


def test_src_ip_signal_resolves_when_host_isolated(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    signal = make_signal(
        tenant_id=tenant_id, analysis_id=analysis_id, entity_type="src_ip", entity_value="10.1.2.3"
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            unresolved = outcome._resolve_signal(session, tenant_id, signal)
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_HOST,
                "10.1.2.3",
                {"isolated": True, "hostname": "10.1.2.3", "files": {}},
            )
            session.commit()
            resolved = outcome._resolve_signal(session, tenant_id, signal)
    finally:
        session.close()

    assert unresolved.resolved is False
    assert resolved.resolved is True


def test_unmapped_entity_type_is_never_resolved(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    signal = make_signal(
        tenant_id=tenant_id, analysis_id=analysis_id, entity_type="country", entity_value="RU"
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = outcome._resolve_signal(session, tenant_id, signal)
    finally:
        session.close()

    assert result.resolved is False
    assert "no corresponding control" in result.reason


# ---------------------------------------------------------------------------- rollup


def test_evaluate_outcome_all_resolved_is_contained(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    s1 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="a.example.com",
    )
    s2 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="b.example.com",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            for domain in ("a.example.com", "b.example.com"):
                state.write_state(
                    session,
                    tenant_id,
                    state.RESOURCE_PROXY_POLICY,
                    domain,
                    {"kind": "domain", "blocked": True, "allowlisted": False},
                )
            session.commit()
            result = outcome.evaluate_outcome(session, tenant_id, [s1, s2], halted=False)
    finally:
        session.close()

    assert result.outcome == outcome.OUTCOME_CONTAINED
    detail = outcome.outcome_detail(result)
    assert detail == {
        "resolved_count": 2,
        "total_count": 2,
        "signals": [
            {
                "signal_id": s1.id,
                "entity_type": "domain",
                "entity_value": "a.example.com",
                "resolved": True,
                "reason": "blocked at the proxy",
            },
            {
                "signal_id": s2.id,
                "entity_type": "domain",
                "entity_value": "b.example.com",
                "resolved": True,
                "reason": "blocked at the proxy",
            },
        ],
    }


def test_evaluate_outcome_some_resolved_is_partially_contained(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    s1 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="blocked.example.com",
    )
    s2 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="unblocked.example.com",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "blocked.example.com",
                {"kind": "domain", "blocked": True, "allowlisted": False},
            )
            session.commit()
            result = outcome.evaluate_outcome(session, tenant_id, [s1, s2], halted=False)
    finally:
        session.close()

    assert result.outcome == outcome.OUTCOME_PARTIALLY_CONTAINED


def test_evaluate_outcome_none_resolved_is_failed(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    s1 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="never-touched.example.com",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = outcome.evaluate_outcome(session, tenant_id, [s1], halted=False)
    finally:
        session.close()

    assert result.outcome == outcome.OUTCOME_FAILED


def test_evaluate_outcome_halted_is_always_failed_even_if_some_resolved(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """docs/08's table: "failed: none resolve, OR the plan halted" — a halted plan is `failed`
    at the rollup level even though the per-signal detail still honestly shows a resolved
    signal."""
    tenant_id, analysis_id = tenant_and_analysis
    s1 = make_signal(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        entity_type="domain",
        entity_value="resolved.example.com",
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "resolved.example.com",
                {"kind": "domain", "blocked": True, "allowlisted": False},
            )
            session.commit()
            result = outcome.evaluate_outcome(session, tenant_id, [s1], halted=True)
    finally:
        session.close()

    assert result.outcome == outcome.OUTCOME_FAILED
    detail = outcome.outcome_detail(result)
    assert detail["resolved_count"] == 1  # honest per-signal detail survives the forced rollup


def test_evaluate_outcome_no_signals_is_vacuously_contained(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, _analysis_id = tenant_and_analysis
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = outcome.evaluate_outcome(session, tenant_id, [], halted=False)
    finally:
        session.close()
    assert result.outcome == outcome.OUTCOME_CONTAINED


def test_fetch_incident_signals_returns_rows_for_signal_ids(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    s1 = make_signal(
        tenant_id=tenant_id, analysis_id=analysis_id, entity_type="user", entity_value="alice"
    )
    incident = make_incident(tenant_id=tenant_id, analysis_id=analysis_id, signal_ids=[s1.id])

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            signals = outcome.fetch_incident_signals(session, incident)
    finally:
        session.close()
    assert [s.id for s in signals] == [s1.id]


# ---------------------------------------------------------------------------- containment rate


def test_containment_rate_across_multiple_plans(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    incident_1 = make_incident(tenant_id=tenant_id, analysis_id=analysis_id)
    incident_2 = make_incident(tenant_id=tenant_id, analysis_id=analysis_id)
    incident_3 = make_incident(tenant_id=tenant_id, analysis_id=analysis_id)

    session = get_session_factory()()
    try:
        # No executed plans yet — rate is undefined (no denominator), not zero.
        with tenant_scope(session, tenant_id):
            zero_state = outcome.containment_rate(session, tenant_id)
        assert zero_state == {"contained": 0, "total": 0, "rate": None}

        for inc, plan_outcome in (
            (incident_1, outcome.OUTCOME_CONTAINED),
            (incident_2, outcome.OUTCOME_CONTAINED),
            (incident_3, outcome.OUTCOME_FAILED),
        ):
            plan = ResponsePlan(
                incident_id=inc.id,
                actions=[],
                verification={"skipped": "llm_disabled"},
                status="approved",
                execution_log=[],
                outcome=plan_outcome,
                outcome_detail={"resolved_count": 0, "total_count": 0, "signals": []},
            )
            session.add(plan)
        session.commit()

        with tenant_scope(session, tenant_id):
            result = outcome.containment_rate(session, tenant_id)
    finally:
        session.close()

    assert result == {"contained": 2, "total": 3, "rate": pytest.approx(2 / 3)}


def test_containment_rate_is_tenant_isolated(response_tenant_cleanup: list[uuid.UUID]) -> None:  # noqa: F811
    tenant_a = make_tenant(name="Containment Rate Tenant A")
    tenant_b = make_tenant(name="Containment Rate Tenant B")
    response_tenant_cleanup.append(tenant_a.id)
    response_tenant_cleanup.append(tenant_b.id)
    user_a = make_user(tenant_id=tenant_a.id, email=f"rate-a-{uuid.uuid4()}@test.local")
    analysis_a = make_analysis(tenant_id=tenant_a.id, user_id=user_a.id)
    incident_a = make_incident(tenant_id=tenant_a.id, analysis_id=analysis_a.id)

    session = get_session_factory()()
    try:
        plan = ResponsePlan(
            incident_id=incident_a.id,
            actions=[],
            verification={"skipped": "llm_disabled"},
            status="approved",
            execution_log=[],
            outcome=outcome.OUTCOME_CONTAINED,
            outcome_detail={},
        )
        session.add(plan)
        session.commit()

        with tenant_scope(session, tenant_b.id):
            b_view = outcome.containment_rate(session, tenant_b.id)
    finally:
        session.close()

    assert b_view == {"contained": 0, "total": 0, "rate": None}
