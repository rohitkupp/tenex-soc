"""`app.response.preconditions` — every check reads REAL rows in `enforcement_state` (docs/08:
"so a failing precondition genuinely blocks the plan"), exercised here against the live Postgres
directly, independent of the executor that uses them as its real gate."""

from __future__ import annotations

import uuid

import pytest

from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.response import preconditions, state
from tests.conftest import make_tenant
from tests.fixtures.response import response_tenant_cleanup  # noqa: F401


@pytest.fixture
def tenant_id(response_tenant_cleanup: list[uuid.UUID]) -> uuid.UUID:  # noqa: F811
    tenant = make_tenant(name="Enforcement Preconditions Test Tenant")
    response_tenant_cleanup.append(tenant.id)
    return tenant.id


def test_user_exists_false_before_seeding(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = preconditions.evaluate("user_exists", session, tenant_id, "ghost")
    finally:
        session.close()
    assert result.satisfied is False


def test_user_exists_and_has_active_sessions_after_seeding(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "revoke_okta_sessions", "alice")
            session.commit()
            exists = preconditions.evaluate("user_exists", session, tenant_id, "alice")
            active = preconditions.evaluate("has_active_sessions", session, tenant_id, "alice")
            revoked = preconditions.evaluate("sessions_revoked", session, tenant_id, "alice")
    finally:
        session.close()
    assert exists.satisfied is True
    assert active.satisfied is True
    assert revoked.satisfied is False  # default-seeded sessions are all active


def test_sessions_revoked_true_after_manually_revoking(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
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
            revoked = preconditions.evaluate("sessions_revoked", session, tenant_id, "alice")
            active = preconditions.evaluate("has_active_sessions", session, tenant_id, "alice")
    finally:
        session.close()
    assert revoked.satisfied is True
    assert active.satisfied is False


def test_has_active_mfa_factor(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "deactivate_compromised_mfa_factor", "bob")
            session.commit()
            before = preconditions.evaluate("has_active_mfa_factor", session, tenant_id, "bob")

            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_OKTA_FACTOR,
                "bob",
                {"factors": [{"id": "f1", "active": False}]},
            )
            session.commit()
            after = preconditions.evaluate("has_active_mfa_factor", session, tenant_id, "bob")
    finally:
        session.close()
    assert before.satisfied is True
    assert after.satisfied is False


def test_api_key_exists_and_enabled(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            missing = preconditions.evaluate("api_key_exists", session, tenant_id, "key-1")

            state.seed_for_step(session, tenant_id, "disable_api_key", "key-1")
            session.commit()
            exists = preconditions.evaluate("api_key_exists", session, tenant_id, "key-1")
            enabled = preconditions.evaluate("api_key_enabled", session, tenant_id, "key-1")

            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_API_KEY,
                "key-1",
                {"enabled": False, "key_id": "key-1"},
            )
            session.commit()
            disabled = preconditions.evaluate("api_key_enabled", session, tenant_id, "key-1")
    finally:
        session.close()
    assert missing.satisfied is False
    assert exists.satisfied is True
    assert enabled.satisfied is True
    assert disabled.satisfied is False


def test_domain_not_allowlisted_default_true_and_false_when_allowlisted(
    tenant_id: uuid.UUID,
) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            never_seeded = preconditions.evaluate(
                "domain_not_allowlisted", session, tenant_id, "unseen.example.com"
            )

            state.seed_for_step(session, tenant_id, "block_domain_at_proxy", "corp-cdn.example.com")
            session.commit()
            not_allowlisted = preconditions.evaluate(
                "domain_not_allowlisted", session, tenant_id, "corp-cdn.example.com"
            )

            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "corp-cdn.example.com",
                {"kind": "domain", "blocked": False, "allowlisted": True},
            )
            session.commit()
            allowlisted = preconditions.evaluate(
                "domain_not_allowlisted", session, tenant_id, "corp-cdn.example.com"
            )
    finally:
        session.close()
    assert never_seeded.satisfied is True
    assert not_allowlisted.satisfied is True
    assert allowlisted.satisfied is False


def test_dst_ip_not_allowlisted(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "10.0.0.1",
                {"kind": "dst_ip", "blocked": False, "allowlisted": True},
            )
            session.commit()
            result = preconditions.evaluate(
                "dst_ip_not_allowlisted", session, tenant_id, "10.0.0.1"
            )
    finally:
        session.close()
    assert result.satisfied is False


def test_host_exists_and_not_isolated(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            missing = preconditions.evaluate("host_exists", session, tenant_id, "host-1")

            state.seed_for_step(session, tenant_id, "isolate_host", "host-1")
            session.commit()
            exists = preconditions.evaluate("host_exists", session, tenant_id, "host-1")
            not_isolated = preconditions.evaluate("host_not_isolated", session, tenant_id, "host-1")

            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_HOST,
                "host-1",
                {"isolated": True, "hostname": "host-1", "files": {}},
            )
            session.commit()
            isolated = preconditions.evaluate("host_not_isolated", session, tenant_id, "host-1")
    finally:
        session.close()
    assert missing.satisfied is False
    assert exists.satisfied is True
    assert not_isolated.satisfied is True
    assert isolated.satisfied is False


def test_file_present(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "quarantine_file", "host-1:deadbeef")
            session.commit()
            present = preconditions.evaluate("file_present", session, tenant_id, "host-1:deadbeef")

            missing = preconditions.evaluate("file_present", session, tenant_id, "host-1:not-there")

            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_HOST,
                "host-1",
                {
                    "isolated": False,
                    "hostname": "host-1",
                    "files": {"deadbeef": {"present": True, "quarantined": True}},
                },
            )
            session.commit()
            already_quarantined = preconditions.evaluate(
                "file_present", session, tenant_id, "host-1:deadbeef"
            )
    finally:
        session.close()
    assert present.satisfied is True
    assert missing.satisfied is False
    assert already_quarantined.satisfied is False


def test_unknown_precondition_raises(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with (
            tenant_scope(session, tenant_id),
            pytest.raises(preconditions.UnknownPreconditionError),
        ):
            preconditions.evaluate("not_a_real_precondition", session, tenant_id, "alice")
    finally:
        session.close()


def test_check_preconditions_aggregates_all_and_reports_each(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "revoke_okta_sessions", "alice")
            session.commit()
            ok, checks = preconditions.check_preconditions(
                session,
                tenant_id,
                "revoke_okta_sessions",
                "alice",
                precondition_ids=("user_exists", "has_active_sessions"),
            )
    finally:
        session.close()
    assert ok is True
    assert {c.id for c in checks} == {"user_exists", "has_active_sessions"}


def test_check_preconditions_reports_the_specific_failure(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "revoke_okta_sessions", "alice")
            session.commit()  # sessions still active — sessions_revoked must fail
            ok, checks = preconditions.check_preconditions(
                session,
                tenant_id,
                "force_credential_reset",
                "alice",
                precondition_ids=("user_exists", "sessions_revoked"),
            )
    finally:
        session.close()
    assert ok is False
    failed = [c for c in checks if not c.satisfied]
    assert len(failed) == 1
    assert failed[0].id == "sessions_revoked"
