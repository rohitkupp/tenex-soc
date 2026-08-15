"""`app.response.state` — the `enforcement_state` read/write/seed primitives and the
action -> resource binding. Runs against the real Postgres from docker-compose.yml, same as
the rest of this backend's tests (no mocking the plane itself — CLAUDE.md's "do not mock what
should be real")."""

from __future__ import annotations

import uuid

import pytest

from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.response import state
from tests.conftest import make_tenant
from tests.fixtures.response import response_tenant_cleanup  # noqa: F401


@pytest.fixture
def tenant_id(response_tenant_cleanup: list[uuid.UUID]) -> uuid.UUID:  # noqa: F811
    tenant = make_tenant(name="Enforcement State Test Tenant")
    response_tenant_cleanup.append(tenant.id)
    return tenant.id


def test_read_missing_resource_returns_none(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            assert state.read_state(session, tenant_id, state.RESOURCE_HOST, "no-such-host") is None
    finally:
        session.close()


def test_seed_if_missing_then_is_idempotent(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_if_missing(
                session,
                tenant_id,
                state.RESOURCE_HOST,
                "host-1",
                state.default_host_state(hostname="host-1"),
            )
            session.commit()
            first = state.read_state(session, tenant_id, state.RESOURCE_HOST, "host-1")
            assert first == {"isolated": False, "hostname": "host-1", "files": {}}

            # Seeding again with a different default must not clobber real execution state.
            state.seed_if_missing(
                session,
                tenant_id,
                state.RESOURCE_HOST,
                "host-1",
                {"isolated": True, "hostname": "different", "files": {}},
            )
            session.commit()
            second = state.read_state(session, tenant_id, state.RESOURCE_HOST, "host-1")
            assert second == first
    finally:
        session.close()


def test_write_state_upserts(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session, tenant_id, state.RESOURCE_API_KEY, "key-1", {"enabled": True}
            )
            session.commit()
            assert state.read_state(session, tenant_id, state.RESOURCE_API_KEY, "key-1") == {
                "enabled": True
            }

            state.write_state(
                session, tenant_id, state.RESOURCE_API_KEY, "key-1", {"enabled": False}
            )
            session.commit()
            assert state.read_state(session, tenant_id, state.RESOURCE_API_KEY, "key-1") == {
                "enabled": False
            }
    finally:
        session.close()


def test_two_tenants_never_see_each_others_state(response_tenant_cleanup: list[uuid.UUID]) -> None:  # noqa: F811
    tenant_a = make_tenant(name="Enforcement State Tenant A")
    tenant_b = make_tenant(name="Enforcement State Tenant B")
    response_tenant_cleanup.append(tenant_a.id)
    response_tenant_cleanup.append(tenant_b.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            state.write_state(
                session, tenant_a.id, state.RESOURCE_HOST, "shared-id", {"isolated": True}
            )
            session.commit()
        with tenant_scope(session, tenant_b.id):
            row = state.read_state(session, tenant_b.id, state.RESOURCE_HOST, "shared-id")
            assert row is None  # same resource_id, different tenant — no leak
    finally:
        session.close()


@pytest.mark.parametrize(
    ("action_id", "target", "expected"),
    [
        ("revoke_okta_sessions", "alice", (state.RESOURCE_OKTA_SESSION, "alice")),
        ("force_credential_reset", "alice", (state.RESOURCE_OKTA_SESSION, "alice")),
        ("suspend_user_account", "alice", (state.RESOURCE_OKTA_SESSION, "alice")),
        ("deactivate_compromised_mfa_factor", "alice", (state.RESOURCE_OKTA_FACTOR, "alice")),
        ("disable_api_key", "key-1", (state.RESOURCE_API_KEY, "key-1")),
        (
            "block_domain_at_proxy",
            "evil.example.com",
            (state.RESOURCE_PROXY_POLICY, "evil.example.com"),
        ),
        ("block_dst_ip", "203.0.113.9", (state.RESOURCE_PROXY_POLICY, "203.0.113.9")),
        ("isolate_host", "host-1", (state.RESOURCE_HOST, "host-1")),
        ("quarantine_file", "host-1:deadbeef", (state.RESOURCE_HOST, "host-1")),
    ],
)
def test_resolve_primary_resource(action_id: str, target: str, expected: tuple[str, str]) -> None:
    assert state.resolve_primary_resource(action_id, target) == expected


def test_resolve_primary_resource_rejects_unknown_action() -> None:
    with pytest.raises(state.UnknownActionResourceError):
        state.resolve_primary_resource("not_a_real_action", "alice")


def test_split_host_file_target() -> None:
    assert state.split_host_file_target("host-1:deadbeef") == ("host-1", "deadbeef")


def test_split_host_file_target_requires_a_colon() -> None:
    with pytest.raises(ValueError, match=r"host_id.:.file_ref"):
        state.split_host_file_target("host-1-no-colon")


def test_seed_for_step_user_seeds_session_and_factor(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "revoke_okta_sessions", "alice")
            session.commit()
            sessions_row = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "alice"
            )
            factor_row = state.read_state(session, tenant_id, state.RESOURCE_OKTA_FACTOR, "alice")
        assert sessions_row is not None and sessions_row["sessions"]
        assert factor_row is not None and factor_row["factors"]
    finally:
        session.close()


def test_seed_for_step_domain_seeds_proxy_policy_kind_domain(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "block_domain_at_proxy", "evil.example.com")
            session.commit()
            row = state.read_state(
                session, tenant_id, state.RESOURCE_PROXY_POLICY, "evil.example.com"
            )
        assert row == {"kind": "domain", "blocked": False, "allowlisted": False}
    finally:
        session.close()


def test_seed_for_step_dst_ip_seeds_proxy_policy_kind_dst_ip(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "block_dst_ip", "203.0.113.9")
            session.commit()
            row = state.read_state(session, tenant_id, state.RESOURCE_PROXY_POLICY, "203.0.113.9")
        assert row == {"kind": "dst_ip", "blocked": False, "allowlisted": False}
    finally:
        session.close()


def test_seed_for_step_quarantine_file_seeds_host_with_file_entry(tenant_id: uuid.UUID) -> None:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_for_step(session, tenant_id, "quarantine_file", "host-1:deadbeef")
            session.commit()
            row = state.read_state(session, tenant_id, state.RESOURCE_HOST, "host-1")
        assert row == {
            "isolated": False,
            "hostname": "host-1",
            "files": {"deadbeef": {"present": True, "quarantined": False}},
        }
    finally:
        session.close()
