"""docs/v2_migration/MIGRATION-01-evidence-first.md, change 23 — "Shared workspace,
single live tenant." Every login lands in the same tenant and sees identical data;
authentication still exists, but it no longer partitions what a user can see.

This is deliberately *not* "remove tenant isolation" — `app.models.base`'s
`TenantScopedMixin`/`tenant_scope`/`do_orm_execute` guard is untouched (see
`tests/test_tenant_isolation.py` for the exhaustive, generic proof of that machinery).
What changed is upstream of it: `app.api.auth.signup` no longer mints a `Tenant` per
account (`tests/test_auth_signup.py` covers that directly). The two things this module
proves are the two halves of "shared workspace" that neither of those files covers on
its own:

1. two different users, same tenant, see the same data — there is no per-user filter
   anywhere in the query layer, only the structural per-tenant one.
2. the structural per-tenant guard still holds even with the live tenant on one side —
   a row belonging to a different tenant is still invisible to it.

Uses the real live tenant (`app.models.tenant.get_or_create_live_tenant`) rather than a
throwaway one so this exercises the actual object every login resolves to, not a stand-in
that merely resembles it. The live tenant is never torn down (it persists across the
whole suite and across `make seed`, like production) — only the rows this module adds
under it are cleaned up, by id, never by tenant_id.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.core.db import get_engine, get_session_factory
from app.models.base import tenant_session
from app.models.tenant import Tenant, get_or_create_live_tenant
from app.models.user import User
from tests.conftest import TEST_ORIGIN, authenticate, make_analysis, make_tenant, make_user


@pytest.fixture
def live_tenant() -> Tenant:
    session = get_session_factory()()
    try:
        tenant = get_or_create_live_tenant(session)
        session.commit()
        session.refresh(tenant)
        return tenant
    finally:
        session.close()


@pytest.fixture
def shared_workspace_cleanup() -> Iterator[dict[str, list[uuid.UUID]]]:
    """Deletes only the rows this module's tests create, by their own id — never by
    `tenant_id`, since the live tenant is shared and persistent (see module docstring).
    Order matters: `analyses` before `uploads` before `users`, matching the FK chain."""
    created: dict[str, list[uuid.UUID]] = {"analyses": [], "uploads": [], "users": []}
    yield created
    if not any(created.values()):
        return
    with get_engine().begin() as conn:
        if created["analyses"]:
            conn.execute(
                text("DELETE FROM analyses WHERE id = ANY(:ids)"), {"ids": created["analyses"]}
            )
        if created["uploads"]:
            conn.execute(
                text("DELETE FROM uploads WHERE id = ANY(:ids)"), {"ids": created["uploads"]}
            )
        if created["users"]:
            conn.execute(text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": created["users"]})


def test_two_different_users_in_the_live_tenant_see_the_same_analysis(
    live_tenant: Tenant, shared_workspace_cleanup: dict[str, list[uuid.UUID]]
) -> None:
    """user_1 creates the analysis; user_2 — a different identity who never touched it —
    can still fetch it, purely because they share a tenant. No per-user filter is
    involved anywhere in `GET /api/analyses/{id}`."""
    from app.main import app

    user_1 = make_user(tenant_id=live_tenant.id, email=f"analyst-1-{uuid.uuid4()}@example.com")
    user_2 = make_user(tenant_id=live_tenant.id, email=f"analyst-2-{uuid.uuid4()}@example.com")
    shared_workspace_cleanup["users"].extend([user_1.id, user_2.id])

    analysis = make_analysis(
        tenant_id=live_tenant.id,
        user_id=user_1.id,
        filename=f"shared-workspace-{uuid.uuid4()}.log",
    )
    shared_workspace_cleanup["analyses"].append(analysis.id)
    shared_workspace_cleanup["uploads"].append(analysis.upload_id)

    client_1 = TestClient(app, headers={"origin": TEST_ORIGIN})
    authenticate(client_1, user_1)
    client_2 = TestClient(app, headers={"origin": TEST_ORIGIN})
    authenticate(client_2, user_2)

    response_1 = client_1.get(f"/api/analyses/{analysis.id}")
    response_2 = client_2.get(f"/api/analyses/{analysis.id}")

    assert response_1.status_code == 200
    assert response_2.status_code == 200
    assert response_1.json()["id"] == str(analysis.id)
    # Identical payload for both -- user_2 sees exactly what user_1 (the creator) sees,
    # not a filtered or empty view.
    assert response_1.json() == response_2.json()


def test_two_different_users_in_the_live_tenant_see_the_same_analysis_in_the_list(
    live_tenant: Tenant, shared_workspace_cleanup: dict[str, list[uuid.UUID]]
) -> None:
    """Same guarantee, through the list endpoint (`GET /api/analyses`) rather than the
    single-resource one -- proves there is no per-user filter baked into the listing
    query either (e.g. `WHERE uploads.user_id = :current_user_id`)."""
    from app.main import app

    user_1 = make_user(tenant_id=live_tenant.id, email=f"lister-1-{uuid.uuid4()}@example.com")
    user_2 = make_user(tenant_id=live_tenant.id, email=f"lister-2-{uuid.uuid4()}@example.com")
    shared_workspace_cleanup["users"].extend([user_1.id, user_2.id])

    analysis = make_analysis(
        tenant_id=live_tenant.id,
        user_id=user_1.id,
        filename=f"shared-workspace-list-{uuid.uuid4()}.log",
    )
    shared_workspace_cleanup["analyses"].append(analysis.id)
    shared_workspace_cleanup["uploads"].append(analysis.upload_id)

    client_2 = TestClient(app, headers={"origin": TEST_ORIGIN})
    authenticate(client_2, user_2)

    response = client_2.get("/api/analyses", params={"limit": 100})
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()["items"]}
    assert str(analysis.id) in ids


def test_tenant_scope_still_filters_with_the_live_tenant_on_one_side(
    live_tenant: Tenant, tenant_cleanup: list[uuid.UUID]
) -> None:
    """Change 23 keeps `tenant_id` and the `do_orm_execute` guard exactly as they are —
    there is simply one live tenant flowing through them in practice. A row belonging
    to a genuinely different tenant ("contoso") must still be invisible to a session
    scoped to the live tenant ("northwind") — the isolation machinery must still work
    even though only one tenant is ever logged into."""
    contoso = make_tenant(name="contoso")
    tenant_cleanup.append(contoso.id)
    contoso_user = make_user(tenant_id=contoso.id, email=f"contoso-{uuid.uuid4()}@example.com")

    session = tenant_session(live_tenant.id)
    try:
        found = session.execute(select(User).where(User.id == contoso_user.id)).scalar_one_or_none()
        # Deliberately unfiltered too -- proves the live tenant's session never sees
        # contoso's user by listing, not only by guessing its id.
        all_ids = {row.id for row in session.execute(select(User)).scalars().all()}
    finally:
        session.close()

    assert found is None
    assert contoso_user.id not in all_ids

    # And the reverse holds too: contoso's own session cannot see the live tenant's rows.
    session = tenant_session(contoso.id)
    try:
        cross = (
            session.execute(select(User).where(User.tenant_id == live_tenant.id)).scalars().all()
        )
    finally:
        session.close()
    assert cross == []
