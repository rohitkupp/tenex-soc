"""GET /api/analyses/{id}/events, GET /api/events/{event_id} — docs/09-API-CONTRACT.md.

Runs against the live Postgres from docker-compose.yml through the real HTTP API
(`TestClient`). Events are seeded directly via
`app.storage.event_writer.bulk_copy_events` — there is no ingestion endpoint yet (that
lands with the pipeline at M4), so a bulk COPY is the only way `events` rows exist at
this milestone.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.event import Event
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from tests.conftest import TEST_ORIGIN, authenticate, make_tenant, make_user


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _make_analysis(
    tenant_id: uuid.UUID, user_id: uuid.UUID, *, filename: str = "events.log"
) -> Analysis:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            upload = Upload(
                tenant_id=tenant_id,
                user_id=user_id,
                filename=filename,
                size_bytes=1,
                sha256="a" * 64,
                storage_ref=f"{tenant_id}/{uuid.uuid4()}",
            )
            session.add(upload)
            session.flush()
            analysis = Analysis(tenant_id=tenant_id, upload_id=upload.id)
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
        return analysis
    finally:
        session.close()


def _seed_events(
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    n: int,
    *,
    start: datetime | None = None,
    principal: Callable[[int], str] | None = None,
    domain: str = "example.com",
    src_ip: str = "10.0.0.1",
    action: str = "allowed",
) -> None:
    start = start or datetime(2026, 1, 1, tzinfo=UTC)

    def rows() -> Iterator[SimpleEventRecord]:
        for i in range(n):
            yield SimpleEventRecord(
                ts=start + timedelta(seconds=i),
                source_type="zscaler",
                raw_line_no=i,
                ocsf_class_uid=4002,
                ocsf={"idx": i},
                principal=(principal(i) if principal else f"u_{i % 3}"),
                src_ip=src_ip,
                domain=domain,
                action=action,
                event_key=f"GET:general:{action}:2xx",
            )

    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=rows())
    finally:
        conn.close()


@pytest.fixture
def authed(client: TestClient, tenant_cleanup: list[uuid.UUID]) -> tuple[Tenant, User]:
    tenant = make_tenant(name="Events API Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="events-api@example.com")
    authenticate(client, user)
    return tenant, user


# ------------------------------------------------------------ auth + tenant scoping


def test_list_events_requires_authentication(client: TestClient) -> None:
    response = client.get(f"/api/analyses/{uuid.uuid4()}/events")
    assert response.status_code == 401


def test_get_event_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/events/1")
    assert response.status_code == 401


def test_list_events_404_for_unknown_analysis(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    response = client.get(f"/api/analyses/{uuid.uuid4()}/events")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_list_events_404_for_another_tenants_analysis(
    client: TestClient, authed: tuple[Tenant, User], tenant_cleanup: list[uuid.UUID]
) -> None:
    other_tenant = make_tenant(name="Not Yours Events")
    tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email="notyours-events@example.com")
    other_analysis = _make_analysis(other_tenant.id, other_user.id)
    _seed_events(other_analysis.id, other_tenant.id, 3)

    response = client.get(f"/api/analyses/{other_analysis.id}/events")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_events_are_tenant_scoped_end_to_end(
    client: TestClient, authed: tuple[Tenant, User], tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(analysis.id, tenant.id, 4)

    other_tenant = make_tenant(name="Other Tenant Events")
    tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email="other-tenant-events@example.com")
    other_client = TestClient(client.app, headers={"origin": TEST_ORIGIN})
    authenticate(other_client, other_user)

    # Tenant A sees its own 4 events.
    own = client.get(f"/api/analyses/{analysis.id}/events")
    assert own.status_code == 200
    assert len(own.json()["items"]) == 4

    # Tenant B cannot see tenant A's analysis or its events at all.
    foreign = other_client.get(f"/api/analyses/{analysis.id}/events")
    assert foreign.status_code == 404

    event_id = own.json()["items"][0]["id"]
    foreign_event = other_client.get(f"/api/events/{event_id}")
    assert foreign_event.status_code == 404


# ------------------------------------------------------------ list shape + filters


def test_list_events_basic_shape_stays_flat(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(analysis.id, tenant.id, 5)

    response = client.get(f"/api/analyses/{analysis.id}/events")
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 5
    assert body["next_cursor"] is None
    first = body["items"][0]
    assert first["analysis_id"] == str(analysis.id)
    assert first["src_ip"] == "10.0.0.1"
    assert first["domain"] == "example.com"
    # docs/09: list items stay flat — full ocsf/enrichment is a separate call.
    assert "ocsf" not in first
    assert "enrichment" not in first


def test_list_events_filters_by_principal(client: TestClient, authed: tuple[Tenant, User]) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(analysis.id, tenant.id, 9, principal=lambda i: f"u_{i % 3}")

    response = client.get(f"/api/analyses/{analysis.id}/events", params={"principal": "u_1"})
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 3
    assert all(item["principal"] == "u_1" for item in items)


def test_list_events_filters_by_domain_src_ip_and_action(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(
        analysis.id,
        tenant.id,
        4,
        domain="a.example.com",
        src_ip="10.0.0.5",
        action="allowed",
        start=datetime(2026, 4, 1, tzinfo=UTC),
    )
    _seed_events(
        analysis.id,
        tenant.id,
        2,
        domain="b.example.com",
        src_ip="10.0.0.9",
        action="blocked",
        start=datetime(2026, 4, 2, tzinfo=UTC),
    )

    by_domain = client.get(
        f"/api/analyses/{analysis.id}/events", params={"domain": "b.example.com"}
    )
    assert len(by_domain.json()["items"]) == 2

    by_ip = client.get(f"/api/analyses/{analysis.id}/events", params={"src_ip": "10.0.0.5"})
    assert len(by_ip.json()["items"]) == 4

    by_action = client.get(f"/api/analyses/{analysis.id}/events", params={"action": "blocked"})
    assert len(by_action.json()["items"]) == 2


def test_list_events_filters_by_ts_range(client: TestClient, authed: tuple[Tenant, User]) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    start = datetime(2026, 6, 1, tzinfo=UTC)
    _seed_events(analysis.id, tenant.id, 10, start=start)

    response = client.get(
        f"/api/analyses/{analysis.id}/events",
        params={
            "ts_from": (start + timedelta(seconds=3)).isoformat(),
            "ts_to": (start + timedelta(seconds=6)).isoformat(),
        },
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 4  # seconds 3, 4, 5, 6


def test_list_events_has_signal_stub_behaviour(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    """docs/02's `signals` table doesn't exist until M6/M7 — see app/api/events.py's
    module docstring for the documented stub behaviour this asserts."""
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(analysis.id, tenant.id, 4)

    flagged_only = client.get(f"/api/analyses/{analysis.id}/events", params={"has_signal": "true"})
    assert flagged_only.status_code == 200
    assert flagged_only.json()["items"] == []

    unflagged = client.get(f"/api/analyses/{analysis.id}/events", params={"has_signal": "false"})
    assert len(unflagged.json()["items"]) == 4


def test_list_events_rejects_invalid_src_ip_filter(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)

    response = client.get(f"/api/analyses/{analysis.id}/events", params={"src_ip": "not-an-ip"})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_filter"


def test_list_events_rejects_invalid_cursor(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)

    response = client.get(
        f"/api/analyses/{analysis.id}/events", params={"cursor": "!!!not-valid-base64!!!"}
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_cursor"


def test_list_events_rejects_limit_out_of_bounds(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)

    assert client.get(f"/api/analyses/{analysis.id}/events", params={"limit": 0}).status_code == 422
    assert (
        client.get(f"/api/analyses/{analysis.id}/events", params={"limit": 5000}).status_code == 422
    )


# ------------------------------------------------------------ keyset pagination


def test_list_events_keyset_pagination_has_no_duplicates_or_skips(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    """Proves the pagination stability the M3 verification bar asks for: paging
    through the full set with a small page size visits every row exactly once, in
    strict `(ts, id)` order — no duplicates, no skips."""
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    total = 733
    _seed_events(analysis.id, tenant.id, total, start=datetime(2026, 3, 1, tzinfo=UTC))

    seen_ids: list[int] = []
    cursor: str | None = None
    page_size = 50
    for _ in range(total // page_size + 5):
        params: dict[str, str | int] = {"limit": page_size}
        if cursor is not None:
            params["cursor"] = cursor
        response = client.get(f"/api/analyses/{analysis.id}/events", params=params)
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) <= page_size
        seen_ids.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert cursor is None, "pagination did not terminate within the expected page count"
    assert len(seen_ids) == total
    assert len(set(seen_ids)) == total, "keyset pagination produced duplicate rows"
    assert seen_ids == sorted(seen_ids), "keyset pagination produced out-of-order/skipped rows"


# ------------------------------------------------------------ single-event detail


def test_get_event_returns_full_ocsf_and_enrichment(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = _make_analysis(tenant.id, user.id)
    _seed_events(analysis.id, tenant.id, 1)

    listed = client.get(f"/api/analyses/{analysis.id}/events").json()["items"][0]
    event_id = listed["id"]

    response = client.get(f"/api/events/{event_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == event_id
    assert body["ocsf"] == {"idx": 0}
    assert body["enrichment"] == {}


def test_get_event_404_for_unknown_id(client: TestClient, authed: tuple[Tenant, User]) -> None:
    response = client.get("/api/events/999999999")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_get_event_404_for_another_tenants_event(
    client: TestClient, authed: tuple[Tenant, User], tenant_cleanup: list[uuid.UUID]
) -> None:
    other_tenant = make_tenant(name="Other Get Event Tenant")
    tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email="other-get-event@example.com")
    other_analysis = _make_analysis(other_tenant.id, other_user.id)
    _seed_events(other_analysis.id, other_tenant.id, 1)

    session = get_session_factory()()
    try:
        with tenant_scope(session, other_tenant.id):
            other_event = session.execute(
                select(Event).where(Event.analysis_id == other_analysis.id)
            ).scalar_one()
    finally:
        session.close()

    response = client.get(f"/api/events/{other_event.id}")
    assert response.status_code == 404
