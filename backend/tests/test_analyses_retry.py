"""`POST /api/analyses/{id}/retry` — docs/v2_migration change 27's replacement for the
deleted `POST /api/ops/dead-letters/{id}/retry`, plus the "failures surface on the
analysis" contract that change puts in its place: a failed analysis exposes
`status`/`stage`/`error` on `GET /api/analyses/{id}`, and the three deleted `/api/ops/*`
routes (`GET /api/ops/queues`, `GET /api/ops/dead-letters`,
`POST /api/ops/dead-letters/{id}/retry`) no longer resolve at all.

Runs against the real Postgres and RabbitMQ from docker-compose.yml through the actual
HTTP API (`TestClient`), same as the dead-letter-retry test this file replaces
(formerly `tests/test_ops_dead_letters.py`, deleted along with `app.api.ops`).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.db import get_engine, get_session_factory
from app.models.dead_letter import DeadLetter
from app.pipeline import state
from app.pipeline.messages import StageMessage
from app.queue.topology import declare_topology, get_connection, work_queue
from tests.conftest import authenticate, make_analysis, make_tenant, make_user


# Autouse for this module: every test here publishes to a real stage queue and consumes it back
# with its own worker, so a running `docker compose` stack silently steals half the messages.
# See the fixture's docstring in conftest.
@pytest.fixture(autouse=True)
def _require_exclusive_queues(no_competing_queue_consumers: None) -> None:
    """Bind the session-scoped check to every test in this module."""


@pytest.fixture
def dead_letter_row(tenant_cleanup: list[uuid.UUID]) -> Iterator[tuple[DeadLetter, uuid.UUID]]:
    tenant = make_tenant(name="Analyses Retry Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"analyses-retry-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    payload = StageMessage(
        analysis_id=analysis.id,
        tenant_id=tenant.id,
        stage="enrich",
        attempt=3,
        emitted_at=datetime.now(UTC),
    ).model_dump(mode="json")

    session = get_session_factory()()
    try:
        row = DeadLetter(
            analysis_id=analysis.id,
            stage="enrich",
            payload=payload,
            error="synthetic analyses-retry test failure",
            attempts=4,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        yield row, tenant.id
    finally:
        session.execute(text("DELETE FROM dead_letters WHERE id = :id"), {"id": row.id})
        session.commit()
        session.close()


def test_retry_republishes_from_the_failed_stage_and_reopens_the_analysis(
    client: TestClient, dead_letter_row: tuple[DeadLetter, uuid.UUID]
) -> None:
    row, tenant_id = dead_letter_row
    assert row.analysis_id is not None  # always set by the `dead_letter_row` fixture
    user = make_user(tenant_id=tenant_id, email=f"analyses-retry-post-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    # Mark the analysis failed first, matching what app.pipeline.base_worker does
    # before a dead letter is ever visible — retry should reopen it.
    with get_engine().begin() as conn:
        state.mark_stage(
            conn, analysis_id=row.analysis_id, tenant_id=tenant_id, stage="enrich", progress=0.4
        )
        state.mark_failed(conn, analysis_id=row.analysis_id, tenant_id=tenant_id, error="boom")

    response = client.post(f"/api/analyses/{row.analysis_id}/retry")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["analysis_id"] == str(row.analysis_id)
    assert body["republished_to"] == work_queue("enrich")
    assert body["retried_at"] is not None

    with get_engine().begin() as conn:
        final = state.fetch_analysis(conn, analysis_id=row.analysis_id, tenant_id=tenant_id)
    assert final["status"] == "running"
    assert final["error"] is None

    # And the republished message actually landed on q.enrich with a fresh attempt
    # budget (attempt=0), not the exhausted attempt=3 it failed at.
    async def _get_one() -> StageMessage | None:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await declare_topology(channel)
            queue = await channel.get_queue(work_queue("enrich"))
            incoming = await queue.get(timeout=5, fail=False)
            if incoming is None:
                return None
            async with incoming.process():
                return StageMessage.model_validate_json(incoming.body)
        finally:
            await connection.close()

    republished = asyncio.run(_get_one())
    assert republished is not None
    assert republished.analysis_id == row.analysis_id
    assert republished.attempt == 0

    # The dead letter this retry used is marked so a second retry attempt (with no new
    # failure) does not reuse the same stale payload. `row` is detached from the
    # fixture's own (closed) session, so re-query rather than `session.refresh(row)`.
    with get_engine().begin() as conn:
        retried_at = conn.execute(
            text("SELECT retried_at FROM dead_letters WHERE id = :id"), {"id": row.id}
        ).scalar_one()
    assert retried_at is not None


def test_retry_404s_for_unknown_analysis(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Analyses Retry 404 Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"analyses-retry-404-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.post(f"/api/analyses/{uuid.uuid4()}/retry")
    assert response.status_code == 404


def test_retry_409s_when_analysis_is_not_failed(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Analyses Retry Not Failed Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"analyses-retry-409-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    authenticate(client, user)

    # `make_analysis` creates a `status='queued'` row — never failed, nothing to retry.
    response = client.post(f"/api/analyses/{analysis.id}/retry")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "not_retryable"


def test_retry_requires_auth(client: TestClient) -> None:
    response = client.post(f"/api/analyses/{uuid.uuid4()}/retry")
    assert response.status_code == 401


def test_failed_analysis_exposes_stage_and_error(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    """docs/v2_migration change 27: "A stage that exhausts retries sets
    `analyses.status = 'failed'`, `analyses.stage` to the failing stage, and
    `analyses.error` to a human-readable message" — and `/analyses/[id]` (the frontend)
    reads all three straight off `GET /api/analyses/{id}` to render the failure at the
    point in the funnel where it occurred, not a generic error."""
    tenant = make_tenant(name="Failed Analysis Exposure Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"failed-analysis-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    authenticate(client, user)

    with get_engine().begin() as conn:
        state.mark_stage(
            conn, analysis_id=analysis.id, tenant_id=tenant.id, stage="detect", progress=0.6
        )
        state.mark_failed(
            conn,
            analysis_id=analysis.id,
            tenant_id=tenant.id,
            error="detect stage failed permanently after 4 attempt(s)",
        )

    response = client.get(f"/api/analyses/{analysis.id}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "failed"
    assert body["stage"] == "detect"
    assert body["error"] == "detect stage failed permanently after 4 attempt(s)"


def test_failed_analysis_shows_up_in_the_list(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Failed Analysis List Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"failed-analysis-list-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    authenticate(client, user)

    with get_engine().begin() as conn:
        state.mark_failed(conn, analysis_id=analysis.id, tenant_id=tenant.id, error="boom")

    response = client.get("/api/analyses")
    assert response.status_code == 200, response.text
    match = next(i for i in response.json()["items"] if i["id"] == str(analysis.id))
    assert match["status"] == "failed"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/ops/queues"),
        ("GET", "/api/ops/dead-letters"),
        ("POST", "/api/ops/dead-letters/1/retry"),
    ],
)
def test_deleted_ops_routes_404(client: TestClient, method: str, path: str) -> None:
    """docs/v2_migration change 27: "Delete `/api/ops/queues`, `/api/ops/dead-letters`,
    `/api/ops/dead-letters/{id}/retry`." These must not resolve at all — not even to a
    401 (which would mean the route still exists behind auth) — since `app.api.ops` is
    gone from `app.main`'s router registration entirely."""
    response = client.request(method, path)
    assert response.status_code == 404


def test_health_still_works_after_ops_removal(client: TestClient) -> None:
    """docs/v2_migration change 27: "Keep `/api/health` — Cloud Run needs it." It lives
    in `app.api.health`, a separate router `app.api.ops` never owned, so deleting
    `app.api.ops` must not take it down."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] in {"ok", "degraded"}
