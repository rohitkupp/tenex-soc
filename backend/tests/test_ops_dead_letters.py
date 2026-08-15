"""GET /api/ops/dead-letters, POST /api/ops/dead-letters/{id}/retry — docs/09's Ops
section. Runs against the real Postgres and RabbitMQ from docker-compose.yml through
the actual HTTP API (`TestClient`).
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


@pytest.fixture
def dead_letter_row(tenant_cleanup: list[uuid.UUID]) -> Iterator[tuple[DeadLetter, uuid.UUID]]:
    tenant = make_tenant(name="Ops Dead Letters Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"ops-dl-{uuid.uuid4()}@test.local")
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
            error="synthetic ops test failure",
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


def test_list_dead_letters_returns_the_row(
    client: TestClient, dead_letter_row: tuple[DeadLetter, uuid.UUID]
) -> None:
    row, tenant_id = dead_letter_row
    user = make_user(tenant_id=tenant_id, email=f"ops-dl-list-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.get("/api/ops/dead-letters", params={"limit": 100})
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    match = next((i for i in items if i["id"] == row.id), None)
    assert match is not None, f"dead letter {row.id} not in {[i['id'] for i in items]}"
    assert match["stage"] == "enrich"
    assert match["attempts"] == 4
    assert match["error"] == "synthetic ops test failure"
    assert match["analysis_id"] == str(row.analysis_id)
    assert match["retried_at"] is None


def test_list_dead_letters_requires_auth(client: TestClient) -> None:
    response = client.get("/api/ops/dead-letters")
    assert response.status_code == 401


def test_retry_dead_letter_republishes_and_reopens_the_analysis(
    client: TestClient, dead_letter_row: tuple[DeadLetter, uuid.UUID]
) -> None:
    row, tenant_id = dead_letter_row
    assert row.analysis_id is not None  # always set by the `dead_letter_row` fixture
    user = make_user(tenant_id=tenant_id, email=f"ops-dl-retry-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    # Mark the analysis failed first, matching what app.pipeline.base_worker does
    # before a dead letter is ever visible — retry should reopen it.
    with get_engine().begin() as conn:
        state.mark_failed(conn, analysis_id=row.analysis_id, tenant_id=tenant_id, error="boom")

    response = client.post(f"/api/ops/dead-letters/{row.id}/retry")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == row.id
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


def test_retry_dead_letter_404_for_unknown_id(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Ops Dead Letters 404 Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"ops-dl-404-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.post("/api/ops/dead-letters/999999999/retry")
    assert response.status_code == 404
