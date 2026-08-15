"""GET /api/ops/queues — docs/09's Ops section, "Depth per queue."

Runs against the real RabbitMQ from docker-compose.yml through the actual HTTP API
(`TestClient`), not a mock of the broker.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.queue.topology import QUEUE_NAMES, dead_letter_queue, delay_queue, work_queue
from tests.conftest import authenticate, make_tenant, make_user


def test_queue_depths_lists_every_declared_queue(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Ops Queues Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"ops-queues-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.get("/api/ops/queues")
    assert response.status_code == 200, response.text

    body = response.json()
    by_name = {item["queue"]: item for item in body["items"]}

    expected_names = {
        name
        for stage in QUEUE_NAMES
        for name in (work_queue(stage), delay_queue(stage), dead_letter_queue(stage))
    }
    assert expected_names <= set(by_name), expected_names - set(by_name)

    for name, item in by_name.items():
        assert isinstance(item["messages"], int) and item["messages"] >= 0, name
        assert isinstance(item["consumers"], int) and item["consumers"] >= 0, name


def test_queue_depths_requires_auth(client: TestClient) -> None:
    response = client.get("/api/ops/queues")
    assert response.status_code == 401


def test_queue_depths_include_docs_01_named_work_queues(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Ops Queues Names Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"ops-queues-names-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.get("/api/ops/queues")
    names = {item["queue"] for item in response.json()["items"]}
    for stage in ("orchestrator", "parse.zscaler", "enrich", "detect", "tier2"):
        assert work_queue(stage) in names
