"""GET /api/analyses/{id}/stream — docs/01's amended "Terminal contract" / docs/09's
SSE relay. Runs against the real Redis, Postgres, and RabbitMQ-adjacent pipeline state
from docker-compose.yml through the actual HTTP API (`TestClient`), not a mock.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any

import redis as sync_redis
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.db import get_engine
from app.pipeline import state
from app.pipeline.progress import channel_name
from tests.conftest import authenticate, make_analysis, make_tenant, make_user


def _publish(analysis_id: uuid.UUID, **payload: object) -> None:
    """Publishes on a plain **synchronous** `redis` client — deliberately not
    `app.pipeline.redis_client.get_redis()` (the async, process-wide `@lru_cache`d
    client the real pipeline/API use). That client is bound to whichever asyncio event
    loop last touched it; `TestClient`'s SSE handler runs on its own persistent
    portal loop for the lifetime of the `client` fixture, and a second, unrelated
    `asyncio.run()` call from this helper would tear its own loop down immediately
    after, breaking the cached client out from under the handler on the next request.
    A separate sync client sidesteps that entirely — and is arguably more realistic
    here anyway: a real progress publisher is a different process (a worker) than the
    API serving this stream, so a plain, independent connection is the honest model."""
    client = sync_redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        client.publish(channel_name(analysis_id), json.dumps(payload))
    finally:
        client.close()


def _read_sse_frames(
    client: TestClient, url: str, *, max_frames: int, timeout_s: float
) -> list[dict[str, Any]]:
    """Blocking SSE reader for the test's main thread — collects up to `max_frames`
    parsed `data:` payloads or gives up after `timeout_s`, whichever comes first (the
    endpoint is expected to close the connection on its own once terminal, so a clean
    run finishes well before the timeout)."""
    frames: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    with client.stream("GET", url) as response:
        assert response.status_code == 200, response.read()
        for line in response.iter_lines():
            if time.monotonic() > deadline:
                break
            if not line.startswith("data:"):
                continue
            frames.append(json.loads(line[len("data:") :].strip()))
            if len(frames) >= max_frames:
                break
    return frames


def test_stream_requires_auth(client: TestClient) -> None:
    response = client.get(f"/api/analyses/{uuid.uuid4()}/stream")
    assert response.status_code == 401


def test_stream_404_for_unknown_analysis(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Stream 404 Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"stream-404-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.get(f"/api/analyses/{uuid.uuid4()}/stream")
    assert response.status_code == 404


def test_stream_snapshot_matches_docs_wire_shape_and_closes_for_a_terminal_analysis(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Stream Snapshot Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"stream-snap-{uuid.uuid4()}@test.local")
    authenticate(client, user)
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    with get_engine().begin() as conn:
        state.start_ingest(
            conn, analysis_id=analysis.id, tenant_id=tenant.id, pending_parsers=1, progress=0.5
        )
        state.mark_complete(conn, analysis_id=analysis.id, tenant_id=tenant.id)

    frames = _read_sse_frames(
        client, f"/api/analyses/{analysis.id}/stream", max_frames=3, timeout_s=5.0
    )

    # Exactly the docs/01 (amended) wire shape — no more, no fewer keys — and the
    # stream must close after the one terminal snapshot, not hang waiting for a Redis
    # message that will never come.
    assert len(frames) == 1, frames
    frame = frames[0]
    assert set(frame.keys()) == {"stage", "progress", "status", "message", "counters"}
    assert frame["status"] == "complete"
    assert frame["progress"] == 1.0
    assert set(frame["counters"].keys()) == {"events", "signals", "incidents", "needs_attention"}


def test_stream_relays_live_progress_and_terminates_on_complete(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Stream Live Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"stream-live-{uuid.uuid4()}@test.local")
    authenticate(client, user)
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    with get_engine().begin() as conn:
        state.start_ingest(
            conn, analysis_id=analysis.id, tenant_id=tenant.id, pending_parsers=1, progress=0.1
        )

    collected: list[dict[str, Any]] = []

    def _reader() -> None:
        collected.extend(
            _read_sse_frames(
                client, f"/api/analyses/{analysis.id}/stream", max_frames=3, timeout_s=10.0
            )
        )

    reader_thread = threading.Thread(target=_reader)
    reader_thread.start()
    time.sleep(0.3)  # let the stream connect and emit its initial snapshot

    _publish(
        analysis.id,
        stage="detect",
        progress=0.6,
        status="running",
        message="Running sequence models",
        counters={"events": 1000, "signals": 5, "incidents": 0, "needs_attention": 0},
    )
    time.sleep(0.2)

    with get_engine().begin() as conn:
        state.mark_complete(conn, analysis_id=analysis.id, tenant_id=tenant.id)
    _publish(
        analysis.id,
        stage="tier2",
        progress=1.0,
        status="complete",
        message="Done",
        counters={"events": 1000, "signals": 5, "incidents": 1, "needs_attention": 1},
    )

    reader_thread.join(timeout=15)
    assert not reader_thread.is_alive(), "stream did not close after the terminal event"

    stages = [f["stage"] for f in collected]
    statuses = [f["status"] for f in collected]
    assert "ingest" in stages  # the initial connect-time snapshot
    assert "detect" in stages  # the live-relayed progress event
    assert statuses[-1] == "complete"
    assert collected[-1]["counters"]["incidents"] == 1
