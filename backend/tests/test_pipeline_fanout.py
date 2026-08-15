"""End-to-end pipeline test — docs/13's M4 acceptance: "An upload flows through every
stage" and this milestone's own brief: "Parallel parser fan-out: an upload with
multiple source types fans out and the pending_parsers gate fires exactly once. Prove
the counter is not racy."

Builds a real mixed-source file — docs/03's "mixed export" case (interleaved zscaler +
okta + cloudtrail lines, all three scoring above the sniff threshold; see
`app.parsers.registry`'s module docstring) — uploads it to the real MinIO from
docker-compose.yml, and runs the actual pipeline end to end: the real orchestrator, all
three real parser workers (`app.pipeline.stages.parse`, the one stage this milestone
makes real), and every skeleton stage through to `tier2` — one asyncio task per docs/01
worker, all against the live broker/DB/Redis, exactly as the deployed system runs them
(co-located in one test process instead of twelve containers, nothing else different).

Because each of the three parsers sees the *entire* mixed blob (not a pre-split,
single-format file — the "mixed export" design in `app.parsers.registry` is precisely
that one raw object can contain more than one format, and every matching parser gets
the whole thing), each parser only recognizes roughly a third of the lines and fails on
the rest. `parse_failure_rate` landing around 0.6-0.7 here is therefore expected and
correct, not a bug — this test asserts it lands in `[0, 1]`, not that it is low.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine
from app.parsers.registry import detect_source_types
from app.pipeline import dead_letter_sink, state
from app.pipeline.base_worker import StageWorker
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.pipeline.stages import orchestrator as orchestrator_stage
from app.pipeline.stages import parse as parse_stage
from app.pipeline.stages.skeleton import make_skeleton_handler
from app.queue.dispatch import kickoff_pipeline
from app.queue.topology import (
    QUEUE_NAMES,
    dead_letter_queue,
    declare_topology,
    delay_queue,
    get_connection,
    work_queue,
)
from app.storage.client import ensure_bucket, get_s3_client
from datagen import corpus
from datagen.rng import SeededRandom
from datagen.types import TimeWindow
from tests.conftest import make_analysis, make_tenant, make_user

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)

_STAGE_HANDLER = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]


def _build_mixed_upload(tmp_path: Path, *, seed: int) -> bytes:
    """A real, multi-source upload — round-robin interleaving of three separately
    generated (real, M2-emitter) benign logs, ZScaler's header line kept exactly once
    at the top (its own `header_lines=1` contract)."""
    org = corpus.build_org(seed, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = SeededRandom(corpus.role_seed(seed, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(1)
    corpus.write_benign_corpus(
        org, root, window, tmp_path, proxy_events=40, okta_events=40, cloudtrail_events=40
    )

    zs_lines = (tmp_path / "benign_zscaler.log").read_text().splitlines()
    ok_lines = (tmp_path / "benign_okta.jsonl").read_text().splitlines()
    ct_lines = (tmp_path / "benign_cloudtrail.jsonl").read_text().splitlines()

    header, zs_data = zs_lines[0], zs_lines[1:]
    mixed = [header]
    for i in range(max(len(zs_data), len(ok_lines), len(ct_lines))):
        if i < len(zs_data):
            mixed.append(zs_data[i])
        if i < len(ok_lines):
            mixed.append(ok_lines[i])
        if i < len(ct_lines):
            mixed.append(ct_lines[i])
    return ("\n".join(mixed) + "\n").encode("utf-8")


@pytest.fixture(autouse=True)
def _fresh_redis_client() -> Iterator[None]:
    get_redis.cache_clear()
    yield
    get_redis.cache_clear()


@pytest.fixture(autouse=True)
async def _clean_all_queues() -> AsyncIterator[None]:
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        for name in QUEUE_NAMES:
            for queue_name in (work_queue(name), delay_queue(name), dead_letter_queue(name)):
                queue = await channel.declare_queue(queue_name, passive=True)
                await queue.purge()
        yield
    finally:
        await connection.close()


def _all_workers(enrich_handler: _STAGE_HANDLER) -> list[StageWorker]:
    handlers: dict[str, _STAGE_HANDLER] = {
        "orchestrator": orchestrator_stage.handle,
        "parse.zscaler": parse_stage.handle,
        "parse.okta": parse_stage.handle,
        "parse.cloudtrail": parse_stage.handle,
        "enrich": enrich_handler,
        "anonymize": make_skeleton_handler("anonymize"),
        "detect": make_skeleton_handler("detect"),
        "correlate": make_skeleton_handler("correlate"),
        "triage": make_skeleton_handler("triage"),
        "respond": make_skeleton_handler("respond"),
        "tier2": make_skeleton_handler("tier2"),
    }
    return [StageWorker(name, handler) for name, handler in handlers.items()]


async def test_upload_flows_through_every_stage_with_parallel_parser_fanout(
    tmp_path: Path, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Fanout E2E Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fanout-{uuid.uuid4()}@test.local")

    mixed_bytes = _build_mixed_upload(tmp_path, seed=777)
    sample_text = mixed_bytes[:65536].decode("utf-8", errors="replace")
    detected = detect_source_types(sample_text)
    assert set(detected) == {"zscaler", "okta", "cloudtrail"}, detected

    settings = get_settings()
    ensure_bucket()
    storage_ref = f"{tenant.id}/{uuid.uuid4()}-mixed.log"
    get_s3_client().put_object(Bucket=settings.s3_bucket, Key=storage_ref, Body=mixed_bytes)

    analysis = make_analysis(
        tenant_id=tenant.id, user_id=user.id, detected_sources=detected, storage_ref=storage_ref
    )

    enrich_calls: list[uuid.UUID] = []
    real_enrich_handler = make_skeleton_handler("enrich")

    async def counting_enrich_handler(message: StageMessage) -> list[tuple[str, StageMessage]]:
        enrich_calls.append(message.analysis_id)
        return await real_enrich_handler(message)

    workers = _all_workers(counting_enrich_handler)
    worker_tasks = [asyncio.create_task(w.run()) for w in workers]
    sink_task = asyncio.create_task(dead_letter_sink.run())

    progress_events: list[dict[str, object]] = []

    async def _collect_progress() -> None:
        redis_client = get_redis()
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(f"analysis:{analysis.id}")
        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    progress_events.append(json.loads(message["data"]))
        finally:
            await pubsub.unsubscribe(f"analysis:{analysis.id}")
            await pubsub.aclose()  # type: ignore[no-untyped-call]

    collector_task = asyncio.create_task(_collect_progress())

    try:
        await kickoff_pipeline(analysis_id=analysis.id, tenant_id=tenant.id)

        deadline = time.monotonic() + 30
        status: str | None = None
        while time.monotonic() < deadline:
            with get_engine().begin() as conn:
                status = state.fetch_status(conn, analysis_id=analysis.id, tenant_id=tenant.id)
            if status in {"complete", "failed"}:
                break
            await asyncio.sleep(0.2)

        with get_engine().begin() as conn:
            final = state.fetch_analysis(conn, analysis_id=analysis.id, tenant_id=tenant.id)
        assert status == "complete", (
            f"pipeline ended in status={status!r}, error={final['error']!r}"
        )

        assert final["stage"] == "tier2"
        assert final["progress"] == 1.0
        assert final["pending_parsers"] == 0
        assert final["parse_failure_rate"] is not None
        assert 0.0 <= final["parse_failure_rate"] <= 1.0
        assert final["counters"]["events"] > 0

        # The fan-in gate fired exactly once: exactly one q.enrich message was ever
        # published, from whichever of the three real parser workers finished last —
        # under real concurrent execution (three genuine asyncio tasks, each doing a
        # real MinIO GET + COPY, racing against the same analyses row), not simulated.
        assert enrich_calls == [analysis.id], enrich_calls

        stages_seen = [e["stage"] for e in progress_events]
        for expected_stage in (
            "ingest",
            "parse",
            "enrich",
            "anonymize",
            "detect",
            "correlate",
            "triage",
            "respond",
            "tier2",
        ):
            assert expected_stage in stages_seen, (
                f"never saw a progress event for stage={expected_stage!r}: {stages_seen}"
            )

        assert progress_events[-1]["status"] == "complete"
        assert progress_events[-1]["progress"] == 1.0

        with get_engine().begin() as conn:
            event_count = conn.execute(
                text("SELECT count(*) FROM events WHERE analysis_id = :aid"), {"aid": analysis.id}
            ).scalar_one()
        assert event_count == final["counters"]["events"]
        assert event_count > 0
    finally:
        for task in (*worker_tasks, sink_task, collector_task):
            task.cancel()
        for task in (*worker_tasks, sink_task, collector_task):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        with get_engine().begin() as conn:
            conn.execute(text("DELETE FROM events WHERE analysis_id = :aid"), {"aid": analysis.id})
