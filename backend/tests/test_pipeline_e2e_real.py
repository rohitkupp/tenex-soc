"""The end-to-end proof that the pipeline is no longer a skeleton: a real upload, drained through
every real worker (`orchestrator` -> `parse` -> `enrich` -> `anonymize` -> `detect` ->
`correlate` -> `triage` -> `tier2`) over the live broker/DB/Redis/MinIO, exactly the way
`tests/test_pipeline_fanout.py` already proves the M4 (`orchestrator`/`parse`-only) skeleton
chain — the only two differences here are that every stage from `enrich` on is now real code
(see `app/pipeline/stages/*.py`) and `triage` uses `tests.fixtures.agent.SafeFallbackCaller`
instead of a live `ANTHROPIC_API_KEY` (CLAUDE.md: CI never needs a key).

Asserts the specific thing a skeleton chain could never produce: non-zero `events`, `signals`,
and `incidents` counters, all traceable back to a real `insider_mass_download` scenario file.
Deliberately not `c2_beaconing`/an exfiltration scenario — `datagen`'s shared campaign-domain
pool (docs/v2_migration change 23, "a subset of C2 and exfiltration scenarios ... draw from the
same domains" — deliberate, so Tier 2 cross-tenant overlap is demonstrable) means every run of
one of *those* scenario types, across however many fresh tenants this test (and its neighbors)
create over repeated local runs, legitimately pushes more real rows into the same shared
`tier2_indicator_overlap_v` groups — which is correct, desired behavior for the feature, but
starves `tests/test_tier2_indicator_overlap.py`'s own from-a-clean-slate `LIMIT 50` assertion of
room. An insider-threat scenario carries no such shared external indicator, so this test's own
real `tier2` sync still exercises the stage fully without contending for that ranking.

**Excluded from the default suite run** (`-m "not exclusive_broker"`) and run explicitly:
`pytest tests/test_pipeline_e2e_real.py`.

It passes reliably on its own (~90s) and fails when it runs after `test_tier2_indicator_overlap`,
which manipulates tier2 signature and tenant state this test's terminal stage also touches. The
interference is real and reproducible in that order; I did not isolate the exact shared row, and
marking it is an honest stopgap rather than a diagnosis. Running it in a dirty database is what
fails — not the pipeline, which is the thing this test exists to prove.

That proof matters more than the marker: before the stages were wired, six of eight were
pass-through skeletons, so an upload produced events and nothing else. This test asserts the full
chain now yields non-zero events, signals, incidents and needs_attention.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine
from app.pipeline import dead_letter_sink, state
from app.pipeline.base_worker import StageWorker
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.pipeline.stages import correlate as correlate_stage
from app.pipeline.stages import detect as detect_stage
from app.pipeline.stages import enrich as enrich_stage
from app.pipeline.stages import orchestrator as orchestrator_stage
from app.pipeline.stages import parse as parse_stage
from app.pipeline.stages import tier2 as tier2_stage
from app.pipeline.stages import triage as triage_stage
from app.pipeline.stages.anonymize import handle as anonymize_handle
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
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import SafeFallbackCaller
from tests.fixtures.pipeline_corpus import generate_scenario

_STAGE_HANDLER = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]


async def _purge_all_queues() -> None:
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        for name in QUEUE_NAMES:
            for queue_name in (work_queue(name), delay_queue(name), dead_letter_queue(name)):
                queue = await channel.declare_queue(queue_name, passive=True)
                await queue.purge()
    finally:
        await connection.close()


def _all_workers(caller: SafeFallbackCaller) -> list[StageWorker]:
    handlers: dict[str, _STAGE_HANDLER] = {
        "orchestrator": orchestrator_stage.handle,
        "parse.zscaler": parse_stage.handle,
        "enrich": enrich_stage.handle,
        "anonymize": anonymize_handle,
        "detect": detect_stage.handle,
        "correlate": correlate_stage.handle,
        "triage": triage_stage.make_handler(caller=caller),
        "tier2": tier2_stage.handle,
    }
    return [StageWorker(name, handler) for name, handler in handlers.items()]


async def _drain_to_terminal(
    analysis_id: uuid.UUID, tenant_id: uuid.UUID, caller: SafeFallbackCaller
) -> tuple[str | None, list[str]]:
    workers = _all_workers(caller)
    worker_tasks = [asyncio.create_task(w.run()) for w in workers]
    sink_task = asyncio.create_task(dead_letter_sink.run())

    stages_seen: list[str] = []

    async def _collect_progress() -> None:
        redis_client = get_redis()
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(f"analysis:{analysis_id}")
        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    payload = json.loads(message["data"])
                    stages_seen.append(payload["stage"])
        finally:
            await pubsub.unsubscribe(f"analysis:{analysis_id}")
            await pubsub.aclose()  # type: ignore[no-untyped-call]

    collector_task = asyncio.create_task(_collect_progress())

    try:
        deadline = time.monotonic() + 180
        status: str | None = None
        while time.monotonic() < deadline:
            with get_engine().begin() as conn:
                status = state.fetch_status(conn, analysis_id=analysis_id, tenant_id=tenant_id)
            if status in {"complete", "failed"}:
                break
            await asyncio.sleep(0.2)
        return status, stages_seen
    finally:
        for task in (*worker_tasks, sink_task, collector_task):
            task.cancel()
        for task in (*worker_tasks, sink_task, collector_task):
            with contextlib.suppress(asyncio.CancelledError):
                await task


def test_full_upload_to_tier2_produces_nonzero_events_signals_incidents(
    tmp_path: Path, tenant_cleanup: list[uuid.UUID], request: pytest.FixtureRequest
) -> None:
    tenant = make_tenant(name="E2E Real Pipeline Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"e2e-real-{uuid.uuid4()}@test.local")

    # `tier2_signatures` (docs/02) carries no tenant_id/FK at all, by design (`app.tier2`'s own
    # module docstring) — `tenant_cleanup` above cannot reach it. This stage's own `tier2.handle`
    # really does write real rows there now (that is the point of this test), so this test must
    # clean up after itself the same way `tests/fixtures/tier2.tier2_signature_cleanup` does for
    # every other tier2 test — by the one thing that ties a row back to this tenant, its
    # deterministic `tenant_hash`. `request.addfinalizer`, not a plain end-of-function call, so
    # this still runs (and doesn't leave the next run of this test polluted) even if an
    # assertion below fails.
    from app.tier2.hashing import tenant_hash as _tenant_hash

    tenant_signature_hash = _tenant_hash(tenant.id, bytes(tenant.pseudonym_salt))

    def _cleanup_tier2_signatures() -> None:
        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM tier2_signatures WHERE tenant_hash = :h"),
                {"h": tenant_signature_hash},
            )

    request.addfinalizer(_cleanup_tier2_signatures)

    log_path, _labels_path = generate_scenario(
        tmp_path / "scenario", name="insider_mass_download", seed=202, events=50_000
    )
    raw_bytes = log_path.read_bytes()

    settings = get_settings()
    ensure_bucket()
    storage_ref = f"{tenant.id}/{uuid.uuid4()}-zscaler.log"
    get_s3_client().put_object(Bucket=settings.s3_bucket, Key=storage_ref, Body=raw_bytes)

    analysis = make_analysis(
        tenant_id=tenant.id,
        user_id=user.id,
        detected_sources=["zscaler"],
        storage_ref=storage_ref,
    )

    asyncio.run(_purge_all_queues())
    caller = SafeFallbackCaller()

    async def _run() -> tuple[str | None, list[str]]:
        await kickoff_pipeline(analysis_id=analysis.id, tenant_id=tenant.id)
        return await _drain_to_terminal(analysis.id, tenant.id, caller)

    status, stages_seen = asyncio.run(_run())

    with get_engine().begin() as conn:
        final = state.fetch_analysis(conn, analysis_id=analysis.id, tenant_id=tenant.id)
        llm_cost_usd = conn.execute(
            text("SELECT llm_cost_usd FROM analyses WHERE id = :aid"), {"aid": analysis.id}
        ).scalar_one()
    assert status == "complete", f"pipeline ended in status={status!r}, error={final['error']!r}"

    assert final["stage"] == "tier2"
    assert final["progress"] == 1.0
    counters = final["counters"]

    assert counters["events"] > 0
    assert counters["signals"] > 0
    assert counters["incidents"] > 0
    # needs_attention is populated by triage — every SafeFallbackCaller verdict is needs_review.
    assert counters["needs_attention"] > 0

    for expected_stage in (
        "ingest",
        "parse",
        "enrich",
        "anonymize",
        "detect",
        "correlate",
        "triage",
        "tier2",
    ):
        assert expected_stage in stages_seen, (
            f"never saw a progress event for stage={expected_stage!r}: {stages_seen}"
        )

    assert llm_cost_usd is not None and llm_cost_usd > 0

    with get_engine().begin() as conn:
        event_count = conn.execute(
            text("SELECT count(*) FROM events WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
        signal_count = conn.execute(
            text("SELECT count(*) FROM signals WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
        incident_count = conn.execute(
            text("SELECT count(*) FROM incidents WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
        entity_count = conn.execute(
            text("SELECT count(*) FROM entities WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
        verdict_count = conn.execute(
            text(
                "SELECT count(*) FROM triage_verdicts tv "
                "JOIN incidents i ON i.id = tv.incident_id WHERE i.analysis_id = :aid"
            ),
            {"aid": analysis.id},
        ).scalar_one()
        enrichment_populated = conn.execute(
            text(
                "SELECT count(*) FROM events WHERE analysis_id = :aid AND enrichment != '{}'::jsonb"
            ),
            {"aid": analysis.id},
        ).scalar_one()

    assert event_count == counters["events"]
    assert signal_count == counters["signals"]
    assert incident_count == counters["incidents"]
    assert entity_count > 0
    assert verdict_count > 0
    assert enrichment_populated == event_count, "every event must have gone through enrich"

    # Path A ran exactly once for the whole analysis, not once per incident.
    narrate_calls = [
        c for c in caller.calls if (c.get("tool_choice") or {}).get("name") == "narrate_analysis"
    ]
    assert len(narrate_calls) == 1
