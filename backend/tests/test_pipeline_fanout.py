"""End-to-end pipeline test — docs/13's M4 acceptance: "An upload flows through every
stage" and this milestone's own brief: "Parallel parser fan-out: an upload with
multiple source types fans out and the pending_parsers gate fires exactly once. Prove
the counter is not racy."

ZScaler is the only registered source today (Okta and CloudTrail were removed, narrowing this
project to ZScaler web proxy logs only), so the fan-out this test proves is real but trivially
N=1: `app.pipeline.stages.orchestrator` still fans an upload's detected sources out to one
`StageMessage` per source (the mechanism `datagen`'s original mixed-export regression exercised
with three real parsers racing is unchanged — see `app.pipeline.contracts.PARSER_QUEUES` and
`app.pipeline.state.decrement_pending_parsers`'s docstring for why the same atomic
`UPDATE ... RETURNING` gate is still what makes "the parser whose decrement observes the counter
hit zero" race-free, whether N is 1 or 3), and `pending_parsers` still has to reach exactly zero
before the single `q.enrich` message is published. What a single registered source cannot prove
is the *race* between concurrent parsers; that regression coverage went with the sources that
made it exercisable, not because it stopped mattering, but because there is no second parser left
to race against. Everything else this test proves — real MinIO upload, the real orchestrator, the
real parse stage, and (M5-M14) every *real* downstream stage through to `tier2`, one asyncio task
per docs/01 worker, all against the live broker/DB/Redis — is otherwise identical to before,
co-located in one test process instead of twelve containers. `triage` uses `tests.fixtures.agent.
SafeFallbackCaller` rather than a live `ANTHROPIC_API_KEY` — this benign, unlabeled corpus is not
expected to produce any signals/incidents to triage in the first place, so the real point here
stays fan-out/race safety, not detection depth (`tests/test_pipeline_e2e_real.py` covers that).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine, get_tier2_engine
from app.parsers.registry import detect_source_types
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
from datagen import corpus
from datagen.rng import SeededRandom
from datagen.types import TimeWindow
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import SafeFallbackCaller


# Autouse for this module: every test here publishes to a real stage queue and consumes it back
# with its own worker, so a running `docker compose` stack silently steals half the messages.
# See the fixture's docstring in conftest.
@pytest.fixture(autouse=True)
def _require_exclusive_queues(no_competing_queue_consumers: None) -> None:
    """Bind the session-scoped check to every test in this module."""

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)

_STAGE_HANDLER = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]


def _build_zscaler_upload(tmp_path: Path, *, seed: int) -> bytes:
    """A real (M2-emitter) benign ZScaler log, header included."""
    org = corpus.build_org(seed, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = SeededRandom(corpus.role_seed(seed, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(1)
    # Large enough that L3's entity-window feature vectors are not degenerate (a handful of
    # events over a couple of hours produces extreme per-window ratios that can overflow a
    # model fit on a much larger, differently-distributed training corpus — a real
    # `app/detection/ml` numeric edge case, not something this test exists to exercise).
    corpus.write_benign_corpus(org, root, window, tmp_path, proxy_events=3000)
    return (tmp_path / "benign_zscaler.log").read_bytes()


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


def _all_workers(
    enrich_handler: _STAGE_HANDLER, *, caller: SafeFallbackCaller
) -> list[StageWorker]:
    handlers: dict[str, _STAGE_HANDLER] = {
        "orchestrator": orchestrator_stage.handle,
        "parse.zscaler": parse_stage.handle,
        "enrich": enrich_handler,
        "anonymize": anonymize_handle,
        "detect": detect_stage.handle,
        "correlate": correlate_stage.handle,
        "triage": triage_stage.make_handler(caller=caller),
        "tier2": tier2_stage.handle,
    }
    return [StageWorker(name, handler) for name, handler in handlers.items()]


async def test_upload_flows_through_every_stage_with_parser_fanout(
    tmp_path: Path, tenant_cleanup: list[uuid.UUID], request: pytest.FixtureRequest
) -> None:
    tenant = make_tenant(name="Fanout E2E Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fanout-{uuid.uuid4()}@test.local")

    # This benign corpus is not expected to form incidents, but a stray Sigma false-positive
    # could still reach `tier2` — `tier2_signatures` carries no tenant_id (see
    # `app.tier2`'s own module docstring), so `tenant_cleanup` above cannot reach it. Same
    # `tenant_hash`-keyed cleanup `tests/test_pipeline_e2e_real.py` uses.
    from app.tier2.hashing import tenant_hash as _tenant_hash

    tenant_signature_hash = _tenant_hash(tenant.id, bytes(tenant.pseudonym_salt))

    def _cleanup_tier2_signatures() -> None:
        # `get_tier2_engine`, not `get_engine`: `tier2_signatures` moved to its own physically
        # separate database in migration e2f71b3c8a45, and this cleanup was left pointing at the
        # primary one. It raised `UndefinedTable` in teardown — after the test body had already
        # passed — so it surfaced as a pytest ERROR rather than a failure and read like flaky
        # infrastructure.
        with get_tier2_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM tier2_signatures WHERE tenant_hash = :h"),
                {"h": tenant_signature_hash},
            )

    request.addfinalizer(_cleanup_tier2_signatures)

    zscaler_bytes = _build_zscaler_upload(tmp_path, seed=777)
    sample_text = zscaler_bytes[:65536].decode("utf-8", errors="replace")
    detected = detect_source_types(sample_text)
    assert detected == ["zscaler"], detected

    settings = get_settings()
    ensure_bucket()
    storage_ref = f"{tenant.id}/{uuid.uuid4()}-zscaler.log"
    get_s3_client().put_object(Bucket=settings.s3_bucket, Key=storage_ref, Body=zscaler_bytes)

    analysis = make_analysis(
        tenant_id=tenant.id, user_id=user.id, detected_sources=detected, storage_ref=storage_ref
    )

    enrich_calls: list[uuid.UUID] = []

    async def counting_enrich_handler(message: StageMessage) -> list[tuple[str, StageMessage]]:
        enrich_calls.append(message.analysis_id)
        return await enrich_stage.handle(message)

    caller = SafeFallbackCaller()
    workers = _all_workers(counting_enrich_handler, caller=caller)
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

        # Longer than the old skeleton-only deadline: every stage from `enrich` on now does
        # real work (model artifact loads, a second MinIO fetch for L3, real graph/LLM calls).
        deadline = time.monotonic() + 90
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
        # published — the single real parser worker's own decrement observed
        # `pending_parsers` hit zero, under real concurrent execution (a real asyncio
        # task doing a real MinIO GET + COPY, racing the same analyses row every other
        # worker in this test also touches), not simulated.
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
            "tier2",
        ):
            assert expected_stage in stages_seen, (
                f"never saw a progress event for stage={expected_stage!r}: {stages_seen}"
            )

        # docs/v2_migration change 20: the response action graph's `respond` stage/queue was
        # removed entirely, and `triage` now publishes straight to `tier2` (`app.pipeline.
        # contracts.NEXT_QUEUE["triage"] == "tier2"`). This is the regression this fanout test
        # exists to catch: if `triage` still published into `q.respond`, no worker in
        # `_all_workers` above would ever consume it, the pipeline would stall mid-run, and
        # `status == "complete"` above would already have failed. Assert the negative directly
        # too, so a future change re-adding a dangling `respond` hop fails here by name, not by
        # a timeout with no explanation.
        assert "respond" not in stages_seen, stages_seen

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
