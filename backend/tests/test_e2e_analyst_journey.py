"""change 25's E2E row: "upload -> overview -> timeline -> incident -> evidence -> feedback ->
learning event ... Playwright, headless, in CI."

## Playwright decision — reported, not silently substituted

Playwright is not a dependency anywhere in this repo (`frontend/package.json`, `backend/
pyproject.toml`, `.github/workflows/ci.yml` — grepped, zero hits) and CLAUDE.md's anti-patterns
list is explicit: "Do not add libraries not listed in the stack table without asking." Playwright
is not in that table. Adding it — plus a browser-install CI step, plus actually building the seven
UI flows this row names into a real headless-browser spec — is a real, non-trivial cost (a new
runtime dependency, a slower/flakier CI job class, and UI automation this codebase has never had)
that should be a decision made with the person who owns this migration, not one made silently
mid-task. This file is the other option change 25's own row explicitly allows: "implement the
equivalent flow as an API-level integration test and say clearly it is not browser-level." It is
not a browser test. It does not render a page, click a button, or verify anything about layout,
CSS, or client-side JS. It proves the seven-step *server-side* journey is coherent end to end
through the same `TestClient`/ASGI transport every other API test in this suite already uses.

## What "real" means for each step here

* **upload**: a genuine `POST /api/uploads` multipart call — real MinIO write, real `uploads`/
  `analyses` rows, and it really does call `app.queue.dispatch.kickoff_pipeline` (docs/09).
* Draining the pipeline to `status=complete` runs the *real* `app.pipeline.stages.orchestrator`
  and `app.pipeline.stages.parse` workers against the live broker/Postgres/Redis/MinIO — the same
  `StageWorker`/`dead_letter_sink` machinery `tests/test_pipeline_fanout.py` proves end to end,
  reused here rather than reinvented. **What is not real yet**: `enrich`/`anonymize`/`detect`/
  `correlate`/`triage`/`tier2` have no queue-worker implementation in this codebase today —
  `app/pipeline/stages/` contains exactly `orchestrator.py`, `parse.py`, and the generic
  `skeleton.py` pass-through (see that module's own docstring: "Their real implementations land
  at M5 through M14"). The underlying detection/correlation/agent *logic* is real and extensively
  covered elsewhere (`tests/test_evidence_*.py`, `tests/test_ml_*.py`, `tests/test_graph_*.py`,
  `tests/test_agent_*.py`, `backend/evals/`) — it is simply not wired into a live queue consumer
  yet. This test cannot fabricate a real incident from a live pipeline run that does not exist,
  so it inserts the incident/signal/verdict directly (`tests/fixtures/learning.make_incident_
  with_verdict`, the exact helper `tests/test_learning_api.py`/`tests/test_incident_detail_api.py`
  already use for the same reason) on the *same* `analysis_id`/`tenant_id` the real upload+parse
  produced — a documented substitution for the one part of the pipeline that is not yet real at
  the worker level, not a shortcut invented for this file alone.
* **overview / timeline / incident / evidence / feedback / learning event**: every one of these
  is a real HTTP round-trip through the real FastAPI app, real Postgres reads/writes, and real
  `app.learning.feedback.record_feedback` consumer wiring (weight tuning, `learning_events`)
  — nothing mocked from here on.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.db import get_engine, get_session_factory
from app.pipeline import dead_letter_sink, state
from app.pipeline.base_worker import StageWorker
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.pipeline.stages import orchestrator as orchestrator_stage
from app.pipeline.stages import parse as parse_stage
from app.pipeline.stages.skeleton import make_skeleton_handler
from app.queue.topology import (
    QUEUE_NAMES,
    dead_letter_queue,
    declare_topology,
    delay_queue,
    get_connection,
    work_queue,
)
from datagen import corpus
from datagen.rng import SeededRandom
from datagen.types import TimeWindow
from tests.conftest import authenticate, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_incident_with_verdict,
    make_signal,
)

_STAGE_HANDLER = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]
_ORG_SPEC = corpus.OrgSpec(n_users=10, n_departments=1, offices=("US-CA",), n_service_accounts=1)


def _build_zscaler_upload(tmp_path: Path, *, seed: int) -> bytes:
    org = corpus.build_org(seed, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = SeededRandom(corpus.role_seed(seed, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(1)
    corpus.write_benign_corpus(org, root, window, tmp_path, proxy_events=60)
    return (tmp_path / "benign_zscaler.log").read_bytes()


def _all_workers() -> list[StageWorker]:
    """The real orchestrator + parse workers, skeleton stubs for everything downstream of
    parse — see this module's own docstring for exactly why (M5-M14 not wired into queue
    workers yet). Same set `tests/test_pipeline_fanout.py` runs, imported nowhere shared between
    the two files only because that module's own helper is private; duplicating eight lines here
    beats reaching into another test module's internals."""
    handlers: dict[str, _STAGE_HANDLER] = {
        "orchestrator": orchestrator_stage.handle,
        "parse.zscaler": parse_stage.handle,
        "enrich": make_skeleton_handler("enrich"),
        "anonymize": make_skeleton_handler("anonymize"),
        "detect": make_skeleton_handler("detect"),
        "correlate": make_skeleton_handler("correlate"),
        "triage": make_skeleton_handler("triage"),
        "tier2": make_skeleton_handler("tier2"),
    }
    return [StageWorker(name, handler) for name, handler in handlers.items()]


async def _purge_all_queues() -> None:
    """Must run *before* the upload call, not after: `app.api.uploads.create_upload` publishes
    the `ingest` message synchronously, inside the HTTP handler itself (`app.queue.dispatch.
    kickoff_pipeline`, docs/09 "Kicks off the pipeline") — by the time `client.post(...)` returns
    to the test, that message already exists on `q.orchestrator`. Purging *after* the upload
    (the naive ordering, matching `tests/test_pipeline_fanout.py`'s autouse fixture, which purges
    in *setup*, before its own test body ever publishes anything) would discard that exact
    message and this test would hang waiting for a pipeline that was never actually started."""
    get_redis.cache_clear()
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


async def _drain_pipeline_to_completion(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    """Runs every real+skeleton worker concurrently until this one analysis reaches a terminal
    status, then tears them down. Assumes `_purge_all_queues` already ran *before* the upload
    call that published the `ingest` message this drains."""
    workers = _all_workers()
    worker_tasks = [asyncio.create_task(w.run()) for w in workers]
    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        deadline = time.monotonic() + 30
        status: str | None = None
        while time.monotonic() < deadline:
            with get_engine().begin() as conn:
                status = state.fetch_status(conn, analysis_id=analysis_id, tenant_id=tenant_id)
            if status in {"complete", "failed"}:
                break
            await asyncio.sleep(0.1)
        assert status == "complete", f"pipeline ended in status={status!r}, expected complete"
    finally:
        for task in (*worker_tasks, sink_task):
            task.cancel()
        for task in (*worker_tasks, sink_task):
            with contextlib.suppress(asyncio.CancelledError):
                await task
    get_redis.cache_clear()


def test_full_analyst_journey_upload_through_learning_event(
    client: TestClient,
    tmp_path: Path,
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The seven-step journey change 25 names, walked in order, each step's assertions built on
    the *previous* step's real response data (not independently re-seeded per step, unlike most
    of this suite's per-endpoint tests) — proving the steps are actually connected, which is the
    entire point of an end-to-end test as opposed to seven isolated ones."""
    tenant = make_tenant(name="E2E Journey Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"e2e-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    # Purge before the upload, not after -- see _purge_all_queues's own docstring.
    asyncio.run(_purge_all_queues())

    # ---- 1. upload ----
    zscaler_bytes = _build_zscaler_upload(tmp_path, seed=4242)
    upload_resp = client.post(
        "/api/uploads", files={"file": ("proxy_export.log", zscaler_bytes, "text/plain")}
    )
    assert upload_resp.status_code == 201, upload_resp.text
    upload_body = upload_resp.json()
    assert "zscaler" in upload_body["detected_sources"]
    analysis_id = uuid.UUID(upload_body["analysis_id"])

    asyncio.run(_drain_pipeline_to_completion(analysis_id, tenant.id))

    # ---- 2. overview ----
    overview_resp = client.get(f"/api/analyses/{analysis_id}/overview")
    assert overview_resp.status_code == 200, overview_resp.text
    overview_body = overview_resp.json()
    assert overview_body["overview"]["events"] == 60, (
        "overview's event count must reflect the real events the real parse stage wrote for "
        "*this* analysis, not a stale/zero placeholder"
    )

    # ---- 3. timeline ----
    timeline_resp = client.get(f"/api/analyses/{analysis_id}/timeline")
    assert timeline_resp.status_code == 200, timeline_resp.text
    assert "phases" in timeline_resp.json()

    # ---- seed the incident: substitution for M5-M14's not-yet-wired workers, see module
    # docstring. Attached to the exact analysis_id/tenant_id the real upload+parse produced, so
    # every later step below reads it through the same real HTTP+DB path any other incident would
    # be read through.
    session = get_session_factory()()
    try:
        signal = make_signal(session, tenant_id=tenant.id, analysis_id=analysis_id)
        incident, _verdict = make_incident_with_verdict(
            session,
            tenant_id=tenant.id,
            analysis_id=analysis_id,
            signals=[signal],
            disposition="true_positive",
        )
        # Every step from here on reads through a *different* session (FastAPI's per-request
        # `get_db`, via TestClient) -- without this commit, those requests run in a separate
        # Postgres transaction that cannot see this one's uncommitted rows.
        session.commit()
    finally:
        session.close()

    # ---- 4. incident (list, then detail) ----
    incidents_resp = client.get(f"/api/analyses/{analysis_id}/incidents")
    assert incidents_resp.status_code == 200, incidents_resp.text
    listed_ids = {item["id"] for item in incidents_resp.json()["items"]}
    assert str(incident.id) in listed_ids, (
        "the incident just seeded under this analysis must appear in its own incident list"
    )

    detail_resp = client.get(f"/api/incidents/{incident.id}")
    assert detail_resp.status_code == 200, detail_resp.text
    detail_body = detail_resp.json()
    assert detail_body["id"] == str(incident.id)
    assert detail_body["verdict"] is not None
    assert detail_body["verdict"]["disposition"] == "true_positive"

    # ---- 5. evidence ----
    evidence_resp = client.get(f"/api/incidents/{incident.id}/evidence")
    assert evidence_resp.status_code == 200, evidence_resp.text

    # ---- 6. feedback ----
    feedback_resp = client.post(f"/api/incidents/{incident.id}/feedback", json={"agrees": True})
    assert feedback_resp.status_code == 200, feedback_resp.text
    feedback_body = feedback_resp.json()
    feedback_id = feedback_body["feedback_id"]

    # ---- 7. learning event ----
    # Mechanism 2 (fusion_weight_tuning) always fires on every feedback event, regardless of
    # disposition (app.learning.feedback's own docstring: "weight tuning always"), so this is the
    # one learning-events row this journey can assert on unconditionally rather than depending on
    # a gated mechanism's own trigger conditions.
    events_resp = client.get("/api/learning/events")
    assert events_resp.status_code == 200, events_resp.text
    matching = [e for e in events_resp.json()["items"] if e["trigger_feedback_id"] == feedback_id]
    assert matching, (
        f"no learning_events row was traceable back to feedback_id={feedback_id!r} -- the "
        "feedback step must produce a visible, attributable learning event, not just a 200"
    )
    assert any(e["mechanism"] == 2 for e in matching), (
        f"expected mechanism 2 (fusion_weight_tuning) among this feedback's learning events, "
        f"got mechanisms {[e['mechanism'] for e in matching]}"
    )
