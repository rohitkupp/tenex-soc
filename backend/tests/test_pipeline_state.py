"""`app.pipeline.state` against the real Postgres from docker-compose.yml.

The load-bearing claim under test: `decrement_pending_parsers` is race-free under real
concurrency — this milestone's brief calls this out explicitly ("Implement that counter
correctly under concurrency (it is a race if done naively)"), so this file proves it
with real concurrent transactions against the live database, not a mock.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator

import pytest

from app.core.db import get_engine, get_session_factory
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.upload import Upload
from app.pipeline import state
from app.pipeline.contracts import DEFAULT_COUNTERS
from tests.conftest import make_tenant, make_user


@pytest.fixture
def analysis_id(tenant_cleanup: list[uuid.UUID]) -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    tenant = make_tenant(name="Pipeline State Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"pipeline-state-{uuid.uuid4()}@test.local")

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            upload = Upload(
                tenant_id=tenant.id,
                user_id=user.id,
                filename="events.log",
                size_bytes=1,
                sha256="a" * 64,
                storage_ref=f"{tenant.id}/{uuid.uuid4()}",
            )
            session.add(upload)
            session.flush()
            analysis = Analysis(tenant_id=tenant.id, upload_id=upload.id, status="queued")
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
        yield analysis.id, tenant.id
    finally:
        session.close()


def test_start_ingest_seeds_full_counter_shape(analysis_id: tuple[uuid.UUID, uuid.UUID]) -> None:
    aid, tid = analysis_id
    with get_engine().begin() as conn:
        state.start_ingest(conn, analysis_id=aid, tenant_id=tid, pending_parsers=3, progress=0.1)
        row = state.fetch_analysis(conn, analysis_id=aid, tenant_id=tid)

    assert row["status"] == "running"
    assert row["stage"] == "ingest"
    assert row["pending_parsers"] == 3
    assert row["counters"] == DEFAULT_COUNTERS


def test_decrement_pending_parsers_reaches_zero_and_floors_there(
    analysis_id: tuple[uuid.UUID, uuid.UUID],
) -> None:
    aid, tid = analysis_id
    with get_engine().begin() as conn:
        state.start_ingest(conn, analysis_id=aid, tenant_id=tid, pending_parsers=2, progress=0.1)

    with get_engine().begin() as conn:
        first = state.decrement_pending_parsers(conn, analysis_id=aid, tenant_id=tid)
    assert first == 1

    with get_engine().begin() as conn:
        second = state.decrement_pending_parsers(conn, analysis_id=aid, tenant_id=tid)
    assert second == 0

    # Floors at 0 rather than going negative if ever called an extra time (e.g. a
    # redelivered duplicate).
    with get_engine().begin() as conn:
        third = state.decrement_pending_parsers(conn, analysis_id=aid, tenant_id=tid)
    assert third == 0


def test_decrement_pending_parsers_fires_the_zero_gate_exactly_once_under_concurrency(
    analysis_id: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """The correctness claim this milestone singles out by name: N concurrent
    "parsers finishing at the same instant" must cause exactly one of them to observe
    the counter hit zero — never zero, never more than one. Real threads, real
    transactions, real Postgres row locking; nothing here is simulated."""
    aid, tid = analysis_id
    n_parsers = 8

    with get_engine().begin() as conn:
        state.start_ingest(
            conn, analysis_id=aid, tenant_id=tid, pending_parsers=n_parsers, progress=0.1
        )

    results: list[int] = []
    results_lock = threading.Lock()
    start_barrier = threading.Barrier(n_parsers)

    def _worker() -> None:
        start_barrier.wait()  # maximize actual concurrent contention on the row
        with get_engine().begin() as conn:
            remaining = state.decrement_pending_parsers(conn, analysis_id=aid, tenant_id=tid)
        with results_lock:
            results.append(remaining)

    threads = [threading.Thread(target=_worker) for _ in range(n_parsers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(results) == n_parsers
    # Every decrement observed a distinct value 0..n_parsers-1 — no two concurrent
    # transactions ever computed the same post-decrement number, and (critically) the
    # gate value 0 was observed exactly once, never zero times, never twice.
    assert sorted(results) == list(range(n_parsers))
    assert results.count(0) == 1

    with get_engine().begin() as conn:
        final = state.fetch_analysis(conn, analysis_id=aid, tenant_id=tid)
    assert final["pending_parsers"] == 0


def test_increment_counter_is_race_free_under_concurrency(
    analysis_id: tuple[uuid.UUID, uuid.UUID],
) -> None:
    aid, tid = analysis_id
    with get_engine().begin() as conn:
        state.start_ingest(conn, analysis_id=aid, tenant_id=tid, pending_parsers=1, progress=0.1)

    n_increments = 25
    start_barrier = threading.Barrier(n_increments)

    def _worker() -> None:
        start_barrier.wait()
        with get_engine().begin() as conn:
            state.increment_counter(conn, analysis_id=aid, tenant_id=tid, key="events", delta=10)

    threads = [threading.Thread(target=_worker) for _ in range(n_increments)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    with get_engine().begin() as conn:
        counters = state.get_counters(conn, analysis_id=aid, tenant_id=tid)
    assert counters["events"] == n_increments * 10  # no lost updates


def test_mark_failed_is_idempotent_and_does_not_clobber_first_error(
    analysis_id: tuple[uuid.UUID, uuid.UUID],
) -> None:
    aid, tid = analysis_id
    with get_engine().begin() as conn:
        state.start_ingest(conn, analysis_id=aid, tenant_id=tid, pending_parsers=1, progress=0.1)
        state.mark_failed(conn, analysis_id=aid, tenant_id=tid, error="first failure")
        state.mark_failed(
            conn, analysis_id=aid, tenant_id=tid, error="second failure, should be ignored"
        )
        row = state.fetch_analysis(conn, analysis_id=aid, tenant_id=tid)

    assert row["status"] == "failed"
    assert row["error"] == "first failure"
    assert row["finished_at"] is not None


def test_reopen_for_retry_only_flips_a_failed_analysis(
    analysis_id: tuple[uuid.UUID, uuid.UUID],
) -> None:
    aid, tid = analysis_id
    with get_engine().begin() as conn:
        state.start_ingest(conn, analysis_id=aid, tenant_id=tid, pending_parsers=1, progress=0.1)
        state.mark_failed(conn, analysis_id=aid, tenant_id=tid, error="boom")
        state.reopen_for_retry(conn, analysis_id=aid, tenant_id=tid)
        row = state.fetch_analysis(conn, analysis_id=aid, tenant_id=tid)

    assert row["status"] == "running"
    assert row["error"] is None
    assert row["finished_at"] is None


def test_fetch_analysis_raises_for_unknown_id(analysis_id: tuple[uuid.UUID, uuid.UUID]) -> None:
    _aid, tid = analysis_id
    with get_engine().begin() as conn, pytest.raises(state.AnalysisNotFoundError):
        state.fetch_analysis(conn, analysis_id=uuid.uuid4(), tenant_id=tid)
