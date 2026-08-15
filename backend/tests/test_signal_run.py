"""End-to-end test for `app.detection.signal.run.run_signal_layer` against the real Postgres
from docker-compose.yml -- the one integration test in this package; every detector's own
scoring logic is already covered by fast, DB-free unit tests (`test_signal_beaconing.py` etc.).
This test only needs to prove the plumbing: events fetched correctly, all four detectors wired
together, `signals` rows persisted with the right `analysis_id`/`tenant_id`/`detector_layer`,
tenant isolation intact.

Events are seeded via `app.storage.event_writer.bulk_copy_events` -- the only sanctioned way to
write `events` (docs/02) -- following the exact fixture pattern `tests/test_events_writer.py`
already established for a tenant-scoped `analyses` row.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.detection.signal.constants import (
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
)
from app.detection.signal.run import run_signal_layer
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.signal import Signal
from app.models.upload import Upload
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from tests.conftest import make_tenant, make_user

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _make_analysis(tenant_id: uuid.UUID, user_id: uuid.UUID) -> Analysis:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            upload = Upload(
                tenant_id=tenant_id,
                user_id=user_id,
                filename="mixed.log",
                size_bytes=1,
                sha256="b" * 64,
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


@pytest.fixture
def analysis(tenant_cleanup: list[uuid.UUID]) -> Analysis:
    tenant = make_tenant(name="Signal Layer Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="signal-layer@example.com")
    return _make_analysis(tenant.id, user.id)


def _record(
    *,
    ts: datetime,
    line_no: int,
    principal: str,
    src_ip: str,
    domain: str,
) -> SimpleEventRecord:
    return SimpleEventRecord(
        ts=ts,
        source_type="zscaler",
        raw_line_no=line_no,
        ocsf_class_uid=4002,
        ocsf={"line": line_no},
        principal=principal,
        src_ip=src_ip,
        domain=domain,
        action="allowed",
        http_method="GET",
        status_code=200,
    )


def _mixed_fixture() -> Iterator[SimpleEventRecord]:
    line = 0

    # -- beaconing + DGA: 60 near-perfectly-regular check-ins to a random-looking domain.
    ts = _T0
    for _ in range(60):
        yield _record(
            ts=ts,
            line_no=line,
            principal="implant-victim@corp.example",
            src_ip="10.0.0.50",
            domain="zzzzqxvbkpjh.top",
        )
        line += 1
        ts += timedelta(seconds=240)

    # -- rarity: one principal visits a low-volume domain a handful of times.
    ts = _T0
    for _ in range(3):
        yield _record(
            ts=ts,
            line_no=line,
            principal="rarity-victim@corp.example",
            src_ip="10.0.0.60",
            domain="raredomain123.example",
        )
        line += 1
        ts += timedelta(seconds=5)

    # -- burst: one principal has a flat baseline then a sharp spike in one 5-minute bucket.
    for bucket_idx, count in enumerate([2, 2, 2, 2, 2, 60]):
        bucket_start = _T0 + timedelta(seconds=bucket_idx * 300)
        for offset in range(count):
            yield _record(
                ts=bucket_start + timedelta(seconds=offset),
                line_no=line,
                principal="burst-victim@corp.example",
                src_ip="10.0.0.70",
                domain="dashboard.corp-tools.example",
            )
            line += 1


def _seed(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> int:
    conn = _raw_connection()
    try:
        return bulk_copy_events(
            conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=_mixed_fixture()
        )
    finally:
        conn.close()


def test_run_signal_layer_fires_all_four_detectors_and_persists_signals(
    analysis: Analysis,
) -> None:
    n_written = _seed(analysis.id, analysis.tenant_id)
    assert n_written > 0

    session = get_session_factory()()
    try:
        summary = run_signal_layer(session, analysis_id=analysis.id, tenant_id=analysis.tenant_id)
        session.commit()

        assert summary.n_events == n_written
        assert summary.counts_by_detector[SIGNAL_BEACONING] >= 1
        assert summary.counts_by_detector[SIGNAL_DGA] >= 1
        assert summary.counts_by_detector[SIGNAL_BURST] >= 1
        assert summary.counts_by_detector[SIGNAL_RARITY] >= 1
        assert summary.total_signals == sum(summary.counts_by_detector.values())

        with tenant_scope(session, analysis.tenant_id):
            rows = (
                session.execute(select(Signal).where(Signal.analysis_id == analysis.id))
                .scalars()
                .all()
            )
        assert len(rows) == summary.total_signals
        for row in rows:
            assert row.tenant_id == analysis.tenant_id
            assert row.analysis_id == analysis.id
            assert row.detector_layer == "signal"
            assert 0.0 <= row.confidence <= 1.0
            assert row.evidence_event_ids
            assert row.explanation
    finally:
        session.close()


def test_run_signal_layer_is_tenant_isolated(
    analysis: Analysis, tenant_cleanup: list[uuid.UUID]
) -> None:
    _seed(analysis.id, analysis.tenant_id)

    other_tenant = make_tenant(name="Other Tenant")
    tenant_cleanup.append(other_tenant.id)

    session = get_session_factory()()
    try:
        run_signal_layer(session, analysis_id=analysis.id, tenant_id=analysis.tenant_id)
        session.commit()

        with tenant_scope(session, other_tenant.id):
            other_tenant_rows = (
                session.execute(select(Signal).where(Signal.analysis_id == analysis.id))
                .scalars()
                .all()
            )
        assert other_tenant_rows == []
    finally:
        session.close()
