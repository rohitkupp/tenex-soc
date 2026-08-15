"""`app.storage.event_writer.bulk_copy_events` against the real Postgres from
docker-compose.yml — docs/02-DATA-MODEL.md: "Bulk-load with COPY, never row-by-row
inserts."

Full-scale (1M-row) throughput/RSS numbers are too slow to run as part of the routine
suite (same tradeoff `tests/test_datagen_realism_perf.py` makes for the synthetic-data
generator) — those are exercised by a standalone benchmark script and quoted in the M3
verification report. What's covered here: correctness of every column round-trip
through COPY, the row-count return value, `SimpleEventRecord`/`from_mapping`
convenience-constructor behavior, and — at a scale that finishes in well under a
second — the streaming-memory claim: peak RSS must not scale with total row count.
"""

from __future__ import annotations

import ipaddress
import resource
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.models.analysis import Analysis
from app.models.base import bypass_tenant_scope, tenant_scope
from app.models.event import Event
from app.models.upload import Upload
from app.storage.event_writer import EventRecord, SimpleEventRecord, bulk_copy_events
from tests.conftest import make_tenant, make_user


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _make_analysis(
    tenant_id: uuid.UUID, user_id: uuid.UUID, *, filename: str = "events.log"
) -> Analysis:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            upload = Upload(
                tenant_id=tenant_id,
                user_id=user_id,
                filename=filename,
                size_bytes=1,
                sha256="a" * 64,
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
    tenant = make_tenant(name="Writer Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="writer@example.com")
    return _make_analysis(tenant.id, user.id)


# ------------------------------------------------------------ correctness


def test_bulk_copy_events_round_trips_every_column(analysis: Analysis) -> None:
    ts = datetime(2026, 5, 1, 12, 30, 0, tzinfo=UTC)
    record = SimpleEventRecord(
        ts=ts,
        source_type="zscaler",
        raw_line_no=42,
        ocsf_class_uid=4002,
        ocsf={"activity_name": "allowed", "nested": {"a": [1, 2, 3]}},
        principal="u_abc123",
        src_ip="203.0.113.7",
        dst_ip="198.51.100.9",
        domain="malicious.example",
        url_path="/login",
        action="allowed",
        http_method="GET",
        status_code=200,
        bytes_in=1024,
        bytes_out=2048,
        user_agent="Mozilla/5.0",
        event_key="GET:general:allowed:2xx",
        enrichment={"asn": {"number": 64512, "org": "Example ASN"}},
    )

    conn = _raw_connection()
    try:
        written = bulk_copy_events(
            conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=[record]
        )
    finally:
        conn.close()
    assert written == 1

    session = get_session_factory()()
    try:
        with tenant_scope(session, analysis.tenant_id):
            row = session.execute(
                select(Event).where(Event.analysis_id == analysis.id)
            ).scalar_one()
    finally:
        session.close()

    assert row.analysis_id == analysis.id
    assert row.tenant_id == analysis.tenant_id
    assert row.ts == ts
    assert row.source_type == "zscaler"
    assert row.raw_line_no == 42
    assert row.ocsf_class_uid == 4002
    assert row.principal == "u_abc123"
    assert ipaddress.ip_address(row.src_ip) == ipaddress.ip_address("203.0.113.7")
    assert ipaddress.ip_address(row.dst_ip) == ipaddress.ip_address("198.51.100.9")
    assert row.domain == "malicious.example"
    assert row.url_path == "/login"
    assert row.action == "allowed"
    assert row.http_method == "GET"
    assert row.status_code == 200
    assert row.bytes_in == 1024
    assert row.bytes_out == 2048
    assert row.user_agent == "Mozilla/5.0"
    assert row.event_key == "GET:general:allowed:2xx"
    assert row.ocsf == {"activity_name": "allowed", "nested": {"a": [1, 2, 3]}}
    assert row.enrichment == {"asn": {"number": 64512, "org": "Example ASN"}}


def test_bulk_copy_events_leaves_nullable_hot_columns_null(analysis: Analysis) -> None:
    record = SimpleEventRecord(
        ts=datetime.now(UTC),
        source_type="zscaler",
        raw_line_no=1,
        ocsf_class_uid=4002,
        ocsf={"activity_name": "allowed"},
    )
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=[record])
    finally:
        conn.close()

    session = get_session_factory()()
    try:
        with tenant_scope(session, analysis.tenant_id):
            row = session.execute(
                select(Event).where(Event.analysis_id == analysis.id)
            ).scalar_one()
    finally:
        session.close()

    assert row.principal is None
    assert row.src_ip is None
    assert row.dst_ip is None
    assert row.status_code is None
    assert row.bytes_in is None
    assert row.enrichment == {}


def test_bulk_copy_events_returns_the_row_count(analysis: Analysis) -> None:
    def rows() -> Iterator[SimpleEventRecord]:
        for i in range(137):
            yield SimpleEventRecord(
                ts=datetime.now(UTC),
                source_type="zscaler",
                raw_line_no=i,
                ocsf_class_uid=4002,
                ocsf={"i": i},
            )

    conn = _raw_connection()
    try:
        written = bulk_copy_events(
            conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=rows()
        )
    finally:
        conn.close()
    assert written == 137

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            count = session.execute(
                select(func.count()).select_from(Event).where(Event.analysis_id == analysis.id)
            ).scalar_one()
    finally:
        session.close()
    assert count == 137


def test_simple_event_record_satisfies_the_event_record_protocol() -> None:
    record = SimpleEventRecord(
        ts=datetime.now(UTC), source_type="zscaler", raw_line_no=0, ocsf_class_uid=4002, ocsf={}
    )
    assert isinstance(record, EventRecord)


def test_simple_event_record_from_mapping_round_trips() -> None:
    ts = datetime.now(UTC)
    mapping = {
        "ts": ts,
        "source_type": "zscaler",
        "raw_line_no": 3,
        "ocsf_class_uid": 4002,
        "ocsf": {"a": 1},
        "principal": "u_x",
        "action": "SUCCESS",
    }
    record = SimpleEventRecord.from_mapping(mapping)
    assert record.ts == ts
    assert record.source_type == "zscaler"
    assert record.principal == "u_x"
    assert record.action == "SUCCESS"
    assert record.domain is None
    assert record.enrichment == {}


def test_simple_event_record_from_mapping_raises_on_missing_required_field() -> None:
    with pytest.raises(KeyError):
        SimpleEventRecord.from_mapping({"source_type": "zscaler"})


# ------------------------------------------------------------ streaming behaviour


def test_bulk_copy_events_streams_without_materializing_the_whole_iterable(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """Mirrors `test_datagen_realism_perf.py`'s memory-growth check: `ru_maxrss` is a
    process-wide high-water mark that never shrinks, so this is a one-sided but real
    proof — true `list(rows)` materialization would show ~5x RSS growth for a 5x
    row-count increase; a generator consumed one row at a time inside a single COPY
    does not. The authoritative 1M-row peak-RSS number is in the M3 verification
    report; this is the fast CI regression guard for the same claim.
    """
    tenant = make_tenant(name="Writer Streaming Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="streaming@example.com")

    def rows(n: int) -> Iterator[SimpleEventRecord]:
        base = datetime(2026, 2, 1, tzinfo=UTC)
        for i in range(n):
            yield SimpleEventRecord(
                ts=base + timedelta(seconds=i),
                source_type="zscaler",
                raw_line_no=i,
                ocsf_class_uid=4002,
                ocsf={"idx": i, "path": f"/resource/{i}", "tags": ["a", "b", "c"]},
                principal=f"u_{i % 50}",
                domain="example.com",
                action="allowed",
            )

    small_analysis = _make_analysis(tenant.id, user.id, filename="small.log")
    conn = _raw_connection()
    try:
        bulk_copy_events(
            conn, analysis_id=small_analysis.id, tenant_id=tenant.id, rows=rows(20_000)
        )
    finally:
        conn.close()
    rss_small = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    big_analysis = _make_analysis(tenant.id, user.id, filename="big.log")
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=big_analysis.id, tenant_id=tenant.id, rows=rows(100_000))
    finally:
        conn.close()
    rss_big = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    growth = rss_big / max(rss_small, 1)
    assert growth < 2.5, (
        f"peak RSS grew {growth:.2f}x when row count grew 5x (20k -> 100k) "
        f"({rss_small} -> {rss_big} KB/bytes) — looks like the writer is materializing "
        "the whole iterable instead of streaming it through COPY"
    )
