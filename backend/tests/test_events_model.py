"""Schema shape, indexes, cascade behavior, and structural tenant isolation for the
`events` table (docs/02-DATA-MODEL.md), against the real Postgres from
docker-compose.yml.

Rows are seeded via `app.storage.event_writer.bulk_copy_events` — there is no other way
to write `events` at this milestone (docs/02: "Bulk-load with COPY, never row-by-row
inserts"), and no ingestion endpoint exists yet (that lands with the pipeline at M4).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.models.analysis import Analysis
from app.models.base import MissingTenantScopeError, bypass_tenant_scope, tenant_scope
from app.models.event import Event
from app.models.upload import Upload
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
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


def _rows(n: int) -> Iterator[SimpleEventRecord]:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(n):
        yield SimpleEventRecord(
            ts=start + timedelta(seconds=i),
            source_type="zscaler",
            raw_line_no=i,
            ocsf_class_uid=4002,
            ocsf={"idx": i},
            principal=f"u_{i}",
            src_ip="10.0.0.1",
            domain="example.com",
            action="allowed",
        )


def _seed(analysis_id: uuid.UUID, tenant_id: uuid.UUID, n: int) -> None:
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=_rows(n))
    finally:
        conn.close()


# ------------------------------------------------------------ schema, exactly as docs/02


def test_events_table_has_exactly_the_five_documented_indexes() -> None:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'events'")
        ).all()
    by_name = dict(rows)

    assert set(by_name) == {
        "events_pkey",
        "ix_events_analysis_id_ts",
        "ix_events_analysis_id_principal_ts",
        "ix_events_analysis_id_domain",
        "ix_events_analysis_id_src_ip",
        "ix_events_ocsf_gin",
    }
    assert "(analysis_id, ts)" in by_name["ix_events_analysis_id_ts"]
    assert "(analysis_id, principal, ts)" in by_name["ix_events_analysis_id_principal_ts"]
    assert "(analysis_id, domain)" in by_name["ix_events_analysis_id_domain"]
    assert "(analysis_id, src_ip)" in by_name["ix_events_analysis_id_src_ip"]
    assert "USING gin (ocsf jsonb_path_ops)" in by_name["ix_events_ocsf_gin"]


def test_events_tenant_id_has_no_foreign_key_and_no_bare_index() -> None:
    """docs/02's own `CREATE TABLE events` gives `tenant_id` neither a `REFERENCES
    tenants(id)` FK nor a standalone index (see app/models/event.py's docstring for
    why) — unlike `users`/`uploads`/`analyses`, which do carry the FK."""
    with get_engine().connect() as conn:
        fk_defs = (
            conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'events'::regclass AND contype = 'f'"
                )
            )
            .scalars()
            .all()
        )
        index_defs = (
            conn.execute(text("SELECT indexdef FROM pg_indexes WHERE tablename = 'events'"))
            .scalars()
            .all()
        )

    assert not any("tenants" in d for d in fk_defs)
    assert not any(d.rstrip().endswith("btree (tenant_id)") for d in index_defs)


def test_events_analysis_id_cascades_on_delete(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant(name="Cascade Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="cascade@example.com")
    analysis = _make_analysis(tenant.id, user.id)
    _seed(analysis.id, tenant.id, 5)

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            count_before = session.execute(
                select(func.count()).select_from(Event).where(Event.analysis_id == analysis.id)
            ).scalar_one()
    finally:
        session.close()
    assert count_before == 5

    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM analyses WHERE id = :id"), {"id": analysis.id})

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            count_after = session.execute(
                select(func.count()).select_from(Event).where(Event.analysis_id == analysis.id)
            ).scalar_one()
    finally:
        session.close()
    assert count_after == 0


def test_events_analysis_id_rejects_unknown_analysis() -> None:
    """`analysis_id` is a real FK (`REFERENCES analyses(id)`), same as docs/02."""
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn = _raw_connection()
        try:
            bulk_copy_events(conn, analysis_id=uuid.uuid4(), tenant_id=uuid.uuid4(), rows=_rows(1))
        finally:
            conn.close()


# ------------------------------------------------------------ structural tenant isolation


def test_bare_session_raises_instead_of_leaking_events(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant(name="Bare Session Events")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="bare-events@example.com")
    analysis = _make_analysis(tenant.id, user.id)
    _seed(analysis.id, tenant.id, 3)

    session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(Event))
    finally:
        session.close()


def test_tenant_scoped_session_sees_only_its_own_events(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant_a = make_tenant(name="Events Tenant A")
    tenant_b = make_tenant(name="Events Tenant B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="events-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="events-b@example.com")
    analysis_a = _make_analysis(tenant_a.id, user_a.id)
    analysis_b = _make_analysis(tenant_b.id, user_b.id)
    _seed(analysis_a.id, tenant_a.id, 5)
    _seed(analysis_b.id, tenant_b.id, 7)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            rows = session.execute(select(Event)).scalars().all()
    finally:
        session.close()

    assert len(rows) == 5
    assert all(r.tenant_id == tenant_a.id for r in rows)


def test_cannot_fetch_another_tenants_event_even_by_primary_key(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant_a = make_tenant(name="PK Events A")
    tenant_b = make_tenant(name="PK Events B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="pk-events-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="pk-events-b@example.com")
    analysis_a = _make_analysis(tenant_a.id, user_a.id)
    analysis_b = _make_analysis(tenant_b.id, user_b.id)
    _seed(analysis_a.id, tenant_a.id, 1)
    _seed(analysis_b.id, tenant_b.id, 1)

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            other_event = session.execute(
                select(Event).where(Event.analysis_id == analysis_b.id)
            ).scalar_one()
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            result = session.execute(
                select(Event).where(Event.id == other_event.id)
            ).scalar_one_or_none()
    finally:
        session.close()
    assert result is None


# ------------------------------------------------------------ query plan


def test_filtered_query_uses_an_index_not_a_sequential_scan(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """docs/13's M3 acceptance ("paginates 1M+ rows without timing out") only holds if
    the planner actually picks one of the five documented indexes for a realistic
    filtered query instead of scanning the whole table. Proven here at a scale (60k
    rows across 20 analyses, this one 5% of the total) large and skewed enough that an
    index plan is reliably cheaper than a sequential scan. The authoritative 1M-row
    EXPLAIN is quoted in the M3 verification report; this is the CI-fast regression
    guard for the same claim, using `EXPLAIN (FORMAT JSON)` so the assertion inspects
    real plan node types rather than pattern-matching text output.
    """
    tenant = make_tenant(name="Explain Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="explain@example.com")

    target = _make_analysis(tenant.id, user.id, filename="target.log")
    _seed(target.id, tenant.id, 3_000)
    for i in range(19):
        other = _make_analysis(tenant.id, user.id, filename=f"other_{i}.log")
        _seed(other.id, tenant.id, 3_000)

    with get_engine().connect() as conn:
        conn.execute(text("ANALYZE events"))
        plan = conn.execute(
            text(
                "EXPLAIN (FORMAT JSON) SELECT * FROM events "
                "WHERE analysis_id = :aid AND principal = :p ORDER BY ts LIMIT 100"
            ),
            {"aid": str(target.id), "p": "u_7"},
        ).scalar_one()

    def node_types(node: dict) -> list[str]:
        types = [node.get("Node Type", "")]
        for child in node.get("Plans", []):
            types.extend(node_types(child))
        return types

    types = node_types(plan[0]["Plan"])
    assert any("Index" in t for t in types), f"no index-based node in plan: {types}"
    assert "Seq Scan" not in types, f"sequential scan chosen: {types}"


def test_events_rejects_missing_required_field(tenant_cleanup: list[uuid.UUID]) -> None:
    """`ocsf`, `ts`, `source_type`, etc. are `NOT NULL` per docs/02 — a `NULL` written
    through COPY (e.g. an adapter forgetting to populate a required field) fails
    loudly at the database rather than silently landing."""
    tenant = make_tenant(name="Not Null")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="notnull@example.com")
    analysis = _make_analysis(tenant.id, user.id)

    bad_row = SimpleEventRecord(
        ts=None,  # type: ignore[arg-type]
        source_type="zscaler",
        raw_line_no=1,
        ocsf_class_uid=4002,
        ocsf={},
    )
    conn = _raw_connection()
    try:
        with pytest.raises(psycopg.errors.NotNullViolation):
            bulk_copy_events(conn, analysis_id=analysis.id, tenant_id=tenant.id, rows=[bad_row])
    finally:
        conn.close()
