"""Shared factory/cleanup helpers for `tests/test_tier2_*.py` — this milestone's own
version of `tests/fixtures/response.py`, kept separate for the same reason that module's
docstring gives: no collision with other, concurrently-developed milestones' fixtures.

Reuses `tests/fixtures/response.py`'s `make_incident`/`make_triage_verdict` directly
(imported by the test modules, not redefined here) rather than duplicating them — this
milestone needs exactly the same two rows, built the same way.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text

from app.core.db import (
    get_engine,
    get_session_factory,
    get_tier2_engine,
    get_tier2_session_factory,
    init_tier2_schema,
)
from app.models.entity import Entity


@pytest.fixture
def tier2_tenant_cleanup() -> Iterator[list[uuid.UUID]]:
    """The same tenant -> analysis -> incident -> verdict chain
    `tests/fixtures/response.py`'s `response_tenant_cleanup` tears down, minus the
    response-plan-specific tables this milestone never writes. Deleting `analyses`
    cascades to `entities` (`ON DELETE CASCADE`, `app.models.entity`) for free. Does
    **not** clean up `tier2_signatures` — that table carries no tenant linkage at all, by
    design (see `app.tier2.__init__`) — `tier2_signature_cleanup` below tracks those rows
    by their own id instead.
    """
    created: list[uuid.UUID] = []
    yield created
    if not created:
        return
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "DELETE FROM triage_verdicts WHERE incident_id IN ("
                "  SELECT id FROM incidents WHERE tenant_id = ANY(:ids)"
                ")"
            ),
            {"ids": created},
        )
        conn.execute(text("DELETE FROM incidents WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM signals WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM analyses WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM uploads WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM users WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": created})


@pytest.fixture
def tier2_signature_cleanup() -> Iterator[list[uuid.UUID]]:
    """`tier2_signatures` rows created directly (not via `sync_incident_to_tier2`'s own
    incident chain, or in addition to it) — tracked and deleted by id, since the table has
    no foreign key for a cascade to ride."""
    # `tier2_signatures` lives in the Tier 2 database now, not the primary one — a separate
    # engine, not just a separate table. Cleaning up through `get_engine()` would silently
    # delete nothing and leave rows behind for the next test to trip over.
    init_tier2_schema()
    created: list[uuid.UUID] = []
    yield created
    if not created:
        return
    with get_tier2_engine().begin() as conn:
        conn.execute(text("DELETE FROM tier2_signatures WHERE id = ANY(:ids)"), {"ids": created})


def make_entity(
    *,
    analysis_id: uuid.UUID,
    entity_type: str,
    value: str,
    event_count: int = 1,
    risk_score: float = 0.5,
) -> Entity:
    """`entities` is not `TenantScopedMixin` (docs/02: no `tenant_id` column at all,
    isolation transitive through `analysis_id`) — unlike `make_signal`/`make_incident` in
    `tests/fixtures/response.py`, this needs no `tenant_scope`."""
    session = get_session_factory()()
    try:
        entity = Entity(
            analysis_id=analysis_id,
            type=entity_type,
            value=value,
            event_count=event_count,
            risk_score=risk_score,
        )
        session.add(entity)
        session.commit()
        session.refresh(entity)
        return entity
    finally:
        session.close()


@pytest.fixture
def tier2_session():
    """A session bound to the Tier 2 database, for the tests that write or assert against
    `tier2_signatures`/`tier2_events` directly. Schema is created on demand so a fresh CI
    database needs no separate migration step."""
    init_tier2_schema()
    session = get_tier2_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
