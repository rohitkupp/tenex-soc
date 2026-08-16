"""`app.pipeline.stages.enrich` — real work, not a skeleton: asserts the actual rows it writes
(`events.enrichment` populated, `entities` seeded), not merely that the stage ran."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline import state
from app.pipeline.contracts import STAGE_PROGRESS
from app.pipeline.messages import StageMessage
from app.pipeline.stages import enrich
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="enrich",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_enrich_populates_enrichment_and_seeds_entities(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"enrich-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=now,
        raw_line_no=1,
        principal="alice@corp.example",
        src_ip="8.8.8.8",
        domain="github.com",
        user_agent="curl/8.0.1",
    )
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=now,
        raw_line_no=2,
        principal="alice@corp.example",
        src_ip="8.8.8.8",
        domain="github.com",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
    )

    forwarded = asyncio.run(enrich.handle(_message(analysis.id, tenant.id)))

    assert len(forwarded) == 1
    queue_name, next_message = forwarded[0]
    assert queue_name == "anonymize"
    assert next_message.stage == "anonymize"
    assert next_message.attempt == 0

    with get_engine().begin() as conn:
        enrichment_rows = (
            conn.execute(
                text("SELECT enrichment FROM events WHERE analysis_id = :aid ORDER BY raw_line_no"),
                {"aid": analysis.id},
            )
            .scalars()
            .all()
        )
        entity_rows = conn.execute(
            text("SELECT type, value, event_count FROM entities WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).all()
        stage_row = conn.execute(
            text("SELECT stage, progress FROM analyses WHERE id = :aid"), {"aid": analysis.id}
        ).one()

    assert len(enrichment_rows) == 2
    for enrichment in enrichment_rows:
        assert enrichment  # not the empty-`{}` default anymore — real work happened
        assert enrichment["domain"]["registrable_domain"] == "github.com"
        assert "tags" in enrichment
        assert "user_agent" in enrichment

    entity_map = {(row.type, row.value): row.event_count for row in entity_rows}
    assert entity_map[("user", "alice@corp.example")] == 2
    assert entity_map[("src_ip", "8.8.8.8")] == 2
    assert entity_map[("domain", "github.com")] == 2

    assert stage_row.stage == "enrich"
    assert stage_row.progress == STAGE_PROGRESS["enrich"]


def test_enrich_leaves_downstream_counters_untouched(tenant_cleanup: list[uuid.UUID]) -> None:
    """Enrich does not fabricate a signals/incidents/needs_attention count it did not produce —
    the same honesty standard the skeletons were written to (CLAUDE.md), just now for a stage
    that is doing real work in its own domain."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"enrich2-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_event(tenant_id=tenant.id, analysis_id=analysis.id, ts=datetime.now(UTC), raw_line_no=1)

    asyncio.run(enrich.handle(_message(analysis.id, tenant.id)))

    # `state.get_counters` (not a raw column read) — it is the one place that applies the
    # documented empty-JSONB -> `DEFAULT_COUNTERS` fallback (`app.pipeline.contracts.
    # public_counters`'s own docstring); a bare `make_analysis()` in a stage-isolation test never
    # went through `ingest`'s `start_ingest`, which is what seeds all four keys in production.
    with get_engine().begin() as conn:
        counters = state.get_counters(conn, analysis_id=analysis.id, tenant_id=tenant.id)
    assert counters["signals"] == 0
    assert counters["incidents"] == 0
    assert counters["needs_attention"] == 0
