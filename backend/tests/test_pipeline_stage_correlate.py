"""`app.pipeline.stages.correlate` — real work: builds the entity graph, forms incidents via
Louvain community detection, fuses/scores them, and populates `incidents.anomaly_confidence`."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline.messages import StageMessage
from app.pipeline.stages import correlate
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event
from tests.fixtures.response import make_signal


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="correlate",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_correlate_forms_incidents_with_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    # Three co-occurring events keep the user<->domain edge above the prune threshold (>= 2).
    for i in range(3):
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=now + timedelta(minutes=i),
            raw_line_no=i + 1,
            principal="alice@corp.example",
            src_ip="10.0.0.5",
            domain="evil-c2.example",
            dst_ip="1.2.3.4",
        )

    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="signal.beaconing",
        confidence=0.9,
    )

    forwarded = asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))
    assert len(forwarded) == 1
    assert forwarded[0][0] == "triage"

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text(
                "SELECT title, severity, fused_score, anomaly_confidence, entity_ids, signal_ids "
                "FROM incidents WHERE analysis_id = :aid"
            ),
            {"aid": analysis.id},
        ).all()
        n_entities = conn.execute(
            text("SELECT count(*) FROM entities WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
        n_edges = conn.execute(
            text("SELECT count(*) FROM entity_edges WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).scalar_one()
        counters = conn.execute(
            text("SELECT counters FROM analyses WHERE id = :aid"), {"aid": analysis.id}
        ).scalar_one()

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity in {"critical", "high", "medium", "low"}
    assert 0.0 < incident.anomaly_confidence <= 100.0
    assert signal.id in incident.signal_ids
    assert n_entities > 0
    assert n_edges > 0
    assert counters["incidents"] == 1


def test_correlate_with_no_signals_forms_no_incidents(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate2-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=datetime.now(UTC),
        raw_line_no=1,
        principal="bob@corp.example",
        domain="benign.example",
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        n_incidents = conn.execute(
            text("SELECT count(*) FROM incidents WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).scalar_one()
        counters = conn.execute(
            text("SELECT counters FROM analyses WHERE id = :aid"), {"aid": analysis.id}
        ).scalar_one()
    assert n_incidents == 0
    assert counters["incidents"] == 0
