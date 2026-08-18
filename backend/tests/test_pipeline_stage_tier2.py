"""`app.pipeline.stages.tier2` — real work: wires `app.tier2.signature_sync.sync_incident_to_tier2`
for real, and is the stage that actually flips `analyses.status` to `complete`."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from app.core.db import get_engine, get_tier2_engine
from app.pipeline.messages import StageMessage
from app.pipeline.stages import tier2
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_signal, make_triage_verdict


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="tier2",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_tier2_syncs_syncable_verdicts_skips_others_and_completes_analysis(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"tier2-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil.example",
    )
    tp_incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id], title="tp incident"
    )
    make_triage_verdict(
        incident_id=tp_incident.id,
        recommended_actions=["Investigate"],
        disposition="true_positive",
    )

    benign_incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, title="benign incident"
    )
    make_triage_verdict(
        incident_id=benign_incident.id, recommended_actions=[], disposition="benign"
    )

    # An incident that never got triaged at all — must be skipped, not crash the stage.
    make_incident(tenant_id=tenant.id, analysis_id=analysis.id, title="untriaged incident")

    with get_tier2_engine().begin() as conn:
        n_before = conn.execute(text("SELECT count(*) FROM tier2_signatures")).scalar_one()

    forwarded = asyncio.run(tier2.handle(_message(analysis.id, tenant.id)))
    assert forwarded == []  # terminal — tier2 never forwards

    # Two engines: the signature count is in the Tier 2 database, the analysis row is in the
    # primary one. The stage writes to both, so verifying it has to read from both.
    with get_tier2_engine().begin() as conn:
        n_after = conn.execute(text("SELECT count(*) FROM tier2_signatures")).scalar_one()
    with get_engine().begin() as conn:
        final = conn.execute(
            text("SELECT status, stage, progress FROM analyses WHERE id = :aid"),
            {"aid": analysis.id},
        ).one()

    # Exactly the true_positive incident synced — benign and untriaged both correctly excluded.
    assert n_after == n_before + 1

    assert final.status == "complete"
    assert final.stage == "tier2"
    assert final.progress == 1.0
