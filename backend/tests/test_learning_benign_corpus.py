"""`app.learning.benign_corpus` — consumer 5, "Benign corpus expansion" (docs/08 Part 2, §5)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.learning.benign_corpus import export_benign_baseline, flag_benign_baseline
from app.models.base import tenant_scope
from app.models.benign_baseline_entry import BenignBaselineEntry
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def test_flag_benign_baseline_requires_the_flag(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Benign Corpus No Flag Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"benign-noflag-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    feedback = make_feedback(
        learning_session, verdict_id=verdict.id, user_id=user.id, mark_benign_baseline=False
    )
    learning_session.commit()

    assert flag_benign_baseline(learning_session, tenant.id, feedback) == []


def test_flag_benign_baseline_creates_one_entry_per_distinct_entity_window(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Benign Corpus Dedup Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"benign-dedup-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig_a = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="ml.iforest",
        entity_type="user",
        entity_value="user1@corp.example",
    )
    # Same detector output twice for a different window on the same entity.
    sig_b = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="ml.autoencoder",
        entity_type="user",
        entity_value="user1@corp.example",
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig_a, sig_b],
        disposition="false_positive",
    )
    feedback = make_feedback(
        learning_session, verdict_id=verdict.id, user_id=user.id, mark_benign_baseline=True
    )
    learning_session.commit()

    entries = flag_benign_baseline(learning_session, tenant.id, feedback)
    # Both signals share (entity_type, entity_value) but have distinct default window bounds
    # (each make_signal call leaves window_start/window_end unset -> both None -> same key) --
    # so with identical keys they dedupe to one entry.
    assert len(entries) == 1
    assert entries[0].entity_type == "user"
    assert entries[0].entity_value == "user1@corp.example"
    assert entries[0].incident_id == _incident.id
    assert entries[0].included_in_training_at is None


def test_export_benign_baseline_returns_only_unconsumed_by_default(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Benign Corpus Export Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"benign-export-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="weird-but-sanctioned.example.com",
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    feedback = make_feedback(
        learning_session, verdict_id=verdict.id, user_id=user.id, mark_benign_baseline=True
    )
    learning_session.commit()

    entries = flag_benign_baseline(learning_session, tenant.id, feedback)
    learning_session.commit()
    assert len(entries) == 1

    export = export_benign_baseline(learning_session, tenant.id)
    exported_values = {e.entity_value for e in export}
    assert "weird-but-sanctioned.example.com" in exported_values
    match = next(e for e in export if e.entity_value == "weird-but-sanctioned.example.com")
    assert match.synthetic is False

    # Mark it consumed and confirm it drops out of the unconsumed export.
    with tenant_scope(learning_session, tenant.id):
        learning_session.execute(
            update(BenignBaselineEntry)
            .where(BenignBaselineEntry.id == entries[0].id)
            .values(included_in_training_at=datetime.now(UTC) + timedelta(seconds=1))
        )
        learning_session.commit()

    export_after = export_benign_baseline(learning_session, tenant.id)
    assert "weird-but-sanctioned.example.com" not in {e.entity_value for e in export_after}

    export_all = export_benign_baseline(learning_session, tenant.id, only_unconsumed=False)
    assert "weird-but-sanctioned.example.com" in {e.entity_value for e in export_all}
