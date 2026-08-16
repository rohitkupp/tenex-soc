"""Round-trips `81f36664938b` (docs/v2_migration change 3, "two confidences, never mixed")
through the real `alembic` CLI machinery, the same way `tests/test_tier2_migration.py` and
`tests/test_baseline_migration.py` prove their own migrations' `downgrade()` isn't rotten.

Also proves the *backfill* actually does what the migration's own docstring claims, not just
that the columns come and go: an incident's `anomaly_confidence` is recomputed from its
`fused_score` on every `upgrade()`, and a verdict's `confidence` (once downgraded) lands in the
threat_confidence bucket's own documented midpoint.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.core.db import get_engine
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_triage_verdict

_MIGRATION_REVISION = "81f36664938b"
_DOWN_REVISION = "744b82efc029"


@pytest.fixture
def _seeded(tenant_cleanup: list[uuid.UUID]) -> tuple[uuid.UUID, uuid.UUID]:
    """One incident + verdict created against the *current* (post-`81f36664938b`) schema, via
    the real ORM models -- so the downgrade below has real, ORM-written data to migrate, not a
    hand-inserted row that happens to match the new shape by construction."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        fused_score=0.9,
        anomaly_confidence=90.0,
    )
    verdict = make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[],
        threat_confidence="high",
        threat_confidence_reason="Test verdict for migration round-trip.",
    )
    return incident.id, verdict.id


def test_two_confidences_migration_downgrade_then_upgrade_round_trips_cleanly(
    _seeded: tuple[uuid.UUID, uuid.UUID],
) -> None:
    from alembic.config import Config

    from alembic import command

    incident_id, verdict_id = _seeded
    cfg = Config("alembic.ini")

    # Same defensive dispose as the sibling migration round-trip tests: a pooled connection
    # that queried these tables under the old column set could otherwise hold a stale relation
    # cache entry once the columns change shape underneath it.
    get_engine().dispose()
    command.downgrade(cfg, _DOWN_REVISION)
    try:
        with get_engine().connect() as conn:
            incident_cols = {
                r.column_name
                for r in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'incidents'"
                    )
                ).all()
            }
            verdict_cols = {
                r.column_name
                for r in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'triage_verdicts'"
                    )
                ).all()
            }
            assert "anomaly_confidence" not in incident_cols
            assert "threat_confidence" not in verdict_cols
            assert "threat_confidence_reason" not in verdict_cols
            assert "confidence" in verdict_cols

            # The backfill's documented bucket midpoint for "high" is 0.85 -- our seeded
            # verdict's threat_confidence was "high", so its downgraded `confidence` must be
            # exactly that midpoint, not the (discarded, by design) original judgement.
            confidence = conn.execute(
                text("SELECT confidence FROM triage_verdicts WHERE id = :id"),
                {"id": str(verdict_id)},
            ).scalar_one()
            assert confidence == pytest.approx(0.85)
    finally:
        command.upgrade(cfg, "head")
        get_engine().dispose()

    # Re-verify the restored state independently of the try/finally above.
    with get_engine().connect() as conn:
        anomaly_confidence = conn.execute(
            text("SELECT anomaly_confidence FROM incidents WHERE id = :id"),
            {"id": str(incident_id)},
        ).scalar_one()
        threat_confidence, threat_confidence_reason = conn.execute(
            text(
                "SELECT threat_confidence, threat_confidence_reason FROM triage_verdicts "
                "WHERE id = :id"
            ),
            {"id": str(verdict_id)},
        ).one()

    # anomaly_confidence is re-derived from fused_score (0.9) on every upgrade -- exactly the
    # same value it carried before the round trip, because that derivation is lossless in this
    # direction (docs/v2_migration change 3's backfill choice).
    assert anomaly_confidence == pytest.approx(90.0)
    # threat_confidence is bucketed back from the downgraded `confidence` (0.85) -- "high" again,
    # by construction of the same thresholds the forward backfill and app.detection.fusion share.
    assert threat_confidence == "high"
    assert threat_confidence_reason  # never blank -- see the migration's own NOT NULL columns
    assert "migration" in threat_confidence_reason.lower()


def test_two_confidences_migration_upgrade_backfill_buckets_are_correct(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """A lower-level check on the forward backfill's own thresholds (>=0.75 high, >=0.4
    moderate, else low), independent of the round-trip test above: writes rows directly with
    raw SQL after a real `downgrade()`, so this exercises `upgrade()`'s `UPDATE` on rows the ORM
    never touched, not just ones already shaped by the current model."""
    from alembic.config import Config

    from alembic import command

    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.5)

    cfg = Config("alembic.ini")
    get_engine().dispose()
    command.downgrade(cfg, _DOWN_REVISION)
    verdict_ids: dict[str, uuid.UUID] = {}
    try:
        with get_engine().begin() as conn:
            for label, raw_confidence in (("high", 0.9), ("moderate", 0.5), ("low", 0.1)):
                vid = uuid.uuid4()
                verdict_ids[label] = vid
                conn.execute(
                    text(
                        "INSERT INTO triage_verdicts "
                        "(id, incident_id, disposition, confidence, mitre_techniques, summary, "
                        " narrative, recommended_actions, tool_trace, citation_valid, model) "
                        "VALUES (:id, :incident_id, 'true_positive', :confidence, '[]', 'x', "
                        " '[]', '[]', '[]', true, 'test')"
                    ),
                    {"id": str(vid), "incident_id": str(incident.id), "confidence": raw_confidence},
                )
    finally:
        command.upgrade(cfg, "head")
        get_engine().dispose()

    with get_engine().connect() as conn:
        buckets = dict(
            conn.execute(
                text("SELECT id, threat_confidence FROM triage_verdicts WHERE id = ANY(:ids)"),
                {"ids": [str(v) for v in verdict_ids.values()]},
            ).all()
        )
    assert buckets[verdict_ids["high"]] == "high"
    assert buckets[verdict_ids["moderate"]] == "moderate"
    assert buckets[verdict_ids["low"]] == "low"
