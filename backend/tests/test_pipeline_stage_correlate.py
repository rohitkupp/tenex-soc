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
                "SELECT title, severity, fused_score, anomaly_confidence, entity_ids, signal_ids, "
                "tags, summary FROM incidents WHERE analysis_id = :aid"
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
    # This task's deterministic pipeline outputs -- present on every incident, not just triaged
    # ones (`app.graph.tags`/`app.graph.summary`).
    assert incident.tags  # at least `layer:signal` / `detector:signal.beaconing`
    assert "layer:signal" in incident.tags
    assert incident.summary
    assert incident.summary != ""


def test_correlate_incident_with_two_allowlisted_techniques_gets_both_tags(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """ "an incident whose signals carry 2+ techniques gets both tags" (this task's test list)."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
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

    # Two signals on the *same* seed entity (the domain) so Louvain places them in one
    # community/incident -- both allowlisted, both proxy-observable (docs/04's own rule set).
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="sigma.blocked_then_allowed",
        detector_layer="rule",
        mitre_technique="T1090",
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="sigma.executable_archive_download_new_domain",
        detector_layer="rule",
        mitre_technique="T1105",
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags, summary FROM incidents WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).all()
    assert len(incidents) == 1
    tags = incidents[0].tags
    assert "technique:T1090" in tags
    assert "technique:T1105" in tags
    assert incidents[0].summary


def test_correlate_incident_technique_outside_allowlist_is_not_passed_through(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """ "a technique outside the allowlist is rejected rather than passed through" (this task's
    test list). T1552.001 is `credentials-in-url.yml`'s own tag and is not one of the 13
    proxy-observable allowlisted techniques."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    for i in range(3):
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=now + timedelta(minutes=i),
            raw_line_no=i + 1,
            principal="bob@corp.example",
            src_ip="10.0.0.6",
            domain="creds.example",
        )

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="creds.example",
        detector_key="sigma.credentials_in_url",
        detector_layer="rule",
        mitre_technique="T1552.001",
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags, summary FROM incidents WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).all()
    assert len(incidents) == 1
    tags = incidents[0].tags
    assert not any(t.startswith("technique:") for t in tags)
    assert "layer:rule" in tags  # the non-technique tags are unaffected
    assert incidents[0].summary


def test_correlate_multi_layer_tag_when_two_layers_corroborate_the_same_entity(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """ "an incident with signals from 2 layers gets a multi-layer tag" (this task's test list)."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
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

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="signal.beaconing",
        detector_layer="signal",
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="sigma.blocked_then_allowed",
        detector_layer="rule",
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags FROM incidents WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).all()
    assert len(incidents) == 1
    assert "multi-layer" in incidents[0].tags


def test_correlate_no_multi_layer_tag_when_single_layer(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
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

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="signal.beaconing",
        detector_layer="signal",
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags FROM incidents WHERE analysis_id = :aid"),
            {"aid": analysis.id},
        ).all()
    assert len(incidents) == 1
    assert "multi-layer" not in incidents[0].tags


def test_correlate_forms_asset_tags_from_evidence_events(tenant_cleanup: list[uuid.UUID]) -> None:
    """`app.graph.asset_tags` end to end: device/os/dept/location/app/risk/flow tags plus the two
    derived tags (`bypassed-client-connector`, `shared-device`) all land on the same
    `incidents.tags` array `app.graph.tags` already populates."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    event_ids = [
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=now + timedelta(minutes=i),
            raw_line_no=i + 1,
            principal="jsmith@corp.example",
            src_ip="10.0.0.5",
            domain="evil-c2.example",
            dst_ip="1.2.3.4",
            hostname="THINKPADSMITH",
            device_name="PC11NLPA:5F08D97B",
            device_owner="contractor1",  # diverges from principal's login -> shared-device
            os_type="windows",
            os_version="Version 10.0.19045",
            bypassed_traffic=True,
            flow_type="VPN Tunnel",
            ocsf={
                "unmapped": {
                    "department": "Sales",
                    "location": "US-CA",
                    "app_name": "Dropbox",
                },
                "risk_score": 95,
            },
        ).id
        for i in range(3)
    ]

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="signal.beaconing",
        confidence=0.9,
        evidence_event_ids=event_ids,
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags FROM incidents WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).all()
    assert len(incidents) == 1
    tags = incidents[0].tags
    assert "device:THINKPADSMITH" in tags
    assert "os:windows" in tags
    assert "os_version:10.0" in tags
    assert "dept:Sales" in tags
    assert "location:US-CA" in tags
    assert "app:Dropbox" in tags
    assert "risk:critical" in tags
    assert "flow:vpn-tunnel" in tags
    assert "bypassed-client-connector" in tags
    assert "shared-device" in tags
    # Signal-derived tags (`app.graph.tags`) still present alongside — one union, not two lists.
    assert "layer:signal" in tags


def test_correlate_asset_tags_absent_when_evidence_events_carry_no_device_data(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """No-fire case: evidence events with no device fields at all (the service-account/headless
    shape `datagen.emitters.zscaler._device_profile` produces) contribute zero asset tags,
    without raising."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"correlate-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    event_ids = [
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=now + timedelta(minutes=i),
            raw_line_no=i + 1,
            principal="svc-etl-airflow@corp.example",
            src_ip="10.0.0.9",
            domain="evil-c2.example",
            dst_ip="1.2.3.4",
        ).id
        for i in range(3)
    ]

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-c2.example",
        detector_key="signal.beaconing",
        confidence=0.9,
        evidence_event_ids=event_ids,
    )

    asyncio.run(correlate.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        incidents = conn.execute(
            text("SELECT tags FROM incidents WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).all()
    assert len(incidents) == 1
    tags = incidents[0].tags
    assert not any(
        t.startswith(("device:", "os:", "os_version:", "dept:", "location:", "app:", "risk:"))
        for t in tags
    )
    assert "bypassed-client-connector" not in tags
    assert "shared-device" not in tags
    assert "layer:signal" in tags  # the signal-derived tags are unaffected


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
