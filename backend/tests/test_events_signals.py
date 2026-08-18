"""Signal-aware events (`GET /api/analyses/{id}/events`, `GET /api/events/{id}`) and the
analysis-wide summarized timeline (`GET /api/analyses/{id}/timeline`) — docs/09.

These close two explicit take-home brief requirements that the pipeline already computes but
never exposed: "highlight the anomalous entries ... with a confidence score" and "a summarized
timeline of events". `app.api.events`'s `has_signal` filter used to be a documented M3-era stub
that always returned zero rows for `has_signal=true`; `test_has_signal_true_returns_only_signal_bearing_events`
is the regression test that proves it is a real predicate now.

Events are seeded via `app.storage.event_writer.bulk_copy_events` directly (no ingestion
endpoint exists to drive this through HTTP, same as `tests/test_events_api.py`). Signals are
seeded via `tests/fixtures/response.py::make_signal`, the same helper
`tests/test_incident_detail_api.py` uses.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.api.incident_detail import MAX_ANALYSIS_TIMELINE_PHASES
from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.models.base import tenant_scope
from app.models.event import Event
from app.models.tenant import Tenant
from app.models.user import User
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.response import make_signal, response_tenant_cleanup  # noqa: F401


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _seed_events(analysis_id: uuid.UUID, tenant_id: uuid.UUID, n: int, *, start: datetime) -> None:
    def rows() -> Iterator[SimpleEventRecord]:
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
                event_key="GET:general:allowed:2xx",
            )

    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=rows())
    finally:
        conn.close()


def _fetch_event_ids(tenant_id: uuid.UUID, analysis_id: uuid.UUID) -> list[int]:
    """Ordered by `id` ascending, which — for a single `bulk_copy_events` call — is also
    insertion order (BIGSERIAL), so index `i` here is the `i`-th event `_seed_events` wrote."""
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            rows = (
                session.execute(
                    select(Event.id).where(Event.analysis_id == analysis_id).order_by(Event.id)
                )
                .scalars()
                .all()
            )
        return list(rows)
    finally:
        session.close()


@pytest.fixture
# `response_tenant_cleanup` param shadows the imported fixture on purpose — same pattern as
# tests/test_incident_detail_api.py's `graph_cleanup`.
def authed(client: TestClient, response_tenant_cleanup: list[uuid.UUID]) -> tuple[Tenant, User]:  # noqa: F811
    tenant = make_tenant(name="Events Signals Tenant")
    response_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"events-signals-{uuid.uuid4()}@test.local")
    authenticate(client, user)
    return tenant, user


# ------------------------------------------------------------ signal stats on the list row


def test_event_with_signal_reports_signal_count_and_max_confidence(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_events(analysis.id, tenant.id, 3, start=datetime(2026, 5, 1, tzinfo=UTC))
    flagged_id, unflagged_id, _other_id = _fetch_event_ids(tenant.id, analysis.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        detector_key="signal.beaconing",
        confidence=0.73,
        evidence_event_ids=[flagged_id],
    )

    resp = client.get(f"/api/analyses/{analysis.id}/events")
    assert resp.status_code == 200
    items = {item["id"]: item for item in resp.json()["items"]}

    flagged_item = items[flagged_id]
    assert flagged_item["signal_count"] == 1
    assert flagged_item["max_confidence"] == pytest.approx(0.73)
    assert flagged_item["detectors"] == ["signal.beaconing"]

    unflagged_item = items[unflagged_id]
    assert unflagged_item["signal_count"] == 0
    assert unflagged_item["max_confidence"] is None
    assert unflagged_item["detectors"] == []


def test_event_cited_by_two_detectors_reports_both_and_max_confidence(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_events(analysis.id, tenant.id, 1, start=datetime(2026, 5, 2, tzinfo=UTC))
    (event_id,) = _fetch_event_ids(tenant.id, analysis.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        detector_key="signal.beaconing",
        confidence=0.4,
        evidence_event_ids=[event_id],
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        detector_key="rule.sigma_suspicious_ua",
        confidence=0.91,
        evidence_event_ids=[event_id],
    )

    resp = client.get(f"/api/analyses/{analysis.id}/events")
    item = next(i for i in resp.json()["items"] if i["id"] == event_id)
    assert item["signal_count"] == 2
    assert item["max_confidence"] == pytest.approx(0.91)
    assert sorted(item["detectors"]) == ["rule.sigma_suspicious_ua", "signal.beaconing"]


# ------------------------------------------------------------ has_signal (the un-stubbed filter)


def test_has_signal_true_returns_only_signal_bearing_events(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    """The regression test for the fix: `has_signal=true` used to `WHERE false()` unconditionally
    (a documented M3-era stub) and always came back empty. It must now return exactly the
    signal-cited events — critically, an unflagged event must be *absent*, not just "the flagged
    one is present" (a query with no predicate at all would also pass that weaker check)."""
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_events(analysis.id, tenant.id, 3, start=datetime(2026, 5, 3, tzinfo=UTC))
    flagged_id, unflagged_id, other_id = _fetch_event_ids(tenant.id, analysis.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        evidence_event_ids=[flagged_id],
    )

    resp = client.get(f"/api/analyses/{analysis.id}/events", params={"has_signal": "true"})
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert ids == {flagged_id}
    assert unflagged_id not in ids
    assert other_id not in ids


def test_has_signal_false_returns_only_events_with_no_signal(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_events(analysis.id, tenant.id, 3, start=datetime(2026, 5, 4, tzinfo=UTC))
    flagged_id, unflagged_id, other_id = _fetch_event_ids(tenant.id, analysis.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        evidence_event_ids=[flagged_id],
    )

    resp = client.get(f"/api/analyses/{analysis.id}/events", params={"has_signal": "false"})
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert ids == {unflagged_id, other_id}
    assert flagged_id not in ids


# ------------------------------------------------------------ GET /events/{id} detail


def test_get_event_returns_full_signals_list_with_explanation_intact(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_events(analysis.id, tenant.id, 1, start=datetime(2026, 5, 5, tzinfo=UTC))
    (event_id,) = _fetch_event_ids(tenant.id, analysis.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="example.com",
        detector_key="signal.beaconing",
        confidence=0.66,
        raw_score=1.2,
        mitre_technique="T1071.001",
        evidence_event_ids=[event_id],
        explanation={
            "mean_interval": 42.0,
            "per_feature": [{"feature": "cv", "contribution": 0.5}],
        },
    )

    resp = client.get(f"/api/events/{event_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["signal_count"] == 1
    assert body["max_confidence"] == pytest.approx(0.66)
    assert body["detectors"] == ["signal.beaconing"]
    assert len(body["signals"]) == 1
    sig = body["signals"][0]
    assert sig["detector_key"] == "signal.beaconing"
    assert sig["mitre_technique"] == "T1071.001"
    assert sig["raw_score"] == pytest.approx(1.2)
    # The nested key proves `explanation` was passed through verbatim, not narrowed/reshaped.
    assert sig["explanation"]["per_feature"][0]["feature"] == "cv"


# ------------------------------------------------------------ GET /analyses/{id}/timeline


def test_analysis_timeline_orders_chronologically_and_truncates_by_confidence(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    """101 signals, one cap of 100: the single weakest-confidence signal (deliberately placed in
    the *middle* of the chronological run, not at either end) must be the one phase dropped, and
    the 100 survivors must come back in chronological order with exactly that one gap — proving
    the cap ranks by confidence but the output order is still time, not confidence."""
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    start = datetime(2026, 6, 1, tzinfo=UTC)
    total = MAX_ANALYSIS_TIMELINE_PHASES + 1
    weak_index = total // 2

    with get_engine().begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO signals (
                    analysis_id, tenant_id, detector_key, detector_layer, raw_score, confidence,
                    entity_type, entity_value, window_start, window_end, mitre_technique,
                    evidence_event_ids, explanation
                )
                SELECT
                    :analysis_id, :tenant_id, 'signal.beaconing', 'signal', 0.5,
                    CASE WHEN i = :weak_index THEN 0.01 ELSE 0.5 + i * 0.001 END,
                    'domain', 'host-' || i || '.example.com',
                    (:start)::timestamptz + (i || ' minutes')::interval,
                    (:start)::timestamptz + (i || ' minutes')::interval,
                    NULL,
                    ARRAY[i]::bigint[],
                    '{}'::jsonb
                FROM generate_series(0, :max_i) AS i
                """
            ),
            {
                "analysis_id": analysis.id,
                "tenant_id": tenant.id,
                "start": start,
                "weak_index": weak_index,
                "max_i": total - 1,
            },
        )

    resp = client.get(f"/api/analyses/{analysis.id}/timeline")
    assert resp.status_code == 200
    body = resp.json()

    assert body["truncated"] is True
    assert body["total_phases"] == total
    phases = body["phases"]
    assert len(phases) == MAX_ANALYSIS_TIMELINE_PHASES
    assert body["total_phases"] > len(phases)  # the pairing the field exists to guarantee

    kept = [p["event_ids"][0] for p in phases]
    assert kept == [i for i in range(total) if i != weak_index]

    timestamps = [p["ts"] for p in phases]
    assert timestamps == sorted(timestamps)


def test_analysis_timeline_not_truncated_when_under_cap(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="a.example.com",
        evidence_event_ids=[1],
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="b.example.com",
        evidence_event_ids=[2],
    )

    resp = client.get(f"/api/analyses/{analysis.id}/timeline")
    assert resp.status_code == 200
    body = resp.json()
    assert body["truncated"] is False
    assert body["total_phases"] == 2
    assert len(body["phases"]) == 2
    assert body["total_phases"] == len(body["phases"])


def test_analysis_timeline_404_for_another_tenants_analysis(
    client: TestClient,
    authed: tuple[Tenant, User],
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811 - see `authed`'s definition above
) -> None:
    other_tenant = make_tenant(name="Other Analysis Timeline Tenant")
    response_tenant_cleanup.append(other_tenant.id)
    other_user = make_user(
        tenant_id=other_tenant.id, email=f"other-timeline-{uuid.uuid4()}@test.local"
    )
    other_analysis = make_analysis(tenant_id=other_tenant.id, user_id=other_user.id)

    resp = client.get(f"/api/analyses/{other_analysis.id}/timeline")
    assert resp.status_code == 404
    assert resp.json()["code"] == "not_found"


def test_analysis_timeline_404_for_unknown_analysis(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    resp = client.get(f"/api/analyses/{uuid.uuid4()}/timeline")
    assert resp.status_code == 404
    assert resp.json()["code"] == "not_found"


def test_analysis_timeline_requires_authentication(client: TestClient) -> None:
    resp = client.get(f"/api/analyses/{uuid.uuid4()}/timeline")
    assert resp.status_code == 401
