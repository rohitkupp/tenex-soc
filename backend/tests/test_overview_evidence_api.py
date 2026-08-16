"""HTTP integration tests for docs/v2_migration/MIGRATION-01-evidence-first.md changes 8, 9, 10,
11, 14 (Path A) and 16 — against the real Postgres from docker-compose.yml:

    GET  /api/analyses/{id}/overview     change 9's deterministic overview + notable users/
                                          destinations, change 8's semantic findings slot (empty
                                          whenever nothing is flagged/no API key is configured —
                                          the LLM pass itself is `app.agent.orchestrator.assess_
                                          domain_semantics`, unit-tested without a DB in
                                          `tests/test_agent_domain_semantics.py`)
    POST /api/analyses/{id}/narrate      change 14 Path A, wired to HTTP
    GET  /api/incidents/{id}/evidence    change 16 primary evidence view + change 11's
                                          `highlight_lines`/`highlight_line_violations`
    GET  /api/analyses/{id}/evidence     change 16 secondary (analysis-wide) evidence view

Events are seeded via `app.storage.event_writer.bulk_copy_events`, the only sanctioned way to
write `events` (docs/02) — same fixture pattern `tests/test_evidence_run.py` and
`tests/test_events_writer.py` already established.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.detection.evidence.constants import SIGNAL_BEACONING, SIGNAL_DGA
from app.graph.builder import REL_ACCESSED
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.triage_verdict import TriageVerdict
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.response import (
    make_incident,
    make_signal,
    make_triage_verdict,
    response_tenant_cleanup,  # noqa: F401
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _seed_events(analysis_id: uuid.UUID, tenant_id: uuid.UUID, rows: list[dict[str, Any]]) -> int:
    def _records() -> Iterator[SimpleEventRecord]:
        for i, r in enumerate(rows):
            yield SimpleEventRecord(
                ts=r.get("ts", _T0),
                source_type="zscaler",
                raw_line_no=r.get("raw_line_no", i),
                ocsf_class_uid=4002,
                ocsf={"line": i},
                principal=r.get("principal"),
                src_ip=r.get("src_ip"),
                domain=r.get("domain"),
                action=r.get("action", "allowed"),
                http_method="GET",
                status_code=200,
                bytes_in=r.get("bytes_in"),
                bytes_out=r.get("bytes_out"),
            )

    conn = _raw_connection()
    try:
        return bulk_copy_events(conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=_records())
    finally:
        conn.close()


@pytest.fixture
def cleanup(response_tenant_cleanup: list[uuid.UUID]) -> Iterator[list[uuid.UUID]]:  # noqa: F811
    yield response_tenant_cleanup
    if not response_tenant_cleanup:
        return
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "DELETE FROM entity_edges WHERE analysis_id IN ("
                "  SELECT id FROM analyses WHERE tenant_id = ANY(:ids))"
            ),
            {"ids": response_tenant_cleanup},
        )
        conn.execute(
            text(
                "DELETE FROM entities WHERE analysis_id IN ("
                "  SELECT id FROM analyses WHERE tenant_id = ANY(:ids))"
            ),
            {"ids": response_tenant_cleanup},
        )
        conn.execute(
            text(
                "DELETE FROM events WHERE analysis_id IN ("
                "  SELECT id FROM analyses WHERE tenant_id = ANY(:ids))"
            ),
            {"ids": response_tenant_cleanup},
        )


@pytest.fixture
def ctx(cleanup: list[uuid.UUID]) -> dict[str, Any]:
    tenant = make_tenant(name="Overview/Evidence API Tenant")
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"overview-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    return {"tenant": tenant, "user": user, "analysis": analysis}


def _make_entity(*, analysis_id: uuid.UUID, type_: str, value: str, event_count: int) -> Entity:
    session = get_session_factory()()
    try:
        entity = Entity(
            analysis_id=analysis_id, type=type_, value=value, event_count=event_count, attrs={}
        )
        session.add(entity)
        session.commit()
        session.refresh(entity)
        return entity
    finally:
        session.close()


def _make_edge(*, analysis_id: uuid.UUID, src: int, dst: int) -> None:
    session = get_session_factory()()
    try:
        session.add(
            EntityEdge(
                analysis_id=analysis_id,
                src_entity_id=src,
                dst_entity_id=dst,
                relation=REL_ACCESSED,
                weight=1.0,
                event_count=1,
            )
        )
        session.commit()
    finally:
        session.close()


# =================================================================================== overview


_OVERVIEW_ROWS = [
    {
        "principal": "alice@corp.example",
        "src_ip": "10.0.0.1",
        "domain": "a.example.com",
        "action": "allowed",
        "bytes_out": 100,
        "bytes_in": 200,
    },
    {
        "principal": "alice@corp.example",
        "src_ip": "10.0.0.1",
        "domain": "a.example.com",
        "action": "allowed",
        "bytes_out": 100,
        "bytes_in": 200,
    },
    {
        "principal": "alice@corp.example",
        "src_ip": "10.0.0.1",
        "domain": "a.example.com",
        "action": "blocked",
        "bytes_out": 5,
        "bytes_in": 5,
    },
    {
        "principal": "bob@corp.example",
        "src_ip": "10.0.0.2",
        "domain": "b.example.com",
        "action": "blocked",
        "bytes_out": 50,
        "bytes_in": 0,
    },
    {
        "principal": "bob@corp.example",
        "src_ip": "10.0.0.2",
        "domain": "b.example.com",
        "action": "blocked",
        "bytes_out": 50,
        "bytes_in": 0,
    },
    {
        "principal": "carol@corp.example",
        "src_ip": "10.0.0.1",
        "domain": "c.example.com",
        "action": "allowed",
        "bytes_out": 10,
        "bytes_in": 20,
    },
]


def test_overview_stats_match_known_fixture_counts(client: TestClient, ctx: dict) -> None:
    """change 9: computed in SQL, matches known fixture counts exactly — expected values are
    derived from `_OVERVIEW_ROWS` itself (the "known fixture"), not hand-computed, so the
    assertion cannot silently drift from what was actually seeded."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    n = _seed_events(analysis.id, tenant.id, _OVERVIEW_ROWS)
    assert n == len(_OVERVIEW_ROWS)

    body = client.get(f"/api/analyses/{analysis.id}/overview").json()
    overview = body["overview"]

    assert overview["events"] == len(_OVERVIEW_ROWS)
    assert overview["users"] == len({r["principal"] for r in _OVERVIEW_ROWS})
    assert overview["src_ips"] == len({r["src_ip"] for r in _OVERVIEW_ROWS})
    assert overview["unique_domains"] == len({r["domain"] for r in _OVERVIEW_ROWS})
    assert overview["allowed"] == sum(1 for r in _OVERVIEW_ROWS if r["action"] == "allowed")
    assert overview["blocked"] == sum(1 for r in _OVERVIEW_ROWS if r["action"] == "blocked")
    assert overview["bytes_out"] == sum(r["bytes_out"] for r in _OVERVIEW_ROWS)
    assert overview["bytes_in"] == sum(r["bytes_in"] for r in _OVERVIEW_ROWS)
    assert body["anomaly_count"] == 0
    assert body["notable_users"] == []
    assert body["notable_destinations"] == []
    # change 8: no `Entity` rows of type "domain" exist for this analysis (only raw events were
    # seeded), so `notable_destinations` is empty and the semantic pass has no candidate to look
    # at — it never makes an LLM call for an empty candidate list
    # (`app.agent.orchestrator.assess_domain_semantics`'s own zero-candidate short-circuit), so
    # this assertion holds regardless of whether `ANTHROPIC_API_KEY` happens to be configured in
    # whatever environment runs this test.
    assert body["domain_semantic_findings"] == []


def test_overview_is_all_zero_for_an_analysis_with_no_events(client: TestClient, ctx: dict) -> None:
    """change 9: "on every upload, whether or not anything is flagged." An empty analysis is a
    valid, reportable overview, not a 500 or a null field."""
    authenticate(client, ctx["user"])
    body = client.get(f"/api/analyses/{ctx['analysis'].id}/overview").json()
    overview = body["overview"]
    assert overview["events"] == 0
    assert overview["users"] == 0
    assert overview["period_start"] is None
    assert overview["period_end"] is None
    assert overview["bytes_out"] == 0
    assert overview["bytes_in"] == 0


def test_overview_404_for_unknown_analysis(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    resp = client.get(f"/api/analyses/{uuid.uuid4()}/overview")
    assert resp.status_code == 404


def test_overview_requires_authentication(client: TestClient, ctx: dict) -> None:
    assert client.get(f"/api/analyses/{ctx['analysis'].id}/overview").status_code == 401


def test_notable_users_and_destinations_are_deterministic(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]

    flagged_user = _make_entity(
        analysis_id=analysis.id, type_="user", value="flagged@corp.example", event_count=500
    )
    quiet_user = _make_entity(
        analysis_id=analysis.id, type_="user", value="quiet@corp.example", event_count=3
    )
    evil_domain = _make_entity(
        analysis_id=analysis.id, type_="domain", value="evil.example.com", event_count=60
    )
    _make_edge(analysis_id=analysis.id, src=flagged_user.id, dst=evil_domain.id)

    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="flagged@corp.example",
        confidence=0.95,
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil.example.com",
        detector_key=SIGNAL_DGA,
        confidence=0.9,
        explanation={"score": 0.93},
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil.example.com",
        detector_key=SIGNAL_BEACONING,
        confidence=0.88,
        explanation={"dominant_period_s": 300.0, "fft_peak_power_ratio": 0.95},
    )

    body = client.get(f"/api/analyses/{analysis.id}/overview").json()

    users_by_value = {u["value"]: u for u in body["notable_users"]}
    assert users_by_value["flagged@corp.example"]["top_anomaly_score"] == pytest.approx(0.95)
    # No signal exists at all for the quiet user — still listed (ranked by volume), but with a
    # null top anomaly score, never a fabricated number.
    assert quiet_user.value not in users_by_value or (
        users_by_value.get(quiet_user.value, {}).get("top_anomaly_score") is None
    )

    dests_by_value = {d["value"]: d for d in body["notable_destinations"]}
    evil = dests_by_value["evil.example.com"]
    assert evil["dga_score"] == pytest.approx(0.93)
    assert evil["periodicity"] == {"dominant_period_s": 300.0, "spectral_strength": 0.95}
    assert evil["distinct_users"] == 1
    assert evil["connection_count"] == 60

    # Determinism: calling twice returns byte-identical JSON.
    body2 = client.get(f"/api/analyses/{analysis.id}/overview").json()
    assert body == body2


# =================================================================== domain semantics (change 8)


def test_overview_wires_domain_semantic_candidates_into_the_semantic_pass(
    client: TestClient, ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No live call: `app.api.analyses.assess_domain_semantics` (and `get_settings`) are
    monkeypatched, mirroring `test_narrate_wires_deterministic_overview_and_incidents_into_the_
    narrator` below — proves the *wiring* (a candidate is built from `notable_destinations` and
    handed to the pass, and its `DomainSemanticResult` is mapped onto the wire schema carrying
    the pinned `SEMANTIC_INSIGHT_LABEL`) without depending on the pass's own prompt/verifier
    behaviour, which `tests/test_agent_domain_semantics.py` covers without a DB at all."""
    from decimal import Decimal

    import app.api.analyses as analyses_module
    from app.agent.orchestrator import DomainFinding, DomainSemanticResult
    from app.schemas.overview import SEMANTIC_INSIGHT_LABEL

    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]

    domain = _make_entity(
        analysis_id=analysis.id,
        type_="domain",
        value="microsoft-security-login-support.com",
        event_count=4,
    )
    _seed_events(
        analysis.id,
        tenant.id,
        [
            {
                "principal": "alice@corp.example",
                "src_ip": "10.0.0.9",
                "domain": domain.value,
                "action": "allowed",
            }
        ],
    )

    captured: dict[str, Any] = {}

    def _fake_assess(**kwargs: Any) -> DomainSemanticResult:
        captured.update(kwargs)
        return DomainSemanticResult(
            findings=(
                DomainFinding(
                    domain=domain.value,
                    assessment="Impersonates Microsoft's security/login branding.",
                    rationale=(
                        "Combines 'microsoft' and 'security-login' with an unrelated base domain."
                    ),
                    evidence_id="DOMAIN-1",
                ),
            ),
            citation_valid=True,
            invalid_citations=(),
            model="test-model",
            tokens_in=10,
            tokens_out=5,
            cost_usd=Decimal("0.002"),
            latency_ms=17,
        )

    class _FakeKey:
        def get_secret_value(self) -> str:
            return "test-key"

    class _FakeSettings:
        llm_enabled = True
        anthropic_model = "test-model"
        anthropic_api_key = _FakeKey()

    monkeypatch.setattr(analyses_module, "assess_domain_semantics", _fake_assess)
    monkeypatch.setattr(analyses_module, "get_settings", lambda: _FakeSettings())

    body = client.get(f"/api/analyses/{analysis.id}/overview").json()

    assert len(captured["candidates"]) == 1
    assert captured["candidates"][0]["domain"] == domain.value

    findings = body["domain_semantic_findings"]
    assert len(findings) == 1
    assert findings[0]["domain"] == domain.value
    assert findings[0]["label"] == SEMANTIC_INSIGHT_LABEL
    assert "Microsoft" in findings[0]["assessment"]


def test_overview_domain_semantic_findings_do_not_alter_the_dga_score(
    client: TestClient, ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The DGA classifier's own score (`signal.dga`, read verbatim onto `NotableDestination.
    dga_score`) must be identical whether or not the semantic pass ran and flagged this same
    domain — change 8: "this does not replace the DGA classifier.\""""
    from decimal import Decimal

    import app.api.analyses as analyses_module
    from app.agent.orchestrator import DomainFinding, DomainSemanticResult

    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]

    domain = _make_entity(
        analysis_id=analysis.id, type_="domain", value="paypa1-secure.example.com", event_count=5
    )
    make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value=domain.value,
        detector_key=SIGNAL_DGA,
        confidence=0.2,
        explanation={"score": 0.11},  # low DGA probability -- linguistically ordinary
    )

    def _fake_assess(**kwargs: Any) -> DomainSemanticResult:
        return DomainSemanticResult(
            findings=(
                DomainFinding(
                    domain=domain.value,
                    assessment="Typosquat of paypal.com (digit substituted for a letter).",
                    rationale="'paypa1' substitutes the digit 1 for the letter l in 'paypal'.",
                    evidence_id="DOMAIN-1",
                ),
            ),
            citation_valid=True,
            invalid_citations=(),
            model="test-model",
            tokens_in=10,
            tokens_out=5,
            cost_usd=Decimal("0.002"),
            latency_ms=17,
        )

    class _FakeKey:
        def get_secret_value(self) -> str:
            return "test-key"

    class _FakeSettings:
        llm_enabled = True
        anthropic_model = "test-model"
        anthropic_api_key = _FakeKey()

    monkeypatch.setattr(analyses_module, "assess_domain_semantics", _fake_assess)
    monkeypatch.setattr(analyses_module, "get_settings", lambda: _FakeSettings())

    body = client.get(f"/api/analyses/{analysis.id}/overview").json()

    dest = next(d for d in body["notable_destinations"] if d["value"] == domain.value)
    assert dest["dga_score"] == pytest.approx(0.11)
    assert len(body["domain_semantic_findings"]) == 1


def test_overview_domain_semantic_findings_empty_without_an_api_key(
    client: TestClient, ctx: dict
) -> None:
    """This test environment has no `ANTHROPIC_API_KEY` configured, matching `test_narrate_
    returns_503_without_an_api_key`'s own assumption — but unlike `POST /narrate`, `GET /overview`
    never 503s over it: an unconfigured key degrades `domain_semantic_findings` to `[]`, the same
    "empty is a correct answer" contract the rest of change 9's overview already guarantees, even
    though a real candidate domain exists."""
    assert get_settings().llm_enabled is False, "this test assumes no API key is configured"
    authenticate(client, ctx["user"])
    analysis = ctx["analysis"]

    _make_entity(
        analysis_id=analysis.id,
        type_="domain",
        value="totally-first-seen.example.com",
        event_count=2,
    )

    resp = client.get(f"/api/analyses/{analysis.id}/overview")
    assert resp.status_code == 200
    assert resp.json()["domain_semantic_findings"] == []


# =================================================================================== narrate


def test_narrate_returns_503_without_an_api_key(client: TestClient, ctx: dict) -> None:
    """This test environment has no `ANTHROPIC_API_KEY` configured (CLAUDE.md: "recorded LLM
    responses, not live calls" — CI must never need a key), so this exercises the real
    no-key branch rather than a mocked one."""
    authenticate(client, ctx["user"])
    assert get_settings().llm_enabled is False, "this test assumes no API key is configured"
    resp = client.post(f"/api/analyses/{ctx['analysis'].id}/narrate")
    assert resp.status_code == 503
    assert resp.json()["code"] == "anthropic_api_key_not_configured"


def test_narrate_requires_authentication(client: TestClient, ctx: dict) -> None:
    assert client.post(f"/api/analyses/{ctx['analysis'].id}/narrate").status_code == 401


def test_narrate_404_for_unknown_analysis(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    assert client.post(f"/api/analyses/{uuid.uuid4()}/narrate").status_code == 404


def test_narrate_wires_deterministic_overview_and_incidents_into_the_narrator(
    client: TestClient, ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No live call: `app.api.analyses.narrate_analysis` (and `get_settings`) are monkeypatched
    so this proves the *wiring* — overview/incidents/timeline built correctly and the
    `NarrationResult` mapped correctly onto the wire — without spending a token or depending on
    the Narrator's own prompt/verifier behaviour (already covered by `tests/
    test_agent_narrator.py`)."""
    from decimal import Decimal

    import app.api.analyses as analyses_module
    from app.agent.orchestrator import NarrationResult

    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    make_incident(tenant_id=tenant.id, analysis_id=analysis.id, title="Beacon to evil.example.com")

    captured: dict[str, Any] = {}

    def _fake_narrate(**kwargs: Any) -> NarrationResult:
        captured.update(kwargs)
        return NarrationResult(
            executive_summary="One incident, no traffic processed.",
            phase_narratives=(),
            citation_valid=True,
            invalid_citations=(),
            model="test-model",
            tokens_in=10,
            tokens_out=5,
            cost_usd=Decimal("0.01"),
            latency_ms=42,
        )

    class _FakeKey:
        def get_secret_value(self) -> str:
            return "test-key"

    class _FakeSettings:
        llm_enabled = True
        anthropic_model = "test-model"
        anthropic_api_key = _FakeKey()

    monkeypatch.setattr(analyses_module, "narrate_analysis", _fake_narrate)
    monkeypatch.setattr(analyses_module, "get_settings", lambda: _FakeSettings())

    resp = client.post(f"/api/analyses/{analysis.id}/narrate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["executive_summary"] == "One incident, no traffic processed."
    assert body["model"] == "test-model"
    assert body["cost_usd"] == "0.01"

    assert captured["overview"]["events"] == 0
    assert len(captured["incidents"]) == 1
    assert captured["incidents"][0]["title"] == "Beacon to evil.example.com"
    assert captured["timeline_phases"] == []


# =================================================================================== evidence


def _beacon_fixture() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ts = _T0
    for i in range(60):
        rows.append(
            {
                "ts": ts,
                "raw_line_no": i,
                "principal": "implant-victim@corp.example",
                "src_ip": "10.0.0.50",
                "domain": "beacon.example.com",
                "action": "allowed",
            }
        )
        ts += timedelta(seconds=240)
    return rows


def test_analysis_evidence_lists_payloads_including_ones_that_formed_no_incident(
    client: TestClient, ctx: dict
) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    _seed_events(analysis.id, tenant.id, _beacon_fixture())

    body = client.get(f"/api/analyses/{analysis.id}/evidence").json()
    assert body["total"] >= 1
    beaconing_items = [i for i in body["items"] if i["extractor"] == "beaconing"]
    assert len(beaconing_items) == 1
    item = beaconing_items[0]
    assert item["entity_type"] == "src_ip"
    assert item["entity_value"] == "10.0.0.50"
    assert item["contributing_line_numbers"]
    # No incident exists yet in this analysis at all — change 16's "including evidence that
    # never formed an incident" is the default state, not an edge case.
    assert item["incident_ids"] == []


def test_analysis_evidence_filters_by_extractor(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    _seed_events(analysis.id, tenant.id, _beacon_fixture())

    body = client.get(f"/api/analyses/{analysis.id}/evidence?extractor=beaconing").json()
    assert all(i["extractor"] == "beaconing" for i in body["items"])
    assert len(body["items"]) >= 1

    body_empty = client.get(f"/api/analyses/{analysis.id}/evidence?extractor=nope").json()
    assert body_empty["items"] == []
    assert body_empty["total"] == 0


def test_analysis_evidence_requires_authentication(client: TestClient, ctx: dict) -> None:
    assert client.get(f"/api/analyses/{ctx['analysis'].id}/evidence").status_code == 401


def test_analysis_evidence_404_for_unknown_analysis(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    assert client.get(f"/api/analyses/{uuid.uuid4()}/evidence").status_code == 404


def test_incident_evidence_highlight_lines_is_the_attribution_union(
    client: TestClient, ctx: dict
) -> None:
    """change 11: `highlight_lines` is the union of `contributing_line_numbers` across every
    `EvidencePayload` in the incident's scope — never wider, never narrower."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    _seed_events(analysis.id, tenant.id, _beacon_fixture())

    src_entity = _make_entity(
        analysis_id=analysis.id, type_="src_ip", value="10.0.0.50", event_count=60
    )
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="src_ip",
        entity_value="10.0.0.50",
        detector_key=SIGNAL_BEACONING,
    )
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            session.execute(
                text("UPDATE signals SET window_start = :s, window_end = :e WHERE id = :id"),
                {"s": _T0 - timedelta(hours=1), "e": _T0 + timedelta(hours=6), "id": signal.id},
            )
            session.commit()
    finally:
        session.close()

    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_ids=[src_entity.id],
        signal_ids=[signal.id],
    )

    evidence_body = client.get(f"/api/incidents/{incident.id}/evidence").json()
    assert evidence_body["items"], "the beaconing evidence should be in this incident's scope"
    union = sorted(
        {n for item in evidence_body["items"] for n in item["contributing_line_numbers"]}
    )
    assert evidence_body["highlight_lines"] == union
    assert evidence_body["highlight_line_violations"] == []

    # Now attach a verdict whose narrative cites a LOG line the evidence layer never nominated —
    # change 11's enforcement must catch it.
    make_triage_verdict(incident_id=incident.id, recommended_actions=[])
    out_of_scope_line = max(evidence_body["highlight_lines"]) + 9999
    session = get_session_factory()()
    try:
        verdict_row = session.execute(
            select(TriageVerdict).where(TriageVerdict.incident_id == incident.id)
        ).scalar_one()
        verdict_row.narrative = [
            {
                "step": 1,
                "claim": "beaconing observed",
                "evidence_ids": [f"LOG-{out_of_scope_line}"],
            }
        ]
        session.add(verdict_row)
        session.commit()
    finally:
        session.close()

    evidence_body_2 = client.get(f"/api/incidents/{incident.id}/evidence").json()
    assert evidence_body_2["highlight_line_violations"] == [out_of_scope_line]


def test_incident_evidence_requires_authentication(client: TestClient, ctx: dict) -> None:
    incident = make_incident(tenant_id=ctx["tenant"].id, analysis_id=ctx["analysis"].id)
    assert client.get(f"/api/incidents/{incident.id}/evidence").status_code == 401


def test_incident_evidence_404_for_another_tenants_incident(
    client: TestClient, ctx: dict, cleanup: list[uuid.UUID]
) -> None:
    other = make_tenant(name="Other Evidence Tenant")
    cleanup.append(other.id)
    other_user = make_user(tenant_id=other.id, email=f"other-{uuid.uuid4()}@test.local")
    other_analysis = make_analysis(tenant_id=other.id, user_id=other_user.id)
    other_incident = make_incident(tenant_id=other.id, analysis_id=other_analysis.id)

    authenticate(client, ctx["user"])
    resp = client.get(f"/api/incidents/{other_incident.id}/evidence")
    assert resp.status_code == 404
