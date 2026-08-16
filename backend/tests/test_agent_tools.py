"""`app.agent.tools` — the five read-only tools against a real Postgres. Proves the tool layer
pseudonymizes/redacts/caps on every path, since (per `app.agent.context`'s module docstring) the
real anonymizer worker is still a skeleton and this package cannot assume upstream data is
already safe to hand to an LLM.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.agent.context import build_agent_context
from app.agent.tools import (
    QUERY_EVENTS_HARD_CAP,
    ToolError,
    dispatch_tool,
    get_entity_baseline,
    get_entity_timeline,
    get_related_signals,
    query_events,
)
from app.core.db import get_session_factory

# `tenant_cleanup` is deliberately NOT imported: it lives in tests/conftest.py, which pytest
# discovers automatically. Importing a conftest fixture by name only creates a module-level
# rebinding that every test parameter then shadows (F811). Fixtures under tests/fixtures/**
# are the ones that must be imported, because that package is not a conftest.
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event
from tests.fixtures.response import make_incident, make_signal

WINDOW_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _setup_incident(cleanup: list[uuid.UUID], *, n_events: int = 3) -> tuple:
    tenant = make_tenant()
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    events = [
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=WINDOW_START + timedelta(minutes=i),
            raw_line_no=i + 1,
            principal="alice@corp.example",
            src_ip="10.1.1.1",
            dst_ip="203.0.113.5",
            domain="evil-newly-registered.example",
            url_path="/api/collect?token=" + ("x" * 300),  # exercise 256-char truncation
            user_agent="curl/8.7.1",
        )
        for i in range(n_events)
    ]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="alice@corp.example",
        detector_key="signal.beaconing",
        mitre_technique="T1071.001",
        evidence_event_ids=[e.id for e in events],
        explanation={"interval_s": 60, "cv": 0.02},
    )
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signal_ids=[signal.id],
        title="Test incident",
        severity="high",
        fused_score=0.9,
    )
    return tenant, analysis, events, signal, incident


@pytest.fixture
def incident_setup(tenant_cleanup: list[uuid.UUID]):
    return _setup_incident(tenant_cleanup)


# ---------------------------------------------------------------------------- query_events


def test_query_events_pseudonymizes_principal_and_ips(incident_setup) -> None:
    tenant, _analysis, events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = query_events(ctx, {"principal": "alice@corp.example"}, limit=50)
    finally:
        session.close()

    assert len(results) == len(events)
    for row in results:
        assert row["principal"] != "alice@corp.example"
        assert row["principal"].startswith("u_")
        assert row["src_ip"] != "10.1.1.1"
        assert row["src_ip"].startswith("ip_")
        # domain is NEVER pseudonymized (docs/06 do-NOT list)
        assert row["domain"] == "evil-newly-registered.example"


def test_query_events_exposes_log_citation_id(incident_setup) -> None:
    """docs/v2_migration change 7's `[LOG-n]` citation form is keyed on the file's own line
    number (`Event.raw_line_no`), not the DB primary key."""
    tenant, _analysis, events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = query_events(ctx, {"principal": "alice@corp.example"}, limit=50)
    finally:
        session.close()

    by_id = {r["id"]: r for r in results}
    for event in events:
        assert by_id[event.id]["log_id"] == f"LOG-{event.raw_line_no}"


def test_query_events_truncates_free_text_fields_to_256_chars(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = query_events(ctx, {"principal": "alice@corp.example"}, limit=50)
    finally:
        session.close()

    for row in results:
        assert len(row["url_path"]) <= 256


def test_query_events_hard_caps_at_200_regardless_of_requested_limit(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident = _setup_incident(tenant_cleanup, n_events=5)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = query_events(ctx, {"principal": "alice@corp.example"}, limit=10_000)
    finally:
        session.close()

    assert len(results) <= QUERY_EVENTS_HARD_CAP
    assert len(results) == 5  # only 5 exist; proves the cap doesn't truncate below what's real


def test_query_events_scoped_to_analysis(tenant_cleanup: list[uuid.UUID]) -> None:
    """A filter must never leak another analysis's events even within the same tenant."""
    tenant, _analysis, events, _signal, incident = _setup_incident(tenant_cleanup)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    other_analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_event(
        tenant_id=tenant.id,
        analysis_id=other_analysis.id,
        ts=WINDOW_START,
        principal="alice@corp.example",
    )

    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = query_events(ctx, {"principal": "alice@corp.example"}, limit=50)
    finally:
        session.close()

    assert len(results) == len(events)  # not len(events) + 1


def test_query_events_rejects_invalid_ip_filter(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        with pytest.raises(ToolError):
            query_events(ctx, {"src_ip": "not-an-ip"}, limit=50)
    finally:
        session.close()


def test_query_events_accepts_pseudonym_from_prior_call(incident_setup) -> None:
    """Once the model has seen a pseudonym, later filters use it — not the raw value it never
    saw. AgentContext must resolve it back for the DB query."""
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        first = query_events(ctx, {"principal": "alice@corp.example"}, limit=50)
        pseudonym = first[0]["principal"]
        second = query_events(ctx, {"principal": pseudonym}, limit=50)
    finally:
        session.close()

    assert len(second) == len(first)


# ---------------------------------------------------------------------------- get_entity_timeline


def test_get_entity_timeline_returns_events_in_window(incident_setup) -> None:
    tenant, _analysis, events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        # the incident's own entity is already pseudonymized in ctx's cache from construction
        pseudonym = ctx.pseudonymize_value("alice@corp.example", "user")
        results = get_entity_timeline(ctx, "user", pseudonym, window_minutes=60)
    finally:
        session.close()

    assert len(results) == len(events)
    assert results == sorted(results, key=lambda r: r["ts"])


def test_get_entity_timeline_unknown_entity_type_raises(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        with pytest.raises(ToolError):
            get_entity_timeline(ctx, "not_a_type", "whatever")
    finally:
        session.close()


# ---------------------------------------------------------------------------- get_entity_baseline


def test_get_entity_baseline_shape(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        pseudonym = ctx.pseudonymize_value("alice@corp.example", "user")
        result = get_entity_baseline(ctx, "user", pseudonym, "event_count")
    finally:
        session.close()

    assert set(result) == {
        "entity_type",
        "entity_value",
        "metric",
        "value",
        "baseline_mean",
        "baseline_p95",
        "z_score",
        "n_baseline_windows",
        "baseline_id",
    }
    # No prior history in this test's window -> no baseline windows -> null z_score, not NaN/inf
    assert result["n_baseline_windows"] == 0
    assert result["z_score"] is None
    # docs/v2_migration change 7's BASELINE-n citation namespace -- minted here, not invented by
    # the model.
    assert result["baseline_id"] == "BASELINE-1"


def test_get_entity_baseline_mints_sequential_citation_ids(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        pseudonym = ctx.pseudonymize_value("alice@corp.example", "user")
        first = get_entity_baseline(ctx, "user", pseudonym, "event_count")
        second = get_entity_baseline(ctx, "user", pseudonym, "bytes_out")
    finally:
        session.close()

    assert first["baseline_id"] == "BASELINE-1"
    assert second["baseline_id"] == "BASELINE-2"
    assert ctx.baseline_citations["BASELINE-1"] == first
    assert ctx.baseline_citations["BASELINE-2"] == second


def test_get_entity_baseline_rejects_unknown_metric(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        with pytest.raises(ToolError):
            get_entity_baseline(ctx, "user", "alice@corp.example", "not_a_real_metric")
    finally:
        session.close()


# ---------------------------------------------------------------------------- get_related_signals


def test_get_related_signals_includes_structured_explanation(incident_setup) -> None:
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        pseudonym = ctx.pseudonymize_value("alice@corp.example", "user")
        results = get_related_signals(ctx, "user", pseudonym)
    finally:
        session.close()

    assert len(results) == 1
    assert results[0]["detector_key"] == "signal.beaconing"
    assert results[0]["explanation"] == {"interval_s": 60, "cv": 0.02}
    assert results[0]["entity_value"].startswith("u_")  # pseudonymized, not raw


def test_get_related_signals_domain_entity_not_pseudonymized(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, analysis, events, _signal, incident = _setup_incident(tenant_cleanup)
    domain_signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil-newly-registered.example",
        detector_key="sigma.large_post_to_new_domain",
        mitre_technique="T1048.003",
        evidence_event_ids=[e.id for e in events],
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        results = get_related_signals(ctx, "domain", "evil-newly-registered.example")
    finally:
        session.close()

    assert len(results) == 1
    assert results[0]["id"] == domain_signal.id
    assert results[0]["entity_value"] == "evil-newly-registered.example"


def test_get_related_signals_exposes_log_ids_not_bare_event_ids(incident_setup) -> None:
    tenant, _analysis, events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        pseudonym = ctx.pseudonymize_value("alice@corp.example", "user")
        results = get_related_signals(ctx, "user", pseudonym)
    finally:
        session.close()

    assert len(results) == 1
    assert "evidence_event_ids" not in results[0]
    assert set(results[0]["log_ids"]) == {f"LOG-{e.raw_line_no}" for e in events}


# ---------------------------------------------------------------------------- search_mitre


def test_search_mitre_records_retrieved_techniques_on_context(incident_setup) -> None:
    """docs/v2_migration change 7 check 3 (retrieval match): a technique the Analyst pulls via
    this tool mid-investigation counts as "actually retrieved" for this run."""
    tenant, _analysis, _events, _signal, incident = incident_setup
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        assert ctx.retrieved_technique_ids == frozenset()
        results = dispatch_tool(
            ctx,
            "search_mitre",
            {"query": "beaconing periodic callback command and control", "top_k": 3},
        )
    finally:
        session.close()

    assert results  # the corpus has real beaconing-relevant techniques
    retrieved_ids = {r["id"] for r in results}
    assert ctx.retrieved_technique_ids == retrieved_ids
