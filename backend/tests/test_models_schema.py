"""Schema shape, tricky-type round trips, and structural tenant isolation for every table
docs/02-DATA-MODEL.md defines beyond `tenants`/`users`/`uploads`/`analyses` (M1),
`events` (M3, tests/test_events_model.py), and `dead_letters` (M4): `signals`, `entities`,
`entity_edges`, `incidents`, `triage_verdicts`, `analyst_feedback`, `detector_stats`,
`model_versions`, `tier2_signatures`, `eval_runs`. Runs against the real Postgres from
docker-compose.yml — no mocking, same philosophy as the rest of this test suite.

`response_plans`, `enforcement_state`, and `enforcement_journal` were dropped in
docs/v2_migration change 20 (the response action graph and enforcement plane); their coverage
was removed from this file along with them.

Every test cleans up its own rows with raw SQL, in FK-dependency order (children before
parents), rather than leaning on `tenant_cleanup`'s cascade-only sweep — several of the new
FKs (`analyst_feedback.verdict_id`/`user_id`, `incidents.recurrence_of`) carry no `ON DELETE`
action per docs/02, so a row referencing a soon-to-be-deleted parent must be removed explicitly
or the tenant/analysis cleanup itself would fail with a `ForeignKeyViolation`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.db import get_engine, get_session_factory
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import MissingTenantScopeError, tenant_scope
from app.models.detector_stats import DetectorStats
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.eval_run import EvalRun
from app.models.incident import Incident
from app.models.model_version import ModelVersion
from app.models.signal import Signal
from app.models.tier2_signature import Tier2Signature
from app.models.triage_verdict import TriageVerdict
from tests.conftest import make_analysis, make_tenant, make_user

VEC = [0.1] * 1024


def _exec(sql: str, **params: object) -> None:
    with get_engine().begin() as conn:
        conn.execute(text(sql), params)


# ------------------------------------------------------------ schema shape, exactly as docs/02


def test_signals_index_and_tenant_id_has_no_fk_or_bare_index() -> None:
    with get_engine().connect() as conn:
        index_defs = dict(
            conn.execute(
                text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'signals'")
            ).all()
        )
        fk_defs = (
            conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'signals'::regclass AND contype = 'f'"
                )
            )
            .scalars()
            .all()
        )

    assert "(analysis_id, confidence DESC)" in index_defs["ix_signals_analysis_id_confidence"]
    assert not any("tenants" in d for d in fk_defs)
    assert not any(d.rstrip().endswith("btree (tenant_id)") for d in index_defs.values())


def test_incidents_hnsw_index_and_recurrence_of_self_fk() -> None:
    with get_engine().connect() as conn:
        index_defs = dict(
            conn.execute(
                text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'incidents'")
            ).all()
        )
        fk_defs = dict(
            conn.execute(
                text(
                    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'incidents'::regclass AND contype = 'f'"
                )
            ).all()
        )

    hnsw_def = index_defs["ix_incidents_embedding_hnsw"]
    assert "USING hnsw" in hnsw_def
    assert "vector_cosine_ops" in hnsw_def
    assert "embedding" in hnsw_def

    assert fk_defs["incidents_recurrence_of_fkey"] == (
        "FOREIGN KEY (recurrence_of) REFERENCES incidents(id)"
    )
    assert not any("tenants" in d for d in fk_defs.values())
    assert not any(d.rstrip().endswith("btree (tenant_id)") for d in index_defs.values())


def test_entities_unique_constraint_on_analysis_id_type_value() -> None:
    with get_engine().connect() as conn:
        index_defs = (
            conn.execute(text("SELECT indexdef FROM pg_indexes WHERE tablename = 'entities'"))
            .scalars()
            .all()
        )
    assert any(
        "UNIQUE INDEX uq_entities_analysis_id_type_value" in d and "(analysis_id, type, value)" in d
        for d in index_defs
    )


def test_detector_stats_tenant_id_has_no_fk() -> None:
    with get_engine().connect() as conn:
        fk_defs = (
            conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'detector_stats'::regclass AND contype = 'f'"
                )
            )
            .scalars()
            .all()
        )
        assert not any("tenants" in d for d in fk_defs)

        # detector_stats' primary key is detector_key itself, per docs/02 verbatim.
        pk_cols = (
            conn.execute(
                text(
                    "SELECT a.attname FROM pg_index i "
                    "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                    "WHERE i.indrelid = 'detector_stats'::regclass AND i.indisprimary"
                )
            )
            .scalars()
            .all()
        )
        assert pk_cols == ["detector_key"]


def test_tier2_signatures_has_tenant_hash_not_tenant_id() -> None:
    """docs/02 is explicit: `tier2_signatures` carries `tenant_hash` (an HMAC), never
    `tenant_id` — the whole point being cross-tenant indicator overlap detection without
    any tenant seeing another's data. This must never be "fixed" into a tenant_id."""
    with get_engine().connect() as conn:
        columns = (
            conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'tier2_signatures'"
                )
            )
            .scalars()
            .all()
        )
    assert "tenant_hash" in columns
    assert "tenant_id" not in columns


def test_vector_columns_are_pgvector_1024() -> None:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.relname, a.atttypmod FROM pg_attribute a "
                "JOIN pg_class c ON c.oid = a.attrelid "
                "WHERE c.relname IN ('incidents', 'tier2_signatures') "
                "AND a.attname = 'embedding' AND a.attnum > 0 AND NOT a.attisdropped"
            )
        ).all()
    by_table = dict(rows)
    assert by_table["incidents"] == 1024
    assert by_table["tier2_signatures"] == 1024


# ------------------------------------------------------------ tricky-type round trips


def test_signals_evidence_event_ids_array_and_explanation_jsonb_round_trip(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Signals Roundtrip")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="signals-rt@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            signal = Signal(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                detector_key="sigma.non_browser_user_agent",
                detector_layer="rule",
                raw_score=0.91,
                confidence=0.73,
                entity_type="user",
                entity_value="u_8f3a91c204de",
                mitre_technique="T1621",
                evidence_event_ids=[1, 2, 3, 42],
                explanation={"kind": "rule", "matched": ["push_1", "push_2"]},
            )
            session.add(signal)
            session.commit()
            session.refresh(signal)

        assert signal.evidence_event_ids == [1, 2, 3, 42]
        assert signal.explanation == {"kind": "rule", "matched": ["push_1", "push_2"]}
        assert isinstance(signal.raw_score, float)
        assert signal.created_at is not None
    finally:
        session.close()


def test_incidents_embedding_vector_and_id_arrays_round_trip(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Incidents Roundtrip")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="incidents-rt@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            incident = Incident(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                title="Suspected credential stuffing",
                severity="high",
                fused_score=0.88,
                entity_ids=[10, 20, 30],
                signal_ids=[100, 200],
                embedding=VEC,
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)

        assert incident.entity_ids == [10, 20, 30]
        assert incident.signal_ids == [100, 200]
        assert incident.status == "open"
        assert incident.embedding is not None
        assert len(incident.embedding) == 1024
        assert incident.recurrence_of is None
    finally:
        session.close()


def test_incidents_recurrence_of_self_reference_round_trip(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Incidents Recurrence")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="incidents-recur@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    child_id: uuid.UUID | None = None
    parent_id: uuid.UUID | None = None
    try:
        with tenant_scope(session, tenant.id):
            parent = Incident(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                title="Original incident",
                severity="medium",
                fused_score=0.5,
                entity_ids=[],
                signal_ids=[],
            )
            session.add(parent)
            session.commit()
            session.refresh(parent)
            parent_id = parent.id

            child = Incident(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                title="Recurrence of the original",
                severity="medium",
                fused_score=0.6,
                entity_ids=[],
                signal_ids=[],
                recurrence_of=parent.id,
                recurrence_similarity=0.94,
            )
            session.add(child)
            session.commit()
            session.refresh(child)
            child_id = child.id

        assert child.recurrence_of == parent_id
        assert child.recurrence_similarity == pytest.approx(0.94)
    finally:
        session.close()
        # Delete the self-referencing child before the parent, then let tenant_cleanup
        # sweep the analysis (which cascades the parent) — recurrence_of has no ON
        # DELETE action per docs/02, so order matters here.
        if child_id is not None:
            _exec("DELETE FROM incidents WHERE id = :id", id=str(child_id))


def test_entities_unique_constraint_raises_on_duplicate(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Entities Unique")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="entities-unique@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        session.add(Entity(analysis_id=analysis.id, type="src_ip", value="10.0.0.7"))
        session.commit()

        session.add(Entity(analysis_id=analysis.id, type="src_ip", value="10.0.0.7"))
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_entities_and_entity_edges_round_trip(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant(name="Entity Graph")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="entity-graph@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        src = Entity(
            analysis_id=analysis.id,
            type="user",
            value="u_8f3a91c204de",
            event_count=12,
            risk_score=0.4,
            attrs={"department": "eng"},
        )
        dst = Entity(analysis_id=analysis.id, type="dst_ip", value="203.0.113.9")
        session.add_all([src, dst])
        session.flush()

        edge = EntityEdge(
            analysis_id=analysis.id,
            src_entity_id=src.id,
            dst_entity_id=dst.id,
            relation="connected_to",
            weight=2.5,
            event_count=7,
        )
        session.add(edge)
        session.commit()
        session.refresh(edge)
        session.refresh(src)

        assert edge.src_entity_id == src.id
        assert edge.dst_entity_id == dst.id
        assert edge.weight == pytest.approx(2.5)
        assert src.attrs == {"department": "eng"}
        assert src.event_count == 12
    finally:
        session.close()


def test_triage_verdicts_round_trip(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Triage Response")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="triage-response@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            incident = Incident(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                title="Data exfil via DNS tunneling",
                severity="critical",
                fused_score=0.95,
                entity_ids=[1],
                signal_ids=[1],
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)
        incident_id = incident.id

        verdict = TriageVerdict(
            incident_id=incident_id,
            disposition="malicious",
            confidence=0.9,
            llm_severity_opinion="critical",
            mitre_techniques={"techniques": ["T1071.004"]},
            summary="DNS tunneling detected from host X.",
            narrative=[{"step": 1, "claim": "beaconing", "evidence_event_ids": [1, 2]}],
            recommended_actions=["Isolate host X pending IT confirmation."],
            tool_trace=[{"tool": "search_events", "args": {}}],
            citation_valid=True,
            model="claude-opus",
            tokens_in=1200,
            tokens_out=340,
            cost_usd=Decimal("0.012345"),
            latency_ms=2100,
        )
        session.add(verdict)
        session.commit()
        session.refresh(verdict)

        assert verdict.mitre_techniques == {"techniques": ["T1071.004"]}
        assert verdict.invalid_citations == []
        assert verdict.cost_usd == Decimal("0.012345")
        assert verdict.recommended_actions == ["Isolate host X pending IT confirmation."]
        verdict_id = verdict.id
    finally:
        session.close()
        _exec("DELETE FROM triage_verdicts WHERE id = :id", id=str(verdict_id))


def test_analyst_feedback_round_trip(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant(name="Analyst Feedback")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="analyst-feedback@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    feedback_id: uuid.UUID | None = None
    verdict_id: uuid.UUID | None = None
    try:
        with tenant_scope(session, tenant.id):
            incident = Incident(
                analysis_id=analysis.id,
                tenant_id=tenant.id,
                title="False positive candidate",
                severity="low",
                fused_score=0.2,
                entity_ids=[],
                signal_ids=[],
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)

        verdict = TriageVerdict(
            incident_id=incident.id,
            disposition="benign",
            confidence=0.3,
            mitre_techniques={},
            summary="Looks like scheduled maintenance.",
            narrative=[],
            recommended_actions=[],
            tool_trace=[],
            citation_valid=True,
            model="claude-opus",
        )
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
        verdict_id = verdict.id

        feedback = AnalystFeedback(
            verdict_id=verdict.id,
            user_id=user.id,
            agrees=False,
            corrected_disposition="malicious",
            corrected_technique="T1078",
            dismissal_reason=None,
            mark_benign_baseline=False,
            note="Actually matches last week's incident.",
        )
        session.add(feedback)
        session.commit()
        session.refresh(feedback)
        feedback_id = feedback.id

        assert feedback.agrees is False
        assert feedback.corrected_disposition == "malicious"
        assert feedback.mark_benign_baseline is False
        assert feedback.created_at is not None
    finally:
        session.close()
        if feedback_id is not None:
            _exec("DELETE FROM analyst_feedback WHERE id = :id", id=str(feedback_id))
        if verdict_id is not None:
            _exec("DELETE FROM triage_verdicts WHERE id = :id", id=str(verdict_id))


def test_detector_stats_pk_is_detector_key_and_defaults(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Detector Stats")
    tenant_cleanup.append(tenant.id)
    detector_key = f"ml.mahalanobis.{uuid.uuid4()}"

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            stats = DetectorStats(detector_key=detector_key, tenant_id=tenant.id)
            session.add(stats)
            session.commit()
            session.refresh(stats)

            assert stats.true_positives == 0
            assert stats.false_positives == 0
            assert stats.fusion_weight == pytest.approx(1.0)
    finally:
        session.close()
        _exec("DELETE FROM detector_stats WHERE detector_key = :k", k=detector_key)


def test_model_versions_unique_constraint(tenant_cleanup: list[uuid.UUID]) -> None:
    model_key = f"lightgbm-{uuid.uuid4()}"
    session = get_session_factory()()
    ids: list[uuid.UUID] = []
    try:
        mv1 = ModelVersion(
            model_key=model_key,
            version=1,
            artifact_ref="s3://models/lgbm/v1",
            trained_at=datetime.now(UTC),
            eval_scores={"auc": 0.91},
            promoted=True,
        )
        session.add(mv1)
        session.commit()
        session.refresh(mv1)
        ids.append(mv1.id)

        assert mv1.promoted is True
        assert mv1.eval_scores == {"auc": 0.91}

        mv_dupe = ModelVersion(
            model_key=model_key,
            version=1,
            artifact_ref="s3://models/lgbm/v1-again",
            trained_at=datetime.now(UTC),
            eval_scores={},
        )
        session.add(mv_dupe)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
    finally:
        session.close()
        for mid in ids:
            _exec("DELETE FROM model_versions WHERE id = :id", id=str(mid))


def test_tier2_signatures_arrays_and_vector_round_trip() -> None:
    session = get_session_factory()()
    sig_id: uuid.UUID | None = None
    try:
        sig = Tier2Signature(
            tenant_hash="h_shared_salt_abc123",
            incident_type="c2_beacon",
            mitre_techniques=["T1071", "T1041"],
            source_types=["zscaler", "endpoint"],
            confidence=0.82,
            indicator_hashes=["h_domain_1", "h_ip_1"],
            observed_at=datetime.now(UTC),
            embedding=VEC,
        )
        session.add(sig)
        session.commit()
        session.refresh(sig)
        sig_id = sig.id

        assert sig.mitre_techniques == ["T1071", "T1041"]
        assert sig.source_types == ["zscaler", "endpoint"]
        assert sig.indicator_hashes == ["h_domain_1", "h_ip_1"]
        assert sig.embedding is not None
        assert len(sig.embedding) == 1024
    finally:
        session.close()
        if sig_id is not None:
            _exec("DELETE FROM tier2_signatures WHERE id = :id", id=str(sig_id))


def test_eval_runs_round_trip() -> None:
    session = get_session_factory()()
    run_id: uuid.UUID | None = None
    try:
        run = EvalRun(
            git_sha="a" * 40,
            metrics={"precision": 0.95, "recall": 0.88},
            passed=True,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

        assert run.metrics == {"precision": 0.95, "recall": 0.88}
        assert run.passed is True
        assert run.created_at is not None
    finally:
        session.close()
        if run_id is not None:
            _exec("DELETE FROM eval_runs WHERE id = :id", id=str(run_id))


# ------------------------------------------------------------ structural tenant isolation


def test_bare_session_raises_instead_of_leaking_signals(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant(name="Bare Session Signals")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="bare-signals@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            session.add(
                Signal(
                    analysis_id=analysis.id,
                    tenant_id=tenant.id,
                    detector_key="rule.test",
                    detector_layer="rule",
                    raw_score=0.5,
                    confidence=0.5,
                    entity_type="user",
                    entity_value="u_x",
                    evidence_event_ids=[],
                    explanation={},
                )
            )
            session.commit()
    finally:
        session.close()

    bare_session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            bare_session.execute(select(Signal))
    finally:
        bare_session.close()


def test_tenant_scoped_session_sees_only_its_own_signals(
    tenant_cleanup: list[uuid.UUID],
) -> None:

    tenant_a = make_tenant(name="Signals Tenant A")
    tenant_b = make_tenant(name="Signals Tenant B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="signals-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="signals-b@example.com")
    analysis_a = make_analysis(tenant_id=tenant_a.id, user_id=user_a.id, filename="a.log")
    analysis_b = make_analysis(tenant_id=tenant_b.id, user_id=user_b.id, filename="b.log")

    def _make_signal(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        session = get_session_factory()()
        try:
            with tenant_scope(session, tenant_id):
                session.add(
                    Signal(
                        analysis_id=analysis_id,
                        tenant_id=tenant_id,
                        detector_key="rule.test",
                        detector_layer="rule",
                        raw_score=0.5,
                        confidence=0.5,
                        entity_type="user",
                        entity_value="u_x",
                        evidence_event_ids=[],
                        explanation={},
                    )
                )
                session.commit()
        finally:
            session.close()

    _make_signal(analysis_a.id, tenant_a.id)
    _make_signal(analysis_b.id, tenant_b.id)
    _make_signal(analysis_b.id, tenant_b.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            rows = session.execute(select(Signal)).scalars().all()
    finally:
        session.close()

    assert len(rows) == 1
    assert all(r.tenant_id == tenant_a.id for r in rows)


def test_cannot_fetch_another_tenants_signal_even_by_primary_key(
    tenant_cleanup: list[uuid.UUID],
) -> None:

    tenant_a = make_tenant(name="PK Signals A")
    tenant_b = make_tenant(name="PK Signals B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_b = make_user(tenant_id=tenant_b.id, email="pk-signals-b@example.com")
    analysis_b = make_analysis(tenant_id=tenant_b.id, user_id=user_b.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_b.id):
            signal = Signal(
                analysis_id=analysis_b.id,
                tenant_id=tenant_b.id,
                detector_key="rule.test",
                detector_layer="rule",
                raw_score=0.5,
                confidence=0.5,
                entity_type="user",
                entity_value="u_x",
                evidence_event_ids=[],
                explanation={},
            )
            session.add(signal)
            session.commit()
            session.refresh(signal)
            other_signal_id = signal.id
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            result = session.execute(
                select(Signal).where(Signal.id == other_signal_id)
            ).scalar_one_or_none()
    finally:
        session.close()
    assert result is None


def test_bare_session_raises_instead_of_leaking_incidents(
    tenant_cleanup: list[uuid.UUID],
) -> None:

    tenant = make_tenant(name="Bare Session Incidents")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="bare-incidents@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            session.add(
                Incident(
                    analysis_id=analysis.id,
                    tenant_id=tenant.id,
                    title="x",
                    severity="low",
                    fused_score=0.1,
                    entity_ids=[],
                    signal_ids=[],
                )
            )
            session.commit()
    finally:
        session.close()

    bare_session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            bare_session.execute(select(Incident))
    finally:
        bare_session.close()


def test_tenant_scoped_session_sees_only_its_own_incidents(
    tenant_cleanup: list[uuid.UUID],
) -> None:

    tenant_a = make_tenant(name="Incidents Tenant A")
    tenant_b = make_tenant(name="Incidents Tenant B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="incidents-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="incidents-b@example.com")
    analysis_a = make_analysis(tenant_id=tenant_a.id, user_id=user_a.id, filename="a.log")
    analysis_b = make_analysis(tenant_id=tenant_b.id, user_id=user_b.id, filename="b.log")

    def _make_incident(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        session = get_session_factory()()
        try:
            with tenant_scope(session, tenant_id):
                session.add(
                    Incident(
                        analysis_id=analysis_id,
                        tenant_id=tenant_id,
                        title="x",
                        severity="low",
                        fused_score=0.1,
                        entity_ids=[],
                        signal_ids=[],
                    )
                )
                session.commit()
        finally:
            session.close()

    _make_incident(analysis_a.id, tenant_a.id)
    _make_incident(analysis_b.id, tenant_b.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            rows = session.execute(select(Incident)).scalars().all()
    finally:
        session.close()

    assert len(rows) == 1
    assert all(r.tenant_id == tenant_a.id for r in rows)


def test_cannot_fetch_another_tenants_incident_even_by_primary_key(
    tenant_cleanup: list[uuid.UUID],
) -> None:

    tenant_a = make_tenant(name="PK Incidents A")
    tenant_b = make_tenant(name="PK Incidents B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_b = make_user(tenant_id=tenant_b.id, email="pk-incidents-b@example.com")
    analysis_b = make_analysis(tenant_id=tenant_b.id, user_id=user_b.id)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_b.id):
            incident = Incident(
                analysis_id=analysis_b.id,
                tenant_id=tenant_b.id,
                title="x",
                severity="low",
                fused_score=0.1,
                entity_ids=[],
                signal_ids=[],
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)
            other_incident_id = incident.id
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_a.id):
            result = session.execute(
                select(Incident).where(Incident.id == other_incident_id)
            ).scalar_one_or_none()
    finally:
        session.close()
    assert result is None
