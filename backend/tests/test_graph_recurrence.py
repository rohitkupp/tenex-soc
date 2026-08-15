"""Tests for `app.graph.recurrence` (docs/05 "Recurrence detection").

`canonical_text`/`embed_text` are pure and DB-free. `cosine_search`/`link_recurrence` need a real
`incidents` row with a real `embedding` to search against, so those run against the live
Postgres from `docker-compose.yml`, same convention as the rest of this test suite
(`tests/conftest.py`).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest

from app.core.db import get_session_factory
from app.graph.recurrence import (
    EMBEDDING_DIMS,
    RECURRENCE_SIMILARITY_THRESHOLD,
    canonical_text,
    cosine_search,
    embed_text,
    link_recurrence,
)
from app.models.base import tenant_scope
from app.models.incident import Incident
from tests.conftest import make_analysis, make_tenant, make_user


def test_canonical_text_is_sorted_and_deduplicated() -> None:
    text = canonical_text(
        technique_ids=["T1071.001", "T1071.001", "T1090"],
        detector_keys=["signal.beaconing"],
        entity_types=["user", "domain"],
        enrichment_tags=["high_risk_tld"],
    )
    tokens = text.split(" ")
    assert tokens == sorted(tokens)
    assert len(tokens) == len(set(tokens))
    assert "technique:T1071.001" in tokens
    assert tokens.count("technique:T1071.001") == 1


def test_canonical_text_never_includes_raw_entity_values() -> None:
    """docs/05: structural similarity, not identity -- entity *values* must never leak into the
    canonical text, only entity *types*."""
    text = canonical_text(
        technique_ids=["T1071.001"],
        detector_keys=["signal.beaconing"],
        entity_types=["user"],
        enrichment_tags=[],
    )
    assert "alice@corp.example" not in text


def test_canonical_text_drops_none_technique() -> None:
    text = canonical_text(
        technique_ids=[None, "T1071.001"],
        detector_keys=[],
        entity_types=[],
        enrichment_tags=[],
    )
    assert text == "technique:T1071.001"


def test_embed_text_is_deterministic() -> None:
    text = canonical_text(
        technique_ids=["T1071.001"],
        detector_keys=["signal.beaconing", "ml.autoencoder"],
        entity_types=["user", "domain"],
        enrichment_tags=["high_risk_tld"],
    )
    assert embed_text(text) == embed_text(text)


def test_embed_text_has_the_documented_dimensionality() -> None:
    assert len(embed_text("technique:T1071.001")) == EMBEDDING_DIMS == 1024


def test_embed_text_similar_incidents_are_closer_than_dissimilar_ones() -> None:
    import numpy as np

    def cos_sim(a: list[float], b: list[float]) -> float:
        av, bv = np.array(a), np.array(b)
        denom = np.linalg.norm(av) * np.linalg.norm(bv)
        return float(np.dot(av, bv) / denom) if denom else 0.0

    beacon_a = embed_text(
        canonical_text(
            technique_ids=["T1071.001"],
            detector_keys=["signal.beaconing", "signal.dga"],
            entity_types=["user", "domain"],
            enrichment_tags=[],
        )
    )
    beacon_b = embed_text(
        canonical_text(
            technique_ids=["T1071.001"],
            detector_keys=["signal.beaconing", "signal.dga"],
            entity_types=["user", "domain"],
            enrichment_tags=[],
        )
    )
    exfil = embed_text(
        canonical_text(
            technique_ids=["T1567.002"],
            detector_keys=["signal.burst", "ml.autoencoder"],
            entity_types=["user", "dst_ip"],
            enrichment_tags=["high_risk_tld"],
        )
    )
    assert cos_sim(beacon_a, beacon_b) > cos_sim(beacon_a, exfil)


def test_embed_text_empty_string_is_zero_vector() -> None:
    assert embed_text("") == [0.0] * EMBEDDING_DIMS


# ---------------------------------------------------------------------------- DB-backed


@pytest.fixture
def tenant_and_analysis(tenant_cleanup: list[uuid.UUID]) -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"recurrence-{uuid.uuid4().hex[:8]}@corp.example")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    yield tenant.id, analysis.id


def _make_incident(
    *, tenant_id: uuid.UUID, analysis_id: uuid.UUID, embedding: list[float], title: str = "test"
) -> Incident:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            incident = Incident(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                title=title,
                severity="low",
                fused_score=0.5,
                entity_ids=[],
                signal_ids=[],
                embedding=embedding,
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)
        return incident
    finally:
        session.close()


def test_cosine_search_finds_the_closer_prior_incident(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    query_text = canonical_text(
        technique_ids=["T1071.001"],
        detector_keys=["signal.beaconing"],
        entity_types=["user"],
        enrichment_tags=[],
    )
    query_embedding = embed_text(query_text)
    close = _make_incident(
        tenant_id=tenant_id, analysis_id=analysis_id, embedding=query_embedding, title="close"
    )
    far_embedding = embed_text(
        canonical_text(
            technique_ids=["T1530"],
            detector_keys=["signal.burst"],
            entity_types=["src_ip"],
            enrichment_tags=["anonymizer"],
        )
    )
    _make_incident(
        tenant_id=tenant_id, analysis_id=analysis_id, embedding=far_embedding, title="far"
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            results = cosine_search(session, query_embedding, limit=5)
    finally:
        session.close()

    assert results
    assert results[0][0].id == close.id
    assert results[0][1] == pytest.approx(1.0, abs=1e-4)


def test_link_recurrence_links_above_threshold(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    embedding = embed_text(
        canonical_text(
            technique_ids=["T1071.001"],
            detector_keys=["signal.beaconing"],
            entity_types=["user"],
            enrichment_tags=[],
        )
    )
    parent = _make_incident(
        tenant_id=tenant_id, analysis_id=analysis_id, embedding=embedding, title="parent"
    )

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            link = link_recurrence(session, embedding)
    finally:
        session.close()

    assert link is not None
    assert link.recurrence_of == parent.id
    assert link.recurrence_similarity >= RECURRENCE_SIMILARITY_THRESHOLD


def test_link_recurrence_excludes_its_own_id(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    embedding = embed_text("technique:T1071.001")
    incident = _make_incident(tenant_id=tenant_id, analysis_id=analysis_id, embedding=embedding)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            link = link_recurrence(session, embedding, exclude_incident_id=incident.id)
    finally:
        session.close()

    assert link is None


def test_link_recurrence_below_threshold_returns_none(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    _make_incident(
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        embedding=embed_text("technique:T1071.001 detector:signal.beaconing"),
    )
    dissimilar = embed_text("technique:T1530 detector:signal.burst tag:anonymizer entity:src_ip")

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            link = link_recurrence(session, dissimilar)
    finally:
        session.close()

    assert link is None
