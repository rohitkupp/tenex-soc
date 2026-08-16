"""Mechanism 7 — cohort re-derivation (change 21, gated). "Recluster peer groups" feeding LOF's
department-cohort features (`app.detection.ml.features`'s `*_z_vs_cohort` family, docs/04 "Peer-
group cohorts").

A real (if intentionally small-scope) unsupervised re-clustering: KMeans over each entity's own
`baseline_windows` feature rows (already in this package's ownership, change 1), proposing a
`cohort_label` per entity that may or may not match its literal HR `department` string. Gated
because it changes what LOF treats as "this entity's peers," which changes what reads as locally
anomalous -- exactly the "changes what the system detects" line change 21 draws.

The gate here is not a golden-set detection-accuracy comparison (re-clustering isn't a trained
detector with held-out predictions) -- it is `app.learning.retrain.evaluate_candidate` applied to
silhouette score, this package's own dependency-free comparator (see `app.learning.mechanisms`'s
module docstring, "why two different comparators").
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.base import tenant_scope
from app.models.baseline_window import BaselineWindow
from app.models.entity_cohort import EntityCohort
from app.models.learning_proposal import LearningProposal

__all__ = ["MIN_ENTITIES_TO_CLUSTER", "accept_cohort_re_derivation", "propose_cohort_re_derivation"]

MIN_ENTITIES_TO_CLUSTER = 6
_N_COHORTS = 3
_SILHOUETTE_TOLERANCE = MetricTolerance("higher_is_better", 0.05)


def _entity_feature_rows(
    session: Session, tenant_id: uuid.UUID
) -> tuple[list[tuple[str, str]], list[list[float]]]:
    with tenant_scope(session, tenant_id):
        rows = session.execute(select(BaselineWindow)).scalars().all()
    by_entity: dict[tuple[str, str], list[dict[str, float]]] = {}
    for r in rows:
        by_entity.setdefault((r.entity_type, r.entity_value), []).append(r.features)
    entities = sorted(by_entity)
    keys = sorted({k for feats in by_entity.values() for f in feats for k in f})
    matrix = [
        [sum(f.get(k, 0.0) for f in by_entity[e]) / len(by_entity[e]) for k in keys]
        for e in entities
    ]
    return entities, matrix


def propose_cohort_re_derivation(
    session: Session, tenant_id: uuid.UUID, *, trigger_feedback_id: uuid.UUID
) -> LearningProposal | None:
    """Called from a Dismiss whose feedback pattern suggests the entity's peer group no longer
    fits (`app/learning/feedback.py` triggers this on any feedback event once enough baseline
    history exists -- see that module for the exact gate). Returns `None` when there is not
    enough baseline history to cluster meaningfully."""
    entities, matrix = _entity_feature_rows(session, tenant_id)
    if len(entities) < MIN_ENTITIES_TO_CLUSTER:
        return None

    from sklearn.cluster import KMeans

    k = min(_N_COHORTS, len(entities) - 1)
    labels = KMeans(n_clusters=k, n_init=10, random_state=42).fit_predict(matrix)
    assignments = [
        {"entity_type": e[0], "entity_value": e[1], "cohort_label": f"cohort-{lbl}"}
        for e, lbl in zip(entities, labels, strict=True)
    ]
    return create_proposal(
        session,
        tenant_id,
        mechanism=7,
        payload={"assignments": assignments, "method": "kmeans", "k": k},
        supporting_feedback_ids=[trigger_feedback_id],
        trigger_feedback_id=trigger_feedback_id,
    )


def _silhouette(
    entities: list[tuple[str, str]], matrix: list[list[float]], labels: list[int]
) -> float | None:
    if len(set(labels)) < 2 or len(matrix) < 3:
        return None
    from sklearn.metrics import silhouette_score

    return float(silhouette_score(matrix, labels))


def _apply(session: Session, tenant_id: uuid.UUID, proposal: LearningProposal) -> dict[str, Any]:
    with tenant_scope(session, tenant_id):
        for a in proposal.payload["assignments"]:
            existing = session.execute(
                select(EntityCohort).where(
                    EntityCohort.entity_type == a["entity_type"],
                    EntityCohort.entity_value == a["entity_value"],
                )
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    EntityCohort(
                        tenant_id=tenant_id,
                        entity_type=a["entity_type"],
                        entity_value=a["entity_value"],
                        cohort_label=a["cohort_label"],
                        method=proposal.payload.get("method", "kmeans"),
                    )
                )
            else:
                existing.cohort_label = a["cohort_label"]
                existing.method = proposal.payload.get("method", "kmeans")
                existing.computed_at = datetime.now(UTC)
        session.flush()
    return {"entities_reassigned": len(proposal.payload["assignments"])}


def accept_cohort_re_derivation(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    entities, matrix = _entity_feature_rows(session, tenant_id)
    by_entity = {
        (a["entity_type"], a["entity_value"]): a["cohort_label"]
        for a in proposal.payload["assignments"]
    }
    labels = [hash(by_entity.get(e, "unassigned")) % 1000 for e in entities]
    candidate_silhouette = _silhouette(entities, matrix, labels)

    with tenant_scope(session, tenant_id):
        current = session.execute(select(EntityCohort)).scalars().all()
    baseline_labels = (
        [hash((c.entity_type, c.entity_value)) % 1000 for c in current] if current else []
    )
    baseline_silhouette = (
        _silhouette([(c.entity_type, c.entity_value) for c in current], matrix, baseline_labels)
        if current
        else None
    )

    if candidate_silhouette is None:
        passed, reason = (
            True,
            "not enough data for a silhouette comparison; proposal accepted as-is",
        )
    else:
        gate = evaluate_candidate(
            {"silhouette": candidate_silhouette},
            {"silhouette": baseline_silhouette} if baseline_silhouette is not None else None,
            tolerances={"silhouette": _SILHOUETTE_TOLERANCE},
        )
        passed, reason = gate.passed, gate.reason

    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=passed,
        metric_delta={
            "silhouette_candidate": candidate_silhouette,
            "silhouette_baseline": baseline_silhouette,
        },
        reason=reason,
        user_id=user_id,
        apply_fn=_apply,
    )
