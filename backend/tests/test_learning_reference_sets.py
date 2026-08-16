"""`app.learning.reference_sets` — mechanisms 4 and 5 (change 21): "the interesting ones,"
because kNN/LOF are instance-based and their reference set changes immediately, with no training
loop. This module tests the real state change against real, small, `pyod`-fitted artifacts, not
mocks -- `KNNArtifact.fit`/`LOFArtifact.fit` are the same classes `app/detection/ml/train.py`
writes to `backend/data/models/` in production, pointed at a `tmp_path` instead.
"""

from __future__ import annotations

import uuid

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.ml.detect import ML_KTH_NN, ML_PEER_GROUP
from app.detection.ml.knn import KNN_ARTIFACT_FILENAME, KNNArtifact
from app.detection.ml.lof import LOF_ARTIFACT_FILENAME, LOFArtifact
from app.learning.reference_sets import (
    ReferenceSetWindow,
    add_to_reference_set,
    exclude_from_reference_set,
)
from app.models.base import tenant_scope
from app.models.learning_event import LearningEvent
from app.models.reference_set_exclusion import ReferenceSetExclusion
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def _make_feedback_with_real_verdict(
    session: Session, *, tenant_id: uuid.UUID, user_id: uuid.UUID, agrees: bool, **kwargs
):
    """`analyst_feedback.verdict_id` is a real `REFERENCES triage_verdicts(id)` FK (docs/02) --
    these tests only need a feedback row that exists and points somewhere valid, not a realistic
    incident, so this builds the minimal chain (`analysis` -> `signal` -> `incident` ->
    `verdict`) once rather than repeating it in every test below."""
    analysis = make_analysis(tenant_id=tenant_id, user_id=user_id)
    sig = make_signal(session, tenant_id=tenant_id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        session, tenant_id=tenant_id, analysis_id=analysis.id, signals=[sig]
    )
    return make_feedback(session, verdict_id=verdict.id, user_id=user_id, agrees=agrees, **kwargs)


_DIM = 5
_RNG = np.random.default_rng(7)


def _write_artifacts(tmp_path):
    """A small benign cluster (std normal around the origin) -- the reference set every test
    below starts from."""
    benign = _RNG.normal(size=(60, _DIM))
    calib = _RNG.normal(size=(20, _DIM))
    knn = KNNArtifact.fit(benign, calib, n_neighbors=5, space="full")
    lof = LOFArtifact.fit(benign, calib, n_neighbors=5, space="full")
    knn.save(tmp_path / KNN_ARTIFACT_FILENAME)
    lof.save(tmp_path / LOF_ARTIFACT_FILENAME)
    return benign


def _knn_score(tmp_path, row: np.ndarray) -> float:
    artifact = KNNArtifact.load(tmp_path / KNN_ARTIFACT_FILENAME)
    return float(artifact.raw_scores(row.reshape(1, -1))[0])


def _lof_score(tmp_path, row: np.ndarray) -> float:
    artifact = LOFArtifact.load(tmp_path / LOF_ARTIFACT_FILENAME)
    return float(artifact.raw_scores(row.reshape(1, -1))[0])


def test_add_to_reference_set_grows_both_instance_models_and_logs_mechanism_4(
    tmp_path,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    _write_artifacts(tmp_path)
    tenant = make_tenant(name="Reference Set Add Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"refset-add-{uuid.uuid4()}@test.local")
    feedback = _make_feedback_with_real_verdict(
        learning_session,
        tenant_id=tenant.id,
        user_id=user.id,
        agrees=False,
        dismissal_reason="known sanctioned scanner",
        mark_benign_baseline=True,
    )
    learning_session.commit()

    knn_before = len(KNNArtifact.load(tmp_path / KNN_ARTIFACT_FILENAME).model.neigh_._fit_X)
    lof_before = len(LOFArtifact.load(tmp_path / LOF_ARTIFACT_FILENAME).model.detector_._fit_X)

    benign_row = _RNG.normal(size=_DIM)  # squarely inside the cluster we just fit against
    window = ReferenceSetWindow("src_ip", "10.0.0.9", None, None)
    mutations = add_to_reference_set(
        learning_session,
        tenant.id,
        window=window,
        feature_row=benign_row,
        trigger_feedback_id=feedback.id,
        models_dir=tmp_path,
    )
    learning_session.commit()

    by_key = {m.detector_key: m for m in mutations}
    assert by_key[ML_KTH_NN].action == "added"
    assert by_key[ML_PEER_GROUP].action == "added"

    knn_after = len(KNNArtifact.load(tmp_path / KNN_ARTIFACT_FILENAME).model.neigh_._fit_X)
    lof_after = len(LOFArtifact.load(tmp_path / LOF_ARTIFACT_FILENAME).model.detector_._fit_X)
    assert knn_after == knn_before + 1
    assert lof_after == lof_before + 1

    event = (
        learning_session.execute(select(LearningEvent).where(LearningEvent.mechanism == 4))
        .scalars()
        .one()
    )
    assert event.applied is True
    assert event.trigger_feedback_id == feedback.id


def test_contamination_exclusion_reverses_the_score_drop_it_caused(
    tmp_path,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The dedicated test change 25 requires: confirm a true positive, then assert a *similar*
    window's score did not drop. Concretely: an attack point scores clearly anomalous against a
    clean benign reference set; contaminating that set with the attack point itself drags a
    *similar* point's score down (the classic instance-based failure mode); confirming the
    contaminating point as a true positive must remove it and the similar point's score must
    recover to at least its pre-contamination level -- it must not stay artificially low.
    """
    _write_artifacts(tmp_path)
    tenant = make_tenant(name="Contamination Exclusion Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"contam-{uuid.uuid4()}@test.local")
    feedback = _make_feedback_with_real_verdict(
        learning_session,
        tenant_id=tenant.id,
        user_id=user.id,
        agrees=True,
        corrected_disposition="true_positive",
    )
    learning_session.commit()

    # An "attack" point, well outside the benign cluster on every axis.
    attack_point = np.full(_DIM, 8.0)
    # A *similar* (not identical) attack window -- what a follow-on, related attack would produce.
    similar_point = attack_point + _RNG.normal(scale=0.05, size=_DIM)

    clean_knn_score = _knn_score(tmp_path, similar_point)
    clean_lof_score = _lof_score(tmp_path, similar_point)

    # Contaminate: simulate the attack point having previously been (wrongly) added to the
    # reference set as if it were benign.
    window = ReferenceSetWindow("user", "alice@example.com", None, None)
    add_to_reference_set(
        learning_session,
        tenant.id,
        window=window,
        feature_row=attack_point,
        trigger_feedback_id=feedback.id,
        models_dir=tmp_path,
    )
    learning_session.commit()

    contaminated_knn_score = _knn_score(tmp_path, similar_point)
    contaminated_lof_score = _lof_score(tmp_path, similar_point)
    # The contaminating point is now the similar point's nearest neighbour -- both models must
    # report the similar point as measurably *less* anomalous than against the clean set.
    assert contaminated_knn_score < clean_knn_score
    assert contaminated_lof_score < clean_lof_score

    # Confirm the contaminating window as a true positive -> mechanism 5 must exclude it.
    exclude_from_reference_set(
        learning_session,
        tenant.id,
        window=window,
        feature_row=attack_point,
        feedback=feedback,
        trigger_feedback_id=feedback.id,
        models_dir=tmp_path,
    )
    learning_session.commit()

    recovered_knn_score = _knn_score(tmp_path, similar_point)
    recovered_lof_score = _lof_score(tmp_path, similar_point)

    # The core assertion: the similar window's score did not stay dropped. It must recover to at
    # least the clean baseline (it may even exceed it slightly due to the refit's tree
    # rebalancing, which is fine -- "did not drop" is the requirement, not exact equality).
    assert recovered_knn_score >= clean_knn_score - 1e-9
    assert recovered_lof_score >= clean_lof_score - 1e-9
    assert recovered_knn_score > contaminated_knn_score
    assert recovered_lof_score > contaminated_lof_score

    with tenant_scope(learning_session, tenant.id):
        exclusion = learning_session.execute(select(ReferenceSetExclusion)).scalars().one()
    assert exclusion.entity_value == "alice@example.com"
    assert "ml.eif" in exclusion.models

    event = (
        learning_session.execute(select(LearningEvent).where(LearningEvent.mechanism == 5))
        .scalars()
        .one()
    )
    assert event.applied is True


def test_confirmed_true_positive_is_not_added_to_the_reference_set(
    tmp_path,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The other half of change 25's dedicated test: a confirmed true positive must never enter
    the reference/training pool in the first place. `app.learning.feedback.record_feedback`
    routes a true-positive confirmation to `exclude_from_reference_set`, never to
    `add_to_reference_set` -- this asserts that at the mechanism level: calling exclude on a
    window that was never added leaves the reference set exactly the size it started at (no
    accidental growth), which is what "must not enter the reference set" means operationally for
    an instance-based model with no separate 'training set' to keep clean.
    """
    _write_artifacts(tmp_path)
    tenant = make_tenant(name="TP Never Added Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"tp-never-added-{uuid.uuid4()}@test.local")
    feedback = _make_feedback_with_real_verdict(
        learning_session,
        tenant_id=tenant.id,
        user_id=user.id,
        agrees=True,
        corrected_disposition="true_positive",
    )
    learning_session.commit()

    knn_before = len(KNNArtifact.load(tmp_path / KNN_ARTIFACT_FILENAME).model.neigh_._fit_X)
    lof_before = len(LOFArtifact.load(tmp_path / LOF_ARTIFACT_FILENAME).model.detector_._fit_X)

    attack_point = np.full(_DIM, 9.0)
    window = ReferenceSetWindow("user", "mallory@example.com", None, None)
    exclude_from_reference_set(
        learning_session,
        tenant.id,
        window=window,
        feature_row=attack_point,
        feedback=feedback,
        trigger_feedback_id=feedback.id,
        models_dir=tmp_path,
    )
    learning_session.commit()

    knn_after = len(KNNArtifact.load(tmp_path / KNN_ARTIFACT_FILENAME).model.neigh_._fit_X)
    lof_after = len(LOFArtifact.load(tmp_path / LOF_ARTIFACT_FILENAME).model.detector_._fit_X)
    assert knn_after == knn_before
    assert lof_after == lof_before
