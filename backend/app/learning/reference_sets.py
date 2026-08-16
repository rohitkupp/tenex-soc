"""Mechanisms 4 and 5 — reference set curation and contamination exclusion (change 21,
both auto-apply). "Exist only because the autoencoder is gone... the interesting ones": kNN
(`ml.kth_nn`) and LOF (`ml.peer_group`) are instance-based -- they score a window against stored
reference points, not learned weights, so their state can change **immediately, with no training
loop**, by mutating the reference-point matrix a fitted `pyod` model already carries
(`model.neigh_._fit_X` for kNN, `model.detector_._fit_X` for LOF -- both already read by each
artifact's own `explain_row`, `app.detection.ml.knn`/`app.detection.ml.lof`).

## What "no training loop" means precisely here

Simply appending a row to `_fit_X` would not update the fitted ball-tree/kd-tree `sklearn`
actually queries at scoring time -- the tree is built once, at `fit()`. The honest way to add or
remove one point is to **refit** the wrapped `sklearn` estimator on the concatenated (or
filtered) point matrix: `model.fit(np.vstack([existing_fit_X, new_row]))`. That is an O(n log n)
tree rebuild over already-in-memory data, not a gradient-descent training run and not the
golden-set-gated retrain change 21 reserves for EIF (mechanism 6/7's own "refit: yes" column) --
which is the actual distinction this mechanism pair is making, not a literal O(1) claim.

## The reference-set-exclusion state EIF also needs

EIF (`ml.eif`) is not instance-based, so mechanism 5 cannot mutate its artifact directly the way
it mutates kNN/LOF's; change 21's own table says EIF's exclusion applies "none / next refit."
`exclude_from_reference_set` always writes a `reference_set_exclusions` row regardless of whether
a live artifact mutation was possible, so a future EIF retrain (mechanism 6) has a durable record
of which windows must never re-enter its training pool.

## Where the feature vector comes from, and the honest limit of this integration

Both functions below take an explicit, already-scaled feature row (`npt.NDArray[np.float64]`,
`app.detection.ml.features.ENTITY_WINDOW_MODEL_FEATURES` order, post-`StandardScaler` -- the same
input `app.detection.ml.detect.MLModelBundle.transform` produces). `feature_row_for_incident`
is the read side a live integration calls to obtain one: today it looks for an `ml.*`-layer
signal on the incident whose `explanation` JSONB carries a `feature_vector` key. **No writer in
this checkout populates that key yet** -- `app.detection.ml.detect.MLSignalDraft.explanation` is
`explain_row`'s `{total_score, per_feature}` deviation shape, not the row's own scaled vector, and
there is currently no live queue-worker path that runs L3 scoring against a real upload at all
(`app/graph/pipeline_demo.py` is a verification CLI, not a wired worker). Returning `None` and
skipping the mechanism call is the same disclosed-gap pattern `app.learning.calibration.
apply_calibrator` already uses when no calibrator has been fit yet -- not a silent no-op, a
documented one. `app/learning/feedback.py` calls this helper and simply does not log a
`learning_events` row for mechanisms 4/5 when it returns `None`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

import numpy as np
import numpy.typing as npt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.ml.artifacts import MODELS_DIR
from app.detection.ml.detect import ML_KTH_NN, ML_PEER_GROUP
from app.detection.ml.knn import KNN_ARTIFACT_FILENAME, KNNArtifact
from app.detection.ml.lof import LOF_ARTIFACT_FILENAME, LOFArtifact
from app.learning.mechanisms import record_event
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.reference_set_exclusion import ReferenceSetExclusion
from app.models.signal import Signal

__all__ = [
    "EXCLUSION_TARGET_MODELS",
    "ReferenceSetWindow",
    "add_to_reference_set",
    "exclude_from_reference_set",
    "feature_row_for_incident",
]

# The two instance-based models' artifact filenames, mutated in place by these mechanisms --
# `ml.eif`/`EIF_ARTIFACT_FILENAME` deliberately excluded: EIF is fitted trees, not an instance
# store (module docstring, "no training loop"). "Full space" artifacts only (`space="full"`) --
# a PCA-space artifact would also need its `PCAReduction` refit to stay consistent, out of this
# mechanism pair's scope; see module docstring.
_INSTANCE_MODELS: dict[str, str] = {
    ML_KTH_NN: KNN_ARTIFACT_FILENAME,
    ML_PEER_GROUP: LOF_ARTIFACT_FILENAME,
}
EXCLUSION_TARGET_MODELS: tuple[str, ...] = (ML_KTH_NN, ML_PEER_GROUP, "ml.eif")


@dataclass(frozen=True, slots=True)
class ReferenceSetWindow:
    entity_type: str
    entity_value: str
    window_start: datetime | None
    window_end: datetime | None


def feature_row_for_incident(
    session: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> tuple[ReferenceSetWindow, npt.NDArray[np.float64]] | None:
    """Best-effort read side -- see module docstring for exactly what this can and cannot find
    today. Returns `None`, not an error, when no `ml.*`-layer signal carries a usable
    `explanation.feature_vector`."""
    with tenant_scope(session, tenant_id):
        incident = session.get(Incident, incident_id)
        if incident is None or not incident.signal_ids:
            return None
        signals = (
            session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
            .scalars()
            .all()
        )
    for sig in signals:
        if sig.detector_layer != "ml":
            continue
        vector = (
            sig.explanation.get("feature_vector") if isinstance(sig.explanation, dict) else None
        )
        if not isinstance(vector, list) or not vector:
            continue
        window = ReferenceSetWindow(
            entity_type=sig.entity_type,
            entity_value=sig.entity_value,
            window_start=sig.window_start,
            window_end=sig.window_end,
        )
        return window, np.asarray(vector, dtype=np.float64)
    return None


def _refit_with_matrix(artifact: KNNArtifact | LOFArtifact, new_x: npt.NDArray[np.float64]) -> None:
    """Refit the wrapped `pyod` estimator on `new_x` in place -- module docstring, "What 'no
    training loop' means precisely here." Only valid for `space == "full"` artifacts."""
    artifact.model.fit(new_x)


def _load_instance_artifact(
    detector_key: str, models_dir: Path
) -> KNNArtifact | LOFArtifact | None:
    path = models_dir / _INSTANCE_MODELS[detector_key]
    if not path.exists():
        return None
    loader = KNNArtifact.load if detector_key == ML_KTH_NN else LOFArtifact.load
    artifact = loader(path)  # type: ignore[operator]
    if artifact.space != "full":
        return None  # PCA-space artifacts are out of scope -- module docstring.
    return artifact


def _fit_x(artifact: KNNArtifact | LOFArtifact) -> npt.NDArray[np.float64]:
    if isinstance(artifact, KNNArtifact):
        return np.asarray(artifact.model.neigh_._fit_X)
    return np.asarray(artifact.model.detector_._fit_X)


def _save(artifact: KNNArtifact | LOFArtifact, models_dir: Path, detector_key: str) -> None:
    artifact.save(models_dir / _INSTANCE_MODELS[detector_key])


@dataclass(slots=True)
class ReferenceSetMutation:
    action: Literal["added", "excluded", "skipped"]
    detector_key: str
    n_reference_points_before: int
    n_reference_points_after: int


def add_to_reference_set(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    window: ReferenceSetWindow,
    feature_row: npt.NDArray[np.float64],
    trigger_feedback_id: uuid.UUID,
    models_dir: Path = MODELS_DIR,
) -> list[ReferenceSetMutation]:
    """Mechanism 4. Appends `feature_row` to kNN's and LOF's reference-point matrix and refits
    each in place, then logs one `learning_events` row (mechanism 4, `applied=True`) summarizing
    both mutations. A detector whose artifact file does not exist yet (no `make train` run in
    this environment) is skipped, not fatal -- reported as `"skipped"` in the result and in
    `after_state`, so a caller can see exactly what did and did not change.
    """
    mutations: list[ReferenceSetMutation] = []
    for detector_key in (ML_KTH_NN, ML_PEER_GROUP):
        artifact = _load_instance_artifact(detector_key, models_dir)
        if artifact is None:
            mutations.append(ReferenceSetMutation("skipped", detector_key, 0, 0))
            continue
        before = _fit_x(artifact)
        n_before = len(before)
        new_x = np.vstack([before, feature_row.reshape(1, -1)])
        _refit_with_matrix(artifact, new_x)
        _save(artifact, models_dir, detector_key)
        mutations.append(ReferenceSetMutation("added", detector_key, n_before, n_before + 1))

    record_event(
        session,
        mechanism=4,
        applied=True,
        trigger_feedback_id=trigger_feedback_id,
        before_state={
            "entity_type": window.entity_type,
            "entity_value": window.entity_value,
            "reference_points": {m.detector_key: m.n_reference_points_before for m in mutations},
        },
        after_state={
            "entity_type": window.entity_type,
            "entity_value": window.entity_value,
            "reference_points": {m.detector_key: m.n_reference_points_after for m in mutations},
            "mutations": {m.detector_key: m.action for m in mutations},
        },
        metric_delta={
            "reference_points_added": sum(1 for m in mutations if m.action == "added"),
        },
    )
    return mutations


def exclude_from_reference_set(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    window: ReferenceSetWindow,
    feature_row: npt.NDArray[np.float64],
    feedback: AnalystFeedback,
    trigger_feedback_id: uuid.UUID,
    models_dir: Path = MODELS_DIR,
    distance_epsilon: float = 1e-6,
) -> list[ReferenceSetMutation]:
    """Mechanism 5 -- the converse of mechanism 4, and change 21's own "one people miss": a
    confirmed *true positive* left in the kNN/LOF reference set gives the next similar attack a
    close, falsely-reassuring neighbour. Removes every reference point within `distance_epsilon`
    of `feature_row` (covers both "this exact window was previously added by mechanism 4" and
    "this window was already part of the original training corpus") and refits in place; always
    records a `reference_set_exclusions` row (all three `EXCLUSION_TARGET_MODELS`, including
    `ml.eif` -- change 21: "none / next refit" for the fitted-trees model) plus one
    `learning_events` row (mechanism 5, `applied=True`).
    """
    mutations: list[ReferenceSetMutation] = []
    for detector_key in (ML_KTH_NN, ML_PEER_GROUP):
        artifact = _load_instance_artifact(detector_key, models_dir)
        if artifact is None:
            mutations.append(ReferenceSetMutation("skipped", detector_key, 0, 0))
            continue
        before = _fit_x(artifact)
        n_before = len(before)
        distances = np.linalg.norm(before - feature_row.reshape(1, -1), axis=1)
        keep_mask = distances > distance_epsilon
        n_removed = int((~keep_mask).sum())
        if n_removed == 0:
            mutations.append(ReferenceSetMutation("skipped", detector_key, n_before, n_before))
            continue
        new_x = before[keep_mask]
        if len(new_x) == 0:
            # Never leave a model with an empty reference set -- refitting on zero rows would
            # make every future score undefined, a worse outcome than leaving one contaminating
            # point in place for one more feedback cycle.
            mutations.append(ReferenceSetMutation("skipped", detector_key, n_before, n_before))
            continue
        _refit_with_matrix(artifact, new_x)
        _save(artifact, models_dir, detector_key)
        mutations.append(
            ReferenceSetMutation("excluded", detector_key, n_before, n_before - n_removed)
        )

    with tenant_scope(session, tenant_id):
        session.add(
            ReferenceSetExclusion(
                tenant_id=tenant_id,
                entity_type=window.entity_type,
                entity_value=window.entity_value,
                window_start=window.window_start,
                window_end=window.window_end,
                feedback_id=feedback.id,
                models=list(EXCLUSION_TARGET_MODELS),
            )
        )
        session.flush()

    record_event(
        session,
        mechanism=5,
        applied=True,
        trigger_feedback_id=trigger_feedback_id,
        before_state={
            "entity_type": window.entity_type,
            "entity_value": window.entity_value,
            "reference_points": {m.detector_key: m.n_reference_points_before for m in mutations},
        },
        after_state={
            "entity_type": window.entity_type,
            "entity_value": window.entity_value,
            "reference_points": {m.detector_key: m.n_reference_points_after for m in mutations},
            "mutations": {m.detector_key: m.action for m in mutations},
            "excluded_for_next_refit": ["ml.eif"],
        },
        metric_delta={
            "reference_points_removed": sum(
                m.n_reference_points_before - m.n_reference_points_after for m in mutations
            ),
        },
    )
    return mutations
