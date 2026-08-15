"""L3 entity-window ML (docs/04 §L3, docs/13 M8): feature extraction plus three benchmarked
anomaly models — Isolation Forest (`ml.iforest`, baseline), robust-covariance Mahalanobis
(`ml.mahalanobis`), and a PyTorch autoencoder (`ml.autoencoder`, Optuna-tuned).

Governing rule (CLAUDE.md): no model ships without a benchmark, and every model has a simpler
baseline it must beat on the labeled eval set. `ml.iforest` is that baseline (docs/04 names it
one, verbatim); `evals/results.md` is where the other two are measured against it, honestly,
including if they lose.

Public surface:

* `features.build_entity_window_features` — raw `MLEvent`s -> the ~50-feature `(entity, hour)`
  table every model scores.
* `events.load_ml_events` — raw log files -> `MLEvent`s (parses through `app.parsers`, enriches
  through `app.enrichment`; never imports `datagen`).
* `iforest.IsolationForestArtifact`, `mahalanobis.MahalanobisArtifact`,
  `autoencoder.AutoencoderArtifact` — the three fitted models, each with `.raw_scores`,
  `.confidence`, `.explain_row`, `.save`/`.load`.
* `detect.MLModelBundle`, `detect.score_entity_windows` — load all three trained artifacts and
  produce `ml.<model>` signals (`detect.MLSignalDraft`).
* `train.train`, `evaluate.evaluate` — the two CLI entrypoints (`python -m app.detection.ml.train`
  / `.evaluate`) that produce `data/models/**` and `evals/results.md`'s numbers, respectively.
"""

from __future__ import annotations

from app.detection.ml.autoencoder import AutoencoderArtifact
from app.detection.ml.detect import (
    DETECTOR_LAYER,
    ML_AUTOENCODER,
    ML_IFOREST,
    ML_MAHALANOBIS,
    MLModelBundle,
    MLSignalDraft,
    score_entity_windows,
)
from app.detection.ml.events import MLEvent, load_ml_events
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, build_entity_window_features
from app.detection.ml.iforest import IsolationForestArtifact
from app.detection.ml.mahalanobis import MahalanobisArtifact

__all__ = [
    "DETECTOR_LAYER",
    "ENTITY_WINDOW_MODEL_FEATURES",
    "ML_AUTOENCODER",
    "ML_IFOREST",
    "ML_MAHALANOBIS",
    "AutoencoderArtifact",
    "IsolationForestArtifact",
    "MLEvent",
    "MLModelBundle",
    "MLSignalDraft",
    "MahalanobisArtifact",
    "build_entity_window_features",
    "load_ml_events",
    "score_entity_windows",
]
