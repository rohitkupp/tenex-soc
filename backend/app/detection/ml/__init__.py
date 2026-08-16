"""L3 entity-window ML (docs/04 §L3, docs/13 M8-M8b): feature extraction plus four benchmarked
anomaly models — Isolation Forest (`ml.iforest`, baseline), robust-covariance Mahalanobis
(`ml.mahalanobis`), ECOD (`ml.ecod`, per-feature tail probability), and LOF (`ml.peer_group`,
peer-relative density).

A fifth model, a PyTorch autoencoder (`ml.autoencoder`, Optuna-tuned), shipped through this
milestone's own development window and was cut by migration change 19
(`docs/v2_migration/MIGRATION-01-evidence-first.md`): its job -- joint-distribution anomalies no
single feature's tail exposes -- is what a later phase's EIF (oblique-split isolation forest) is
meant to take over, and docs/04 had already committed to "if EIF matches the autoencoder, the
autoencoder is cut" before that benchmark ran. Not built here; this package is four models until
it lands.

Also new this migration: `features.NAVIGATION_FEATURES`, the navigation chain extractor's
aggregated output (`navigation.py`, change 18) — deterministic referer-chain reconstruction, not a
model, folded into the same `(entity, hour)` feature vector every model here scores.

Governing rule (CLAUDE.md): no model ships without a benchmark, and every model has a simpler
baseline it must beat on the labeled eval set. `ml.iforest` is that baseline (docs/04 names it
one, verbatim); `evals/results.md` is where the other three are measured against it, honestly,
including if they lose.

Public surface:

* `features.build_entity_window_features` — raw `MLEvent`s -> the feature `(entity, hour)`
  table every model scores, including the docs/04-normative own-history- and department-cohort-
  relative variants (`features.py`'s own module docstring, "Entity-relative features") and the
  navigation chain family.
* `navigation.annotate_navigation_hops` — per-event referer-chain reconstruction `features.py`
  aggregates into the navigation feature family (see that module's own docstring).
* `events.load_ml_events` — raw log files -> `MLEvent`s (parses through `app.parsers`, enriches
  through `app.enrichment`; never imports `datagen`).
* `iforest.IsolationForestArtifact`, `mahalanobis.MahalanobisArtifact`, `ecod.ECODArtifact`,
  `lof.LOFArtifact` — the four fitted models, each with `.raw_scores`, `.confidence`,
  `.explain_row`, `.save`/`.load`.
* `detect.MLModelBundle`, `detect.score_entity_windows` — load all four trained artifacts and
  produce `ml.<model>` signals (`detect.MLSignalDraft`).
* `train.train`, `evaluate.evaluate` — the two CLI entrypoints (`python -m app.detection.ml.train`
  / `.evaluate`) that produce `data/models/**` and `evals/results.md`'s numbers, respectively.
"""

from __future__ import annotations

from app.detection.ml.detect import (
    DETECTOR_LAYER,
    ML_ECOD,
    ML_IFOREST,
    ML_MAHALANOBIS,
    ML_PEER_GROUP,
    MLModelBundle,
    MLSignalDraft,
    score_entity_windows,
)
from app.detection.ml.ecod import ECODArtifact
from app.detection.ml.events import MLEvent, load_ml_events
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, build_entity_window_features
from app.detection.ml.iforest import IsolationForestArtifact
from app.detection.ml.lof import LOFArtifact
from app.detection.ml.mahalanobis import MahalanobisArtifact
from app.detection.ml.navigation import annotate_navigation_hops

__all__ = [
    "DETECTOR_LAYER",
    "ENTITY_WINDOW_MODEL_FEATURES",
    "ML_ECOD",
    "ML_IFOREST",
    "ML_MAHALANOBIS",
    "ML_PEER_GROUP",
    "ECODArtifact",
    "IsolationForestArtifact",
    "LOFArtifact",
    "MLEvent",
    "MLModelBundle",
    "MLSignalDraft",
    "MahalanobisArtifact",
    "annotate_navigation_hops",
    "build_entity_window_features",
    "load_ml_events",
    "score_entity_windows",
]
