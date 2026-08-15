"""LightGBM technique classifier (docs/04 "Classification — LightGBM -> ATT&CK").

> Supervised multiclass over the L3 feature vector plus signal-presence indicators. Trained on
> labeled synthetic scenarios (docs/11).
> - `objective='multiclass'`, classes = the scenario techniques + `benign`
> - Class weights to handle imbalance
> - SHAP values written to `explanation`
> - Benchmark against Claude zero-shot classification... for now report its own accuracy and
>   macro-F1 (docs/13 M10: the LLM comparison is explicitly an M11 follow-up, not this
>   milestone's job — CLAUDE.md's own M10 task list only asks for this classifier's own numbers).

Sits between L5 (graph) and fusion in the pipeline (docs/04: "L1 ... -> L5 graph -> classify ->
fuse & calibrate"). Lives in `app.graph` rather than `app.detection.ml` because `app/detection/
ml/**` is explicitly out of this milestone's ownership (concurrent agents) — this module reuses
that package's feature extraction read-only (`build_entity_window_features`, `to_feature_matrix`,
`ENTITY_WINDOW_MODEL_FEATURES`) rather than duplicating it, the same reuse boundary
`app.detection.calibration` holds for its own L3 recompare.

## Feature vector

The L3 ~50-feature vector (docs/04 §L3, `app.detection.ml.features`) plus one signal-presence
indicator per L3 model — whether that model itself flags this (entity, window) at the docs/04
operating point (`SIGNAL_PRESENCE_FEATURES`, dynamically sized to whatever
`app.detection.ml.detect.MLModelBundle` currently ships — five models as of this milestone's own
development window: `ml.iforest`, `ml.mahalanobis`, `ml.ecod`, `ml.peer_group`, `ml.autoencoder`).
**Scope, stated plainly:** "signal-presence indicators" in the general sense (docs/04) would also
include L1 rule hits and L2 signal-layer detections; those operate on raw events (L1's SQL
predicates need a live analysis in Postgres, L2 needs `EventRow`s), not on this module's
entity-window rows, and re-deriving them a second time at this granularity is out of scope for
what this milestone's time affords. Scoped here to the L3 detectors that already produce a
same-granularity, same-DataFrame flag (`app.detection.ml.detect.MLModelBundle`) — documented as a
scope cut, not hidden.

## Labels

One label per entity-window row: the scenario's own `technique` (ATT&CK ID, from
`GroundTruth`/`.labels.json`, docs/11) if the row is one of that scenario's malicious rows,
else `"benign"`. A malicious row from a scenario with no attached technique (`prompt_injection_
canary` — a prompt-injection test, not an ATT&CK-mapped attack) is dropped from training/eval
entirely rather than mislabeled either way.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import numpy.typing as npt
import pandas as pd
import shap
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, f1_score

from app.core.logging import get_logger

__all__ = [
    "BENIGN_LABEL",
    "CLASSIFIER_ARTIFACT_FILENAME",
    "SIGNAL_PRESENCE_FEATURES",
    "TechniqueClassifierArtifact",
    "TrainEvalResult",
    "build_training_frame",
    "train_and_evaluate",
]

log = get_logger(__name__)

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
MODELS_DIR: Final[Path] = _BACKEND_ROOT / "data" / "models"
CLASSIFIER_ARTIFACT_FILENAME: Final[str] = "lightgbm_technique.joblib"

BENIGN_LABEL: Final[str] = "benign"
# One flag per L3 model `app.detection.ml.detect.MLModelBundle` currently ships. That package
# (out of this milestone's ownership, concurrently developed) grew from three models to the full
# five-model docs/04 roster during this milestone's own development window -- see
# `app.detection.calibration._model_pairs`'s docstring for the same note. Kept as a `Final` tuple
# (not derived dynamically at import time) so column order is stable across a training run and a
# later scoring call without needing a live model bundle just to know the feature names.
SIGNAL_PRESENCE_FEATURES: Final[tuple[str, ...]] = (
    "ml.iforest_flag",
    "ml.mahalanobis_flag",
    "ml.ecod_flag",
    "ml.peer_group_flag",
    "ml.autoencoder_flag",
)

_MAX_BENIGN_TRAIN_ROWS: Final[int] = 8_000
_RANDOM_STATE: Final[int] = 42
_TOP_K_SHAP: Final[int] = 10


def build_training_frame(scenario_dir: Path) -> tuple[pd.DataFrame, pd.Series]:
    """One scenario directory (`python -m datagen scenario ...` output) -> `(X, y)`: `X` is the
    L3 feature vector plus `SIGNAL_PRESENCE_FEATURES`, `y` is the per-row label
    (technique ID or `"benign"`). Rows from a malicious scenario with no attached technique are
    dropped (see module docstring).
    """
    # Local imports: this module's callers (the pipeline demo, `CalibratorStore`-adjacent code)
    # should not pay for `app.detection.ml`'s heavy import graph (torch, etc.) unless they
    # actually train/score the classifier.
    from app.detection.ml.detect import SIGNAL_CONFIDENCE_THRESHOLD, MLModelBundle
    from app.detection.ml.events import load_ml_events
    from app.detection.ml.features import build_entity_window_features

    label_files = sorted(scenario_dir.glob("*.labels.json"))
    log_files = sorted(scenario_dir.glob("*.log"))
    if not label_files or not log_files:
        return pd.DataFrame(), pd.Series(dtype=object)

    payload = json.loads(label_files[0].read_text(encoding="utf-8"))
    technique_by_line: dict[int, str] = {}
    for s in payload["scenarios"]:
        technique = s.get("technique")
        if technique is None:
            continue
        for ln in s["malicious_line_numbers"]:
            technique_by_line[ln] = technique
    all_malicious = {ln for s in payload["scenarios"] for ln in s["malicious_line_numbers"]}

    events = load_ml_events({"zscaler": log_files[0]})
    df = build_entity_window_features(events)
    if df.empty:
        return pd.DataFrame(), pd.Series(dtype=object)

    def row_label(line_numbers: list[int]) -> str | None:
        malicious_lines = [ln for ln in line_numbers if ln in all_malicious]
        if not malicious_lines:
            return BENIGN_LABEL
        techniques = {technique_by_line[ln] for ln in malicious_lines if ln in technique_by_line}
        if not techniques:
            return None  # malicious but technique-less (e.g. prompt_injection_canary) -- drop
        return sorted(techniques)[0]  # deterministic tie-break if a window spans >1 technique

    labels = df["line_numbers"].apply(row_label)
    keep = labels.notna()
    df, labels = df[keep].reset_index(drop=True), labels[keep].reset_index(drop=True)

    bundle = MLModelBundle.load()
    x_scaled = bundle.transform(df)
    # `Any`-typed list: the five model classes share no common base (each independently defines
    # `raw_scores`/`confidence`), so a plain heterogeneous tuple would make mypy join their
    # element type down to `object` when iterated -- same reasoning as
    # `app.graph.pipeline_demo._ml_model_pairs`.
    models: list[Any] = [
        bundle.iforest,
        bundle.mahalanobis,
        bundle.ecod,
        bundle.lof,
        bundle.autoencoder,
    ]
    for name, model in zip(SIGNAL_PRESENCE_FEATURES, models, strict=True):
        raw = model.raw_scores(x_scaled)
        conf = model.confidence(raw)
        df[name] = (conf >= SIGNAL_CONFIDENCE_THRESHOLD).astype(float)

    from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES

    feature_cols = list(ENTITY_WINDOW_MODEL_FEATURES) + list(SIGNAL_PRESENCE_FEATURES)
    x = df[feature_cols].astype(np.float64)
    return x, labels.rename("label")


@dataclass(slots=True)
class TechniqueClassifierArtifact:
    model: LGBMClassifier
    feature_names: tuple[str, ...]
    classes: tuple[str, ...]

    def save(self, path: Path = MODELS_DIR / CLASSIFIER_ARTIFACT_FILENAME) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(
        cls, path: Path = MODELS_DIR / CLASSIFIER_ARTIFACT_FILENAME
    ) -> TechniqueClassifierArtifact:
        loaded: TechniqueClassifierArtifact = joblib.load(path)
        return loaded

    def predict(self, x_row: npt.NDArray[np.float64]) -> tuple[str, float, dict[str, Any]]:
        """One row (`self.feature_names` order) -> `(predicted_label, confidence, shap_payload)`.
        `shap_payload` matches docs/04's per-model shape: `{"total_score", "per_feature": [...]}`,
        sorted by `|contribution|` descending, top `_TOP_K_SHAP` only."""
        proba = self.model.predict_proba(x_row.reshape(1, -1))[0]
        idx = int(np.argmax(proba))
        label = self.classes[idx]
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(x_row.reshape(1, -1))
        # Multiclass LightGBM via SHAP: a list of per-class arrays (older API) or a single
        # `(n_samples, n_features, n_classes)` array (newer API) -- normalize both to one
        # per-feature vector for the predicted class.
        if isinstance(shap_values, list):
            class_values = np.asarray(shap_values[idx])[0]
        else:
            arr = np.asarray(shap_values)
            class_values = arr[0, :, idx] if arr.ndim == 3 else arr[0]
        pairs = sorted(
            zip(self.feature_names, class_values.tolist(), strict=True),
            key=lambda p: abs(p[1]),
            reverse=True,
        )[:_TOP_K_SHAP]
        payload = {
            "total_score": float(proba[idx]),
            "per_feature": [{"feature": f, "contribution": v} for f, v in pairs],
        }
        return label, float(proba[idx]), payload


@dataclass(frozen=True, slots=True)
class TrainEvalResult:
    accuracy: float
    macro_f1: float
    n_train: int
    n_test: int
    classes: tuple[str, ...]
    class_counts_train: dict[str, int]
    class_counts_test: dict[str, int]
    per_class_f1: dict[str, float]
    fit_seconds: float
    shap_example: dict[str, Any]


def train_and_evaluate(
    train_scenario_dirs: list[Path], test_scenario_dirs: list[Path]
) -> tuple[TechniqueClassifierArtifact, TrainEvalResult]:
    """Fit on `train_scenario_dirs` (one `datagen scenario` output dir per scenario key),
    evaluate on `test_scenario_dirs` (a disjoint seed, mirroring every other train/eval split in
    this codebase). The benign class is subsampled at train time only (`_MAX_BENIGN_TRAIN_ROWS`)
    to keep LightGBM's fit fast and the class balance sane; the test split keeps its natural
    (heavily benign-skewed) distribution for an honest accuracy/macro-F1 number.
    """
    t0 = time.perf_counter()
    x_train_parts: list[pd.DataFrame] = []
    y_train_parts: list[pd.Series] = []
    for d in train_scenario_dirs:
        x, y = build_training_frame(d)
        if not x.empty:
            x_train_parts.append(x)
            y_train_parts.append(y)
    x_train = pd.concat(x_train_parts, ignore_index=True)
    y_train = pd.concat(y_train_parts, ignore_index=True)

    rng = np.random.default_rng(_RANDOM_STATE)
    benign_idx = y_train[y_train == BENIGN_LABEL].index.to_numpy()
    if len(benign_idx) > _MAX_BENIGN_TRAIN_ROWS:
        drop = rng.choice(benign_idx, size=len(benign_idx) - _MAX_BENIGN_TRAIN_ROWS, replace=False)
        x_train = x_train.drop(index=drop).reset_index(drop=True)
        y_train = y_train.drop(index=drop).reset_index(drop=True)

    x_test_parts: list[pd.DataFrame] = []
    y_test_parts: list[pd.Series] = []
    for d in test_scenario_dirs:
        x, y = build_training_frame(d)
        if not x.empty:
            x_test_parts.append(x)
            y_test_parts.append(y)
    x_test = pd.concat(x_test_parts, ignore_index=True)
    y_test = pd.concat(y_test_parts, ignore_index=True)

    classes = tuple(sorted(set(y_train) | set(y_test)))
    model = LGBMClassifier(
        objective="multiclass",
        num_class=len(classes),
        class_weight="balanced",
        n_estimators=200,
        random_state=_RANDOM_STATE,
        verbose=-1,
    )
    model.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - t0

    y_pred = model.predict(x_test)
    accuracy = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    per_class_f1 = dict(
        zip(
            sorted(set(y_test) | set(y_pred)),
            f1_score(
                y_test,
                y_pred,
                labels=sorted(set(y_test) | set(y_pred)),
                average=None,
                zero_division=0,
            ).tolist(),
            strict=True,
        )
    )

    artifact = TechniqueClassifierArtifact(
        model=model, feature_names=tuple(x_train.columns), classes=classes
    )

    shap_row = x_test.iloc[[0]].to_numpy(dtype=np.float64)[0]
    _, _, shap_example = artifact.predict(shap_row)

    result = TrainEvalResult(
        accuracy=accuracy,
        macro_f1=macro_f1,
        n_train=len(x_train),
        n_test=len(x_test),
        classes=classes,
        class_counts_train=y_train.value_counts().to_dict(),
        class_counts_test=y_test.value_counts().to_dict(),
        per_class_f1=per_class_f1,
        fit_seconds=fit_seconds,
        shap_example=shap_example,
    )
    log.info(
        "classifier.trained",
        accuracy=round(accuracy, 4),
        macro_f1=round(macro_f1, 4),
        n_train=len(x_train),
        n_test=len(x_test),
        classes=classes,
        fit_seconds=round(fit_seconds, 2),
    )
    return artifact, result
