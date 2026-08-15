"""Consumer 6 (training half) — Classifier retraining (docs/08 Part 2, §6).

"`corrected_technique` labels append to the LightGBM training set. Retrain on a schedule or at a
feedback-count threshold."

## Scope, stated honestly

docs/04's LightGBM classifier is trained on "the L3 feature vector plus signal-presence
indicators" plus graph features (docs/05) — both belong to M10 ("Graph, correlation, fusion"),
which is concurrent with this milestone and not yet built in this checkout (`app/graph/` is an
empty stub). Feature parity with that eventual pipeline is out of reach here without depending on
code this milestone does not own. What *is* available now, read-only, is exactly what
`app/learning/feedback_data.py` already reads: each incident's own `signals` (detector_key,
detector_layer, raw_score, confidence) and `incidents.fused_score`/`severity`. `FEATURE_NAMES`
below is a small, honest feature set built only from that — aggregated per incident rather than
one-hot per exact `detector_key`, so it does not silently go stale if the detector catalog grows.
The retrain *gate* (`app/learning/retrain.py`) is the part of docs/08's acceptance bar that must
work regardless ("A deliberately worse candidate model is rejected by the gate") — this module
only has to produce two comparable candidates for that gate to arbitrate between.

## Why `lightgbm` is imported lazily, inside functions

Not a style preference: on at least one development machine in this project's history, the
installed `lightgbm` wheel fails to `import` at all (`OSError: ... Library not loaded:
@rpath/libomp.dylib`, an OpenMP runtime mismatch unrelated to this code). A module-level import
would make `import app.learning.classifier` — and therefore `import app.learning` and every test
that merely imports the package — fail on that machine even for tests that never train anything.
Deferring the import to `train_and_evaluate` means the failure surfaces only when training is
actually attempted, and callers that only need `build_training_rows` or the label/feature logic
are unaffected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.feedback_data import effective_label
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "BENIGN_LABEL",
    "FEATURE_NAMES",
    "MIN_TRAINING_ROWS",
    "TrainResult",
    "TrainingRow",
    "build_training_rows",
    "featurize",
    "train_and_evaluate",
]

BENIGN_LABEL = "benign"

# One feature vector per incident, aggregated over its contributing signals -- see module
# docstring for why this is not the full docs/04 L3 + graph feature vector.
FEATURE_NAMES: tuple[str, ...] = (
    "n_signals",
    "n_distinct_layers",
    "has_layer_rule",
    "has_layer_signal",
    "has_layer_ml",
    "has_layer_graph",
    "max_confidence",
    "mean_confidence",
    "max_raw_score",
    "mean_raw_score",
    "fused_score",
    "severity_ordinal",
)

_SEVERITY_ORDINAL: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_KNOWN_LAYERS: tuple[str, ...] = ("rule", "signal", "ml", "graph")

# docs/08 §6: "Retrain on a schedule or at a feedback-count threshold." This is that threshold --
# below it, a fit is more likely to memorize than generalize, so `run_classifier_retrain`
# (app/learning/retrain.py) skips training entirely rather than gate a fit not worth gating.
MIN_TRAINING_ROWS = 20


@dataclass(frozen=True, slots=True)
class TrainingRow:
    incident_id: uuid.UUID
    features: dict[str, float]
    label: str
    created_at: datetime


def _incident_features(incident: Incident, signals: list[Signal]) -> dict[str, float]:
    confidences = [s.confidence for s in signals]
    raw_scores = [s.raw_score for s in signals]
    layers = {s.detector_layer for s in signals}
    return {
        "n_signals": float(len(signals)),
        "n_distinct_layers": float(len(layers)),
        **{f"has_layer_{layer}": float(layer in layers) for layer in _KNOWN_LAYERS},
        "max_confidence": float(max(confidences)) if confidences else 0.0,
        "mean_confidence": float(sum(confidences) / len(confidences)) if confidences else 0.0,
        "max_raw_score": float(max(raw_scores)) if raw_scores else 0.0,
        "mean_raw_score": float(sum(raw_scores) / len(raw_scores)) if raw_scores else 0.0,
        "fused_score": float(incident.fused_score),
        "severity_ordinal": float(_SEVERITY_ORDINAL.get(incident.severity, 0)),
    }


def _label_for(feedback: AnalystFeedback, verdict: TriageVerdict) -> str | None:
    """docs/08 §6: corrected_technique labels append to the training set. A confirmed (or
    corrected-to-true-positive) verdict with a technique on file also contributes its own label
    -- without that, `corrected_technique` alone could never produce the `benign` class the
    classifier also needs (docs/04: "classes = the scenario techniques + benign"). Returns `None`
    for feedback that carries neither signal (nothing this consumer can label)."""
    if feedback.corrected_technique:
        return feedback.corrected_technique
    if effective_label(verdict.disposition, feedback) == 0:
        return BENIGN_LABEL
    if isinstance(verdict.mitre_techniques, list) and verdict.mitre_techniques:
        first = verdict.mitre_techniques[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict):
            tid = first.get("technique") or first.get("id")
            if isinstance(tid, str):
                return tid
    return None


def build_training_rows(session: Session, tenant_id: uuid.UUID) -> list[TrainingRow]:
    """One row per feedback event that resolves to a label (see `_label_for`), oldest first --
    callers that need a time-based train/held-out split (`train_and_evaluate`) can slice this
    list directly rather than re-sorting."""
    with tenant_scope(session, tenant_id):
        rows = session.execute(
            select(AnalystFeedback, TriageVerdict, Incident)
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
            .order_by(AnalystFeedback.created_at.asc())
        ).all()

        training_rows: list[TrainingRow] = []
        for feedback, verdict, incident in rows:
            label = _label_for(feedback, verdict)
            if label is None:
                continue
            signals = (
                session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
                .scalars()
                .all()
                if incident.signal_ids
                else []
            )
            training_rows.append(
                TrainingRow(
                    incident_id=incident.id,
                    features=_incident_features(incident, list(signals)),
                    label=label,
                    created_at=feedback.created_at,
                )
            )
    return training_rows


def featurize(rows: list[TrainingRow]) -> tuple[list[list[float]], list[str]]:
    """`(X, y)` in `FEATURE_NAMES` order -- kept dependency-free (no numpy) so it's usable from
    both `train_and_evaluate` (which does need numpy/lightgbm) and from tests that only want to
    check the encoding itself."""
    x = [[row.features[name] for name in FEATURE_NAMES] for row in rows]
    y = [row.label for row in rows]
    return x, y


@dataclass(frozen=True, slots=True)
class TrainResult:
    model_bytes: bytes
    label_classes: tuple[str, ...]
    eval_scores: dict[str, float]
    n_train: int
    n_held_out: int


def train_and_evaluate(rows: list[TrainingRow], *, held_out_fraction: float = 0.2) -> TrainResult:
    """Trains a candidate LightGBM multiclass classifier on the first `1 - held_out_fraction` of
    `rows` (already time-ordered by `build_training_rows`) and evaluates it on the remainder --
    docs/12's gate flow ("train candidate -> run golden dataset -> compare to live model") reused
    at classifier scope, with the time-held-out slice standing in for the golden dataset (the
    real `evals/golden` fixtures are M16's ownership, not built in this checkout either).

    This is the one function `app/learning/retrain.py` calls by default; its tests inject a
    lighter-weight stand-in instead (see that module's docstring) so the retrain *gate* — the
    part of this milestone's acceptance bar that must demonstrably work — is exercised
    independent of whether the local `lightgbm` install actually loads.
    """
    import lightgbm as lgb  # deferred import -- see module docstring
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.preprocessing import LabelEncoder

    if len(rows) < 2:
        raise ValueError(f"need at least 2 training rows, got {len(rows)}")

    split = max(1, int(len(rows) * (1 - held_out_fraction)))
    split = min(split, len(rows) - 1) if len(rows) > 1 else split
    train_rows, held_rows = rows[:split], rows[split:]
    if not held_rows:
        train_rows, held_rows = rows[:-1], rows[-1:]

    x_train, y_train_raw = featurize(train_rows)
    x_held, y_held_raw = featurize(held_rows)

    encoder = LabelEncoder()
    encoder.fit([row.label for row in rows])
    y_train = encoder.transform(y_train_raw)
    y_held = encoder.transform(y_held_raw)

    model = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=len(encoder.classes_),
        n_estimators=50,
        class_weight="balanced",
        min_child_samples=1,
        random_state=42,
        verbosity=-1,
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_held)
    accuracy = float(accuracy_score(y_held, y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_held, y_pred, average="macro", zero_division=0
    )

    return TrainResult(
        model_bytes=model.booster_.model_to_string().encode("utf-8"),
        label_classes=tuple(encoder.classes_.tolist()),
        eval_scores={
            "accuracy": accuracy,
            "macro_precision": float(precision),
            "macro_recall": float(recall),
            "macro_f1": float(f1),
        },
        n_train=len(train_rows),
        n_held_out=len(held_rows),
    )
