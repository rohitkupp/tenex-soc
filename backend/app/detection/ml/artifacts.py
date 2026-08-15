"""Where trained L3 artifacts live, plus the tiny shared bits every model's persistence code
needs (docs/13 M8: "trained on the clean benign corpus... write artifacts to
`backend/data/models/`").

One directory, one manifest. `feature_manifest.json` records the exact
`ENTITY_WINDOW_MODEL_FEATURES` order every artifact in this directory was fit against — if
`features.py` ever changes that order or the feature count, every artifact here is stale, and
`load_feature_manifest`'s consistency check (used by `detect.py`) fails loudly instead of
silently scoring garbage through a column-shifted feature vector.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES

__all__ = [
    "MODELS_DIR",
    "FeatureManifest",
    "load_feature_manifest",
    "write_feature_manifest",
]

# app/detection/ml/artifacts.py -> ml -> detection -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR: Path = _BACKEND_ROOT / "data" / "models"

_MANIFEST_FILENAME = "feature_manifest.json"


@dataclass(frozen=True, slots=True)
class FeatureManifest:
    feature_names: tuple[str, ...]
    trained_at: str
    corpus_seed: int
    corpus_n_events: int
    extra: dict[str, Any]


def write_feature_manifest(
    *,
    trained_at: str,
    corpus_seed: int,
    corpus_n_events: int,
    extra: dict[str, Any] | None = None,
    models_dir: Path = MODELS_DIR,
) -> Path:
    models_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "feature_names": list(ENTITY_WINDOW_MODEL_FEATURES),
        "trained_at": trained_at,
        "corpus_seed": corpus_seed,
        "corpus_n_events": corpus_n_events,
        "extra": extra or {},
    }
    path = models_dir / _MANIFEST_FILENAME
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_feature_manifest(models_dir: Path = MODELS_DIR) -> FeatureManifest:
    path = models_dir / _MANIFEST_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    manifest = FeatureManifest(
        feature_names=tuple(payload["feature_names"]),
        trained_at=payload["trained_at"],
        corpus_seed=payload["corpus_seed"],
        corpus_n_events=payload["corpus_n_events"],
        extra=payload.get("extra", {}),
    )
    if manifest.feature_names != ENTITY_WINDOW_MODEL_FEATURES:
        raise ValueError(
            "feature_manifest.json was written against a different feature vector than "
            "app.detection.ml.features.ENTITY_WINDOW_MODEL_FEATURES exposes today -- every "
            "artifact under data/models/ is stale and must be retrained (`python -m "
            "app.detection.ml.train`) before `detect.py` can safely load them."
        )
    return manifest
