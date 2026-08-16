"""Offline fit for the DGA detector's logistic-regression weights (docs/04 §L2 "Domain entropy
/ DGA": "Fit w by logistic regression on a labeled set of known-DGA vs. top-sites domains. Ship
the fitted coefficients as an artifact" -- and the task brief: "do not hardcode magic numbers.
M2 bundles a 5,000-domain top-sites list at backend/datagen/data/top_domains.txt and its
scenarios generate DGA domains -- use both as the labelled training set.").

Run once, offline: `python -m app.detection.evidence.dga_train`. Writes
`backend/data/models/dga_weights.json`, which `dga.py` (the runtime detector) loads and never
refits. This is the **only** module under `app/detection/evidence/` that reads `datagen/data/` (a
bundled text asset, the same file `app.enrichment.domain_enrichment` already reads) or generates
DGA-style strings -- it does so with its own small, self-contained generator rather than
importing `datagen.realism.DGAGenerator`, deliberately: every other module in this codebase that
crosses the detection/generator boundary (`app.detection.features`, `app.enrichment.loader`)
does so with detection-owned code as the canonical side and `datagen` depending on *it*, never
the other way around, and `tests/test_detection_features.py` states outright that detection's
own tests stay "deliberately decoupled from `datagen`." `_generate_dga_label` below mirrors
`DGAGenerator`'s four style categories (random / hex / consonant / numeric) closely enough that
the fitted model sees the same *kind* of string scenario 1 will actually emit, without a hard
import dependency in either direction.

## Train/test split, and where bigram fitting sits relative to it

`BigramModel.fit` (docs/04's "bigram model fit on a top-domains list") is itself a piece of
*feature engineering*, not the classifier -- but fitting it on the full benign label set,
including domains later used to measure held-out accuracy, would leak test-set structure into a
feature the classifier then trains on, inflating the reported accuracy. The split therefore
happens **before** the bigram model is fit: `train_test_split` first, `BigramModel.fit` only on
the benign-train partition, and every feature vector (train and test, both classes) computed
through that same fitted model. `held_out_accuracy` and friends are honest numbers about
generalization to domains this run never touched, not just to unseen data conditioned on
leaked benign structure.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from app.core.logging import configure_logging, get_logger
from app.detection.evidence.dga import DEFAULT_ARTIFACT_PATH
from app.detection.evidence.dga_features import (
    FEATURE_NAMES,
    BigramModel,
    feature_vector,
    second_level_label,
)
from app.enrichment.domain_enrichment import enrich_domain
from app.enrichment.loader import DATAGEN_DATA_DIR

log = get_logger(__name__)

TOP_DOMAINS_TXT = DATAGEN_DATA_DIR / "top_domains.txt"

# Mirrors `datagen.realism.DGAGenerator` -- see module docstring for why this is a parallel,
# self-contained implementation rather than an import of it.
_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
_VOWELS = "aeiou"
_HEX_DIGITS = "0123456789abcdef"
_STYLES: tuple[str, ...] = ("random", "hex", "consonant", "numeric")
_TLDS: tuple[str, ...] = ("top", "xyz", "cc", "su", "info", "net", "org", "biz", "ru", "com")
_LENGTH_RANGE = (10, 18)

DEFAULT_SEED = 20260814  # generation date, pinned for reproducibility -- not a "found" number
DEFAULT_N_PER_STYLE = 1400
DEFAULT_TEST_SIZE = 0.2
DEFAULT_ALPHA = 1.0
DEFAULT_DECISION_THRESHOLD = 0.5


def _generate_dga_label(rng: random.Random, style: str) -> str:
    n = rng.randint(*_LENGTH_RANGE)
    if style == "hex":
        return "".join(rng.choice(_HEX_DIGITS) for _ in range(n))
    if style == "numeric":
        alphabet = _CONSONANTS + _VOWELS + "0123456789"
        return "".join(rng.choice(alphabet) for _ in range(n))
    if style == "consonant":
        return "".join(rng.choice(_CONSONANTS) for _ in range(n))
    alphabet = _CONSONANTS + _VOWELS
    return "".join(rng.choice(alphabet) for _ in range(n))


def _dga_labels(rng: random.Random, n_per_style: int) -> list[str]:
    labels: set[str] = set()
    for style in _STYLES:
        target = len(labels) + n_per_style
        attempts = 0
        while len(labels) < target and attempts < n_per_style * 20:
            raw = _generate_dga_label(rng, style)
            tld = rng.choice(_TLDS)
            # Route through the same registrable-domain resolution the runtime detector uses,
            # so a training-time label is computed by the identical pipeline as an inference-
            # time one (module docstring's train/serve-symmetry point).
            info = enrich_domain(f"{raw}.{tld}")
            label = second_level_label(info.registrable_domain, info.tld) if info else raw
            labels.add(label)
            attempts += 1
    return sorted(labels)


def _benign_labels() -> list[str]:
    labels: set[str] = set()
    for raw_line in TOP_DOMAINS_TXT.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        info = enrich_domain(line)
        if info is None:
            continue
        label = second_level_label(info.registrable_domain, info.tld)
        if label:
            labels.add(label)
    return sorted(labels)


@dataclass(frozen=True, slots=True)
class FitResult:
    weights: dict[str, float]
    intercept: float
    bigram: BigramModel
    metrics: dict[str, float]
    counts: dict[str, int]


def fit(
    *,
    seed: int = DEFAULT_SEED,
    n_per_style: int = DEFAULT_N_PER_STYLE,
    test_size: float = DEFAULT_TEST_SIZE,
    alpha: float = DEFAULT_ALPHA,
) -> FitResult:
    rng = random.Random(seed)  # noqa: S311 - synthetic training-label generation, not security

    benign = _benign_labels()
    dga = _dga_labels(rng, n_per_style)
    # A label generated for the DGA class that happens to collide with a real top-site's second-
    # level label (astronomically unlikely given the character space, but checked rather than
    # assumed) stays benign -- the top-sites list is ground truth about the real world; the
    # generator's draw is not.
    dga = [label for label in dga if label not in set(benign)]

    log.info("dga_train.labels", n_benign=len(benign), n_dga=len(dga))

    labels = benign + dga
    y = [0] * len(benign) + [1] * len(dga)
    labels_train, labels_test, y_train, y_test = train_test_split(
        labels, y, test_size=test_size, random_state=seed, stratify=y
    )

    benign_train = [lbl for lbl, cls in zip(labels_train, y_train, strict=True) if cls == 0]
    bigram = BigramModel.fit(benign_train, alpha=alpha)

    x_train = [feature_vector(lbl, bigram).as_vector() for lbl in labels_train]
    x_test = [feature_vector(lbl, bigram).as_vector() for lbl in labels_test]

    clf = LogisticRegression(class_weight="balanced", max_iter=5000, random_state=seed)
    clf.fit(x_train, y_train)

    y_pred = clf.predict(x_test)
    y_score = clf.predict_proba(x_test)[:, 1]
    metrics = {
        "held_out_accuracy": float(accuracy_score(y_test, y_pred)),
        "held_out_precision": float(precision_score(y_test, y_pred)),
        "held_out_recall": float(recall_score(y_test, y_pred)),
        "held_out_f1": float(f1_score(y_test, y_pred)),
        "held_out_roc_auc": float(roc_auc_score(y_test, y_score)),
    }
    counts = {
        "n_benign_total": len(benign),
        "n_dga_total": len(dga),
        "n_train": len(labels_train),
        "n_test": len(labels_test),
        "n_benign_train": int(sum(1 for c in y_train if c == 0)),
        "n_dga_train": int(sum(1 for c in y_train if c == 1)),
        "n_benign_test": int(sum(1 for c in y_test if c == 0)),
        "n_dga_test": int(sum(1 for c in y_test if c == 1)),
    }
    weights = dict(zip(FEATURE_NAMES, (float(w) for w in clf.coef_[0]), strict=True))

    log.info(
        "dga_train.fit", weights=weights, intercept=float(clf.intercept_[0]), **metrics, **counts
    )

    return FitResult(
        weights=weights,
        intercept=float(clf.intercept_[0]),
        bigram=bigram,
        metrics=metrics,
        counts=counts,
    )


def write_artifact(result: FitResult, path: Path, *, seed: int) -> None:
    payload: dict[str, Any] = {
        "version": 1,
        "fitted_at": datetime.now(UTC).isoformat(),
        "feature_order": list(FEATURE_NAMES),
        "weights": result.weights,
        "intercept": result.intercept,
        "decision_threshold": DEFAULT_DECISION_THRESHOLD,
        "len_norm_cap": 32.0,
        "bigram_model": result.bigram.to_dict(),
        "training": {
            **result.metrics,
            **result.counts,
            "seed": seed,
            "benign_source": str(TOP_DOMAINS_TXT.relative_to(TOP_DOMAINS_TXT.parents[2])),
            "dga_source": (
                "app.detection.evidence.dga_train._generate_dga_label -- mirrors "
                "datagen.realism.DGAGenerator's random/hex/consonant/numeric styles"
            ),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    log.info("dga_train.artifact_written", path=str(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fit and persist the DGA detector's weights")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--n-per-style", type=int, default=DEFAULT_N_PER_STYLE)
    parser.add_argument("--test-size", type=float, default=DEFAULT_TEST_SIZE)
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    parser.add_argument("--out", type=Path, default=DEFAULT_ARTIFACT_PATH)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    configure_logging(args.log_level)
    result = fit(
        seed=args.seed, n_per_style=args.n_per_style, test_size=args.test_size, alpha=args.alpha
    )
    write_artifact(result, args.out, seed=args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = ["DEFAULT_SEED", "FitResult", "fit", "main", "write_artifact"]
