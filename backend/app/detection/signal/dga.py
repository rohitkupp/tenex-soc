"""Domain entropy / DGA detector (docs/04 §L2 "Domain entropy / DGA"), runtime half.

```
score = sigmoid(w1*H + w2*(-ngram_ll) + w3*digit_ratio + w4*max_consonant_run + w5*len_norm)
```

This module never fits `w1..w5` and never imports `datagen` -- it loads the artifact
`dga_train.py` (offline, run once) wrote to `backend/data/models/dga_weights.json` and applies
it. "Fit `w` by logistic regression on known-DGA vs. top-sites domains and ship the fitted
coefficients as an artifact" (task brief) is `dga_train.py`'s job; "do not hardcode magic
numbers" is why this module has none -- every number `score_label` touches besides the feature
formulas themselves (which are `dga_features.py`'s, shared with training) comes out of the
loaded JSON.

Domains are scored **per registrable domain**, not per raw hostname: `events.domain` can carry
several subdomains of the same attacker infrastructure (`a1.abcdef.top`, `a2.abcdef.top`, ...),
and docs/04 says to score "the registrable domain's second-level label," so every hostname that
resolves to the same registrable domain is grouped, scored once, and its evidence pooled --
`app.enrichment.domain_enrichment.enrich_domain` (already-canonical registrable-domain
resolution, reused rather than re-deriving public-suffix logic a second time) does that
resolution.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.detection.signal.constants import DGA_ARTIFACT_FILENAME, ENTITY_DOMAIN, SIGNAL_DGA
from app.detection.signal.dga_features import (
    FEATURE_NAMES,
    BigramModel,
    DGAFeatures,
    dot,
    feature_vector,
    second_level_label,
    sigmoid,
)
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow, rows_with_domain
from app.enrichment.domain_enrichment import enrich_domain

__all__ = ["DEFAULT_ARTIFACT_PATH", "DGAArtifact", "detect_dga", "load_artifact", "score_label"]

# app/detection/signal/dga.py -> signal -> detection -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_PATH: Path = _BACKEND_ROOT / "data" / "models" / DGA_ARTIFACT_FILENAME


@dataclass(frozen=True, slots=True)
class DGAArtifact:
    weights: tuple[float, ...]  # order matches `FEATURE_NAMES`
    intercept: float
    decision_threshold: float
    bigram: BigramModel
    len_norm_cap: float
    metadata: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DGAArtifact:
        weights_by_name = data["weights"]
        weights = tuple(float(weights_by_name[name]) for name in FEATURE_NAMES)
        return cls(
            weights=weights,
            intercept=float(data["intercept"]),
            decision_threshold=float(data.get("decision_threshold", 0.5)),
            bigram=BigramModel.from_dict(data["bigram_model"]),
            len_norm_cap=float(data.get("len_norm_cap", 32.0)),
            metadata=data.get("training", {}),
        )

    def weight_map(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.weights, strict=True))


@lru_cache(maxsize=8)
def _load_cached(resolved_path: str) -> DGAArtifact:
    payload = json.loads(Path(resolved_path).read_text(encoding="utf-8"))
    return DGAArtifact.from_dict(payload)


def load_artifact(path: Path | None = None) -> DGAArtifact:
    resolved = (path or DEFAULT_ARTIFACT_PATH).resolve()
    if not resolved.exists():
        raise FileNotFoundError(
            f"DGA artifact not found at {resolved}. Run "
            "`python -m app.detection.signal.dga_train` first (docs/04 §L2 'Domain entropy / "
            "DGA': 'Fit w by logistic regression ... ship the fitted coefficients as an "
            "artifact')."
        )
    return _load_cached(str(resolved))


def score_label(label: str, artifact: DGAArtifact) -> tuple[float, DGAFeatures]:
    features = feature_vector(label, artifact.bigram, cap=artifact.len_norm_cap)
    logit = dot(artifact.weights, features) + artifact.intercept
    return sigmoid(logit), features


def detect_dga(
    rows: Sequence[EventRow], *, artifact: DGAArtifact | None = None
) -> list[SignalDraft]:
    artifact = artifact if artifact is not None else load_artifact()

    groups: dict[str, tuple[str, list[EventRow]]] = {}
    hostnames_by_registrable: dict[str, set[str]] = defaultdict(set)
    for row in rows_with_domain(rows):
        assert row.domain is not None  # narrowed by rows_with_domain
        info = enrich_domain(row.domain)
        registrable = info.registrable_domain if info else row.domain
        tld = info.tld if info else ""
        hostnames_by_registrable[registrable].add(row.domain)
        if registrable not in groups:
            groups[registrable] = (tld, [])
        groups[registrable][1].append(row)

    drafts: list[SignalDraft] = []
    for registrable, (tld, group_rows) in groups.items():
        label = second_level_label(registrable, tld)
        score, features = score_label(label, artifact)
        if score < artifact.decision_threshold:
            continue

        ordered = sorted(group_rows, key=lambda r: r.ts)
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered])
        explanation: dict[str, Any] = {
            "domain": registrable,
            "second_level_label": label,
            "tld": tld,
            "hostnames": sorted(hostnames_by_registrable[registrable])[:20],
            "shannon_entropy": features.shannon_entropy,
            "neg_ngram_log_likelihood": features.neg_ngram_ll,
            "digit_ratio": features.digit_ratio,
            "max_consonant_run": features.max_consonant_run,
            "len_norm": features.len_norm,
            "score": score,
            "decision_threshold": artifact.decision_threshold,
            "weights": artifact.weight_map(),
            "intercept": artifact.intercept,
            "n_events": len(ordered),
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_DGA,
                entity_type=ENTITY_DOMAIN,
                entity_value=registrable,
                raw_score=score,
                confidence_raw=score,
                window_start=ordered[0].ts,
                window_end=ordered[-1].ts,
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts
