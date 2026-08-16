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

from app.detection.evidence.constants import (
    DGA_ARTIFACT_FILENAME,
    ENTITY_DOMAIN,
    EXTRACTOR_DGA,
    SIGNAL_DGA,
)
from app.detection.evidence.dga_features import (
    FEATURE_NAMES,
    BigramModel,
    DGAFeatures,
    dot,
    feature_vector,
    second_level_label,
    sigmoid,
)
from app.detection.evidence.drafts import SignalDraft, cap_evidence, cap_evidence_rows
from app.detection.evidence.events_dao import EventRow, rows_with_domain
from app.detection.evidence.payload import RawEvidence
from app.enrichment.domain_enrichment import enrich_domain

__all__ = [
    "DEFAULT_ARTIFACT_PATH",
    "DGAArtifact",
    "detect_dga",
    "load_artifact",
    "raw_evidence_dga",
    "score_label",
]

# app/detection/evidence/dga.py -> evidence -> detection -> app -> backend
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
            "`python -m app.detection.evidence.dga_train` first (docs/04 §L2 'Domain entropy / "
            "DGA': 'Fit w by logistic regression ... ship the fitted coefficients as an "
            "artifact')."
        )
    return _load_cached(str(resolved))


def score_label(label: str, artifact: DGAArtifact) -> tuple[float, DGAFeatures]:
    features = feature_vector(label, artifact.bigram, cap=artifact.len_norm_cap)
    logit = dot(artifact.weights, features) + artifact.intercept
    return sigmoid(logit), features


@dataclass(frozen=True, slots=True)
class _DGAFinding:
    """One fired registrable domain -- shared by `detect_dga` (`SignalDraft`) and
    `raw_evidence_dga` (`EvidencePayload`), computed once (`_dga_findings`)."""

    registrable: str
    tld: str
    label: str
    hostnames: list[str]
    ordered_rows: list[EventRow]
    score: float
    features: DGAFeatures


def _dga_findings(rows: Sequence[EventRow], artifact: DGAArtifact) -> list[_DGAFinding]:
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

    findings: list[_DGAFinding] = []
    for registrable, (tld, group_rows) in groups.items():
        label = second_level_label(registrable, tld)
        score, features = score_label(label, artifact)
        if score < artifact.decision_threshold:
            continue
        findings.append(
            _DGAFinding(
                registrable=registrable,
                tld=tld,
                label=label,
                hostnames=sorted(hostnames_by_registrable[registrable])[:20],
                ordered_rows=sorted(group_rows, key=lambda r: r.ts),
                score=score,
                features=features,
            )
        )
    return findings


def detect_dga(
    rows: Sequence[EventRow], *, artifact: DGAArtifact | None = None
) -> list[SignalDraft]:
    artifact = artifact if artifact is not None else load_artifact()

    drafts: list[SignalDraft] = []
    for f in _dga_findings(rows, artifact):
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in f.ordered_rows])
        explanation: dict[str, Any] = {
            "domain": f.registrable,
            "second_level_label": f.label,
            "tld": f.tld,
            "hostnames": f.hostnames,
            "shannon_entropy": f.features.shannon_entropy,
            "neg_ngram_log_likelihood": f.features.neg_ngram_ll,
            "digit_ratio": f.features.digit_ratio,
            "max_consonant_run": f.features.max_consonant_run,
            "len_norm": f.features.len_norm,
            "score": f.score,
            "decision_threshold": artifact.decision_threshold,
            "weights": artifact.weight_map(),
            "intercept": artifact.intercept,
            "n_events": len(f.ordered_rows),
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_DGA,
                entity_type=ENTITY_DOMAIN,
                entity_value=f.registrable,
                raw_score=f.score,
                confidence_raw=f.score,
                window_start=f.ordered_rows[0].ts,
                window_end=f.ordered_rows[-1].ts,
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def raw_evidence_dga(
    rows: Sequence[EventRow], *, artifact: DGAArtifact | None = None
) -> list[RawEvidence]:
    """`EvidencePayload` measurements for every registrable domain `detect_dga` also fires a
    `signals` row for (module docstring; same "ride the signal gate" rationale as `beaconing.
    raw_evidence_beaconing`, CLAUDE.md rule 1). `historical` is deliberately empty --
    docs/v2_migration change 2's own table: "dga | classifier probability, entropy, bigram
    log-likelihood, digit ratio, consonant run | — (probability is already the answer)." No
    `baseline_queries` means this extractor never nominates a candidate on its own (`resolve_
    evidence.py`'s dga branch) -- consistent with a calibrated classifier probability already
    being the judgment a percentile would otherwise stand in for.
    """
    artifact = artifact if artifact is not None else load_artifact()

    raw: list[RawEvidence] = []
    for f in _dga_findings(rows, artifact):
        _event_ids, line_numbers, truncated = cap_evidence_rows(f.ordered_rows)
        measurements: dict[str, Any] = {
            "probability": f.score,
            "shannon_entropy": f.features.shannon_entropy,
            "neg_ngram_log_likelihood": f.features.neg_ngram_ll,
            "digit_ratio": f.features.digit_ratio,
            "max_consonant_run": f.features.max_consonant_run,
            "evidence_truncated": truncated,
        }
        raw.append(
            RawEvidence(
                extractor=EXTRACTOR_DGA,
                entity={"type": ENTITY_DOMAIN, "value": f.registrable},
                window=(f.ordered_rows[0].ts, f.ordered_rows[-1].ts),
                measurements=measurements,
                contributing_line_numbers=line_numbers,
            )
        )
    return raw
