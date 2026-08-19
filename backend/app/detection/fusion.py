"""Incident-level score fusion, the graph bonus, and severity (docs/04 §Fusion, docs/05
"Incident scoring"). M10.

Three formulas, applied in this exact order, once each — see each function's own docstring for
why double-applying any of them would double-count evidence:

1. `fuse_signals` — per-detector calibrated confidences -> one base probability
   (docs/04 §Fusion: `fused = 1 - Π(1 - w_d * c_d)`).
2. `apply_graph_bonus` — the base score, boosted by cross-**layer** corroboration and community
   signal density (docs/05's rewritten formula). This is the *only* corroboration bonus in the
   system — see its docstring for the removed `multi_source` term this replaces.
3. `severity_for_score` — fixed thresholds on the final `fused_score`. **Severity is set here,
   never by the LLM** (CLAUDE.md rule 5) — the agent (M11) may record its own opinion for the
   `severity_disagreement` metric, but it never determines `incidents.severity`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "GRAPH_BONUS_COMMUNITY_DENSITY_WEIGHT",
    "GRAPH_BONUS_LAYER_WEIGHT",
    "MAX_FUSED_SCORE",
    "SEVERITY_THRESHOLDS",
    "FusionInput",
    "IncidentScore",
    "Severity",
    "anomaly_confidence_from_fused_score",
    "apply_graph_bonus",
    "fuse_signals",
    "score_incident",
    "severity_for_score",
]

Severity = Literal["critical", "high", "medium", "low"]

# docs/05: `graph_bonus = 1 + 0.15*log1p(n_distinct_detector_layers) + 0.10*min(community_signal_density, 1)`
GRAPH_BONUS_LAYER_WEIGHT: Final[float] = 0.15
GRAPH_BONUS_COMMUNITY_DENSITY_WEIGHT: Final[float] = 0.10
MAX_FUSED_SCORE: Final[float] = 0.99

# docs/04 §Fusion "Severity": >=0.85 critical, >=0.65 high, >=0.40 medium, else low. Ordered
# highest-first so `severity_for_score` can walk it top-down.
SEVERITY_THRESHOLDS: Final[tuple[tuple[float, Severity], ...]] = (
    (0.85, "critical"),
    (0.65, "high"),
    (0.40, "medium"),
)


def fuse_signals(confidences: list[float], weights: list[float]) -> float:
    """docs/04 §Fusion: `fused = 1 - Π(1 - w_d * c_d)` over an incident's contributing signals.

    `c_d` is each signal's *calibrated* confidence (`app.detection.calibration`) and `w_d` is
    `detector_stats.fusion_weight` for that signal's detector (docs/08: analyst feedback tunes
    this over time; defaults to 1.0 for a detector with no feedback history yet). Order-
    independent (a product), so callers don't need to sort `confidences`/`weights` — they only
    need to be the same length and pairwise-aligned.

    An incident with no contributing signals has no evidence and fuses to `0.0` — the empty
    product is 1, so `1 - 1 == 0`, which is also the mathematically correct base case (no
    hypotheses raised, no probability of a true incident) rather than a special-cased branch.

    `w_d * c_d` is clamped to `[0, 1]` per term before multiplying: `c_d` is already a
    probability (`[0, 1]` by construction, `app.detection.calibration.IsotonicCalibrator`
    guarantees this), but `w_d` is an analyst-adjustable weight with no hard-coded ceiling
    (docs/08 lets it move with feedback), so a weight pushed above `1/c_d` by aggressive positive
    feedback must not make `1 - w_d*c_d` go negative — that would make one *additional* signal
    (multiplying in one more `(1 - w_d*c_d)` term) *increase* `1 - Π(...)`'s complement past 1
    and the fused score would fall as evidence accumulates, the opposite of what fusion means.
    """
    if len(confidences) != len(weights):
        raise ValueError(
            f"confidences and weights must be the same length, got {len(confidences)} "
            f"and {len(weights)}"
        )
    product = 1.0
    for c, w in zip(confidences, weights, strict=True):
        # Balanced-midpoint rescale: `2c - 1`, floored at zero. Calibrated confidences are
        # class-balanced posteriors (docs/04 §Per-detector calibration), where 0.5 means "this
        # firing carries no information" — likelihood ratio 1. Noisy-OR's neutral element is 0,
        # not 0.5: fed the posteriors directly, four completely uninformative detectors fuse to
        # 1 - 0.5^4 ≈ 0.94 and every multi-detector incident lands critical, which is exactly
        # what production showed the day balanced calibration shipped (benign single-user
        # incidents at fused 0.99 beside the real exfiltration, indistinguishable). Rescaling
        # makes the fused input "evidence in excess of uninformative": 0.5 contributes nothing,
        # 1.0 contributes fully, and anything the calibrator scored *below* its balanced
        # midpoint — more benign-like than not — contributes nothing rather than negative
        # evidence, keeping the noisy-OR's independence semantics intact.
        evidence = max(0.0, 2.0 * c - 1.0)
        term = max(0.0, min(1.0, w * evidence))
        product *= 1.0 - term
    return 1.0 - product


def apply_graph_bonus(
    base_score: float, *, n_distinct_detector_layers: int, community_signal_density: float
) -> float:
    """docs/05's rewritten graph bonus — the system's **only** corroboration-across-evidence-
    types bonus, applied exactly once, at this stage.

    ```
    graph_bonus = 1 + 0.15*log1p(n_distinct_detector_layers) + 0.10*min(community_signal_density, 1)
    fused_score = min(base_score * graph_bonus, 0.99)
    ```

    **This replaces the old design's separate `multi_source` term** (`fused *= 1.25` if an
    incident spanned proxy and identity signals) — with ZScaler as the only log source, that axis
    is gone outright, not renamed. `n_distinct_detector_layers` (rule/signal/ml/graph — docs/02's
    `detector_layer` enum) now carries the *entire* weight of "independent corroboration is
    stronger evidence," measured by detection method instead of by source. docs/04 §Fusion is
    explicit that it does **not** apply a second, separate layer-diversity bonus at the fusion
    stage (`fuse_signals` above) — this function is the only place that credit is given. A caller
    must never call both a fusion-stage layer bonus *and* this one on the same incident.
    """
    bonus = (
        1.0
        + GRAPH_BONUS_LAYER_WEIGHT * math.log1p(max(0, n_distinct_detector_layers))
        + GRAPH_BONUS_COMMUNITY_DENSITY_WEIGHT * min(max(0.0, community_signal_density), 1.0)
    )
    return min(base_score * bonus, MAX_FUSED_SCORE)


def anomaly_confidence_from_fused_score(fused_score: float) -> float:
    """docs/v2_migration change 3 ("two confidences, never mixed"): `incidents.anomaly_confidence`
    — the calibrated "how unusual is this vs. history" number an analyst reads directly, on a
    0-100 scale, derived from `fused_score` (already isotonic-calibrated end to end through
    `fuse_signals`/`apply_graph_bonus` above), not recomputed from raw detector scores a second
    time. This is the *only* place that conversion happens — every caller that persists an
    `Incident` row derives `anomaly_confidence` by calling this function on the same `fused_score`
    it is about to store, so the two columns can never silently drift apart.

    Never conflate this with `threat_confidence` (`app.agent.schemas.TriageVerdictOut`) — that is
    the LLM's own low/moderate/high judgement of how well the evidence supports *one specific*
    security interpretation, sourced entirely differently (hypothesis evaluation, not calibration)
    and expressed on a different scale. A behaviour can score 96 here and still turn out to be a
    scheduled backup job — this number measures rarity, not malice (CLAUDE.md rule 5: the LLM,
    not this function, is the only thing that speaks to intent, and even it never sets priority).

    Clamped to `[0, 1]` before scaling (`fused_score` is already bounded to `[0, MAX_FUSED_SCORE]`
    by `apply_graph_bonus`, but this function does not assume every caller went through that exact
    path) and rounded to one decimal place: enough precision to be a useful "X/100" reading,
    coarse enough that `app.agent.verifier.verify_anomaly_confidence` comparing the LLM's echoed
    value back against this one isn't chasing float noise introduced by Postgres' `REAL` (4-byte
    float) column round-tripping the value.
    """
    return round(min(max(fused_score, 0.0), 1.0) * 100, 1)


def severity_for_score(fused_score: float) -> Severity:
    """docs/04 §Fusion "Severity" — fixed thresholds on the post-graph-bonus `fused_score`.
    Deterministic and total: every score in `[0, 1]` (and anything outside it, clamped) maps to
    exactly one of the four severities, always via this function — never inferred by the LLM
    (CLAUDE.md rule 5)."""
    for threshold, severity in SEVERITY_THRESHOLDS:
        if fused_score >= threshold:
            return severity
    return "low"


@dataclass(frozen=True, slots=True)
class FusionInput:
    """One contributing signal's fusion inputs — detector identity kept alongside the numbers so
    `score_incident` can also report `n_distinct_detector_layers` without a second pass over the
    incident's signals."""

    detector_key: str
    detector_layer: str
    confidence: float
    fusion_weight: float = 1.0


@dataclass(frozen=True, slots=True)
class IncidentScore:
    base_score: float
    fused_score: float
    severity: Severity
    n_distinct_detector_layers: int
    community_signal_density: float
    # docs/v2_migration change 3: `incidents.anomaly_confidence`, 0-100, derived from `fused_score`
    # by `anomaly_confidence_from_fused_score` — see that function's docstring for why this is the
    # single derivation point rather than something each caller recomputes.
    anomaly_confidence: float


def score_incident(signals: list[FusionInput], *, community_signal_density: float) -> IncidentScore:
    """The full pipeline for one incident: fuse -> graph bonus -> severity, in that order (see
    module docstring). Convenience wrapper over the three functions above for callers (incident
    formation) that have a signal list and a community density in hand and want the final,
    ready-to-persist `(fused_score, severity, anomaly_confidence)` triple in one call.
    """
    # Fuse over the strongest signal *per detector*, not every signal. `fuse_signals` is a
    # noisy-OR, which assumes each term is independent evidence. Repeated firings of the same
    # detector on the same incident violate that outright: `signal.beaconing` firing in 40
    # windows on one src_ip is one behaviour observed 40 times, not 40 independent findings.
    # Fed every row, the product drives to zero and the score pins at the MAX_FUSED_SCORE
    # ceiling regardless of how weak the evidence is — 100 signals at c=0.05 already fuse to
    # 0.994. That is exactly the observed saturation: fifteen incidents all reporting a
    # fused_score of 0.99 and an anomaly_confidence of 99.0, which tells an analyst nothing
    # about which to open first.
    #
    # Taking the max per detector keeps corroboration *across* methods (the thing the score is
    # meant to measure, and what `apply_graph_bonus` separately rewards) while refusing to let
    # one chatty detector manufacture certainty on its own.
    strongest_by_detector: dict[str, FusionInput] = {}
    for sig in signals:
        best = strongest_by_detector.get(sig.detector_key)
        if (
            best is None
            or sig.confidence * sig.fusion_weight > best.confidence * best.fusion_weight
        ):
            strongest_by_detector[sig.detector_key] = sig
    contributing = list(strongest_by_detector.values())

    base = fuse_signals(
        [s.confidence for s in contributing], [s.fusion_weight for s in contributing]
    )
    n_layers = len({s.detector_layer for s in signals})
    fused = apply_graph_bonus(
        base,
        n_distinct_detector_layers=n_layers,
        community_signal_density=community_signal_density,
    )
    return IncidentScore(
        base_score=base,
        fused_score=fused,
        severity=severity_for_score(fused),
        n_distinct_detector_layers=n_layers,
        community_signal_density=community_signal_density,
        anomaly_confidence=anomaly_confidence_from_fused_score(fused),
    )
