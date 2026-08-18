"""Evidence confidence — a number the machine computes from the Judge's rubric grades.

**Why this exists.** The pipeline already carried two confidence-shaped values and neither
answers "how much should an analyst trust this triage?":

* `incidents.fused_score` / `anomaly_confidence` is calibrated detector fusion — *how unusual
  is this versus history*. It knows nothing about whether the reasoning built on top of it
  holds up.
* `triage_verdicts.threat_confidence` is a `low|moderate|high` label the Presenter emits in
  the same call as its prose. Nothing constrains it to the evidence; it is exactly the
  "blindly generated confidence value" this module exists to replace.

**The design.** The Judge already grades every finding against `JUDGE_RUBRIC`'s ten
evidentiary items, one boolean and a note each, having read the same evidence package the
Analyst worked from. Those ten grades *are* an evidence assessment — they were simply being
thrown away after the PASS/REVISE/REJECT call. This module weights them into a score.

So the split is the migration's governing sentence applied to confidence itself: **the LLM
interprets (does this item hold up against the evidence?), the machine calculates (what is
that worth?)**. No stage is ever asked to emit the number, which means it cannot be asserted,
cannot drift with prose style, and cannot be talked upward by a confident-sounding model. It
also satisfies CLAUDE.md rule 5 one hop out: the arithmetic is code, reproducible from stored
grades forever, and every value decomposes into "these items failed" for a UI to render.

**Weights.** Ten items do not bear equally on trustworthiness. The three citation/evidence
integrity items (1, 2, 3) carry 45% between them because a finding whose claims are not in
the evidence is not a weak finding, it is a fabricated one. Self-calibration (8) and the
overclaim guard (10) carry least — not because they are unimportant, but because they are
downstream symptoms: a finding that fails them usually fails an integrity item first, and
double-counting would make one defect look like two.

**Caps.** A weighted mean alone lets nine cheap passes bury one disqualifying failure — a
finding whose citations do not support it would still score 0.85. Failing a `_CAPS` item
therefore ceilings the result regardless of the rest. Caps are ceilings, never floors, and
the tightest applicable one wins. Only *independent* failures cap: see `_CAPS` on why items 1
and 2 deliberately do not, despite being the two heaviest-weighted integrity items.

The caps are deliberately moderate (0.45-0.55, not 0.1). A capped finding should read as
"corroborate this before acting", which is a real analyst state, rather than as a broken
detector — and the cap's job is to stop a defective finding from *outranking* a sound one,
which a 0.5 ceiling under a 0.75 "high" band already does.
"""

from __future__ import annotations

from typing import Final, Iterable, Literal, Sequence

from app.agent.schemas import JUDGE_RUBRIC

__all__ = [
    "ConfidenceBand",
    "EvidenceConfidence",
    "RubricGrade",
    "JUDGE_RUBRIC_WEIGHTS",
    "band_for",
    "evidence_confidence",
    "aggregate_evidence_confidence",
]

ConfidenceBand = Literal["high", "moderate", "low", "very_low"]


class RubricGrade:
    """The minimal shape this module needs from a graded rubric item.

    Deliberately structural rather than importing `JudgeRubricItem`: the scorer is a pure
    function over `(item, satisfied)` pairs and is tested with plain tuples, so it must not
    depend on the agent's Pydantic layer. `from_items` adapts anything with those attributes.
    """

    __slots__ = ("item", "satisfied")

    def __init__(self, item: int, satisfied: bool) -> None:
        self.item = item
        self.satisfied = satisfied

    @staticmethod
    def from_items(items: Iterable[object]) -> list["RubricGrade"]:
        return [
            RubricGrade(item=int(getattr(i, "item")), satisfied=bool(getattr(i, "satisfied")))
            for i in items
        ]


# Index i holds the weight for rubric item i+1. Must sum to exactly 1.0 and stay aligned with
# `JUDGE_RUBRIC` -- both invariants are asserted at import time below and in the unit tests, so
# adding an eleventh rubric item fails loudly here rather than silently renormalizing the scale.
JUDGE_RUBRIC_WEIGHTS: Final[tuple[float, ...]] = (
    0.18,  # 1. every factual claim supported by supplied evidence
    0.12,  # 2. all numerical claims appear exactly in the evidence
    0.15,  # 3. each cited log line actually supports the statement
    0.08,  # 4. cited ATT&CK document supports the mapping
    0.10,  # 5. observation clearly separated from inference
    0.09,  # 6. benign alternatives considered
    0.10,  # 7. all required evidence actually present
    0.06,  # 8. confidence matches evidence strength
    0.07,  # 9. technique observable from Zscaler proxy telemetry
    0.05,  # 10. maliciousness claimed only where evidence establishes it
)

# item number -> ceiling imposed when that item is graded unsatisfied.
#
# **Only genuinely independent failures cap.** Items 1, 2 and 3 are not three separate tests.
# Item 1 asks whether *every* factual claim is supported, which its own quantifier makes a
# roll-up: it fails automatically whenever item 2 or item 3 fails. Capping on item 1 as well as
# on its constituents charged one defect twice, and because item 1 also carries the heaviest
# weight, the commonest artifact in this pipeline -- a number written in a different form than
# the evidence spells it, which the report-only verifier tolerates by design -- was landing the
# maximum penalty available. The first two production runs scored eight of ten incidents at
# exactly item 1's old ceiling, and the Judge's own note on one of them read "core claim ... is
# supported by sigma rule 37561, ML detectors, and burst evidence".
#
# So item 1 keeps its weight (a roll-up failing is real information) and loses its cap, and item
# 2 loses its cap too: an unmatched number is a precision defect, not a fabrication. What remains
# is the pair that cannot be explained away -- a citation that does not support the statement it
# is attached to (3), and a technique this telemetry cannot observe at all (9).
_CAPS: Final[dict[int, float]] = {
    3: 0.50,  # a citation that does not support its statement
    9: 0.50,  # a technique this telemetry cannot observe
}

# Band thresholds, inclusive lower bounds. `moderate` starting at 0.50 means a finding must
# clear more than half the weighted rubric to stop reading as weak, and every `_CAPS` ceiling
# sits below `high` by construction -- a capped finding can never present as high confidence.
_BANDS: Final[tuple[tuple[float, ConfidenceBand], ...]] = (
    (0.75, "high"),
    (0.50, "moderate"),
    (0.25, "low"),
    (0.0, "very_low"),
)

if len(JUDGE_RUBRIC_WEIGHTS) != len(JUDGE_RUBRIC):  # pragma: no cover - import-time invariant
    raise RuntimeError(
        f"JUDGE_RUBRIC_WEIGHTS has {len(JUDGE_RUBRIC_WEIGHTS)} entries but JUDGE_RUBRIC has "
        f"{len(JUDGE_RUBRIC)}; every rubric item needs a weight or the scale renormalizes silently"
    )
if abs(sum(JUDGE_RUBRIC_WEIGHTS) - 1.0) > 1e-9:  # pragma: no cover - import-time invariant
    raise RuntimeError(f"JUDGE_RUBRIC_WEIGHTS must sum to 1.0, got {sum(JUDGE_RUBRIC_WEIGHTS)}")


class EvidenceConfidence:
    """A score, its band, and the decomposition that produced it.

    `failed_items` is what makes the number defensible rather than merely reproducible: it is
    the exact list of rubric items the Judge marked unsatisfied, which is what the UI renders
    on hover and what an analyst disputing the score would argue with.
    """

    __slots__ = ("score", "band", "failed_items", "capped_by", "graded_items")

    def __init__(
        self,
        score: float,
        band: ConfidenceBand,
        failed_items: list[int],
        capped_by: int | None,
        graded_items: int,
    ) -> None:
        self.score = score
        self.band = band
        self.failed_items = failed_items
        self.capped_by = capped_by
        self.graded_items = graded_items

    def as_basis(self) -> dict[str, object]:
        """The JSONB payload persisted alongside the score, so a value can be explained years
        later without re-running anything. Rubric *text* is stored, not just indices -- the
        wording of an item can change (it already has once, for polarity), and a stored basis
        that says "item 7" would silently start meaning something else."""
        return {
            "score": self.score,
            "band": self.band,
            "capped_by": self.capped_by,
            "graded_items": self.graded_items,
            "failed_items": [
                {"item": i, "text": JUDGE_RUBRIC[i - 1]}
                for i in self.failed_items
                if 1 <= i <= len(JUDGE_RUBRIC)
            ],
        }


def band_for(score: float) -> ConfidenceBand:
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return "very_low"


def evidence_confidence(grades: Sequence[RubricGrade]) -> EvidenceConfidence | None:
    """Score one finding's rubric assessment. `None` when nothing was graded.

    Returning `None` rather than 0.0 for an ungraded finding is the important case: a triage
    that fell back to `needs_review` before the Judge ran has *no* evidence assessment, which
    is a different statement from "the evidence was assessed and found worthless". The column
    is nullable end-to-end for exactly this reason, and the UI renders it as an em dash.

    Unknown item numbers are ignored rather than raising: `JudgeVerdict` already validates
    completeness upstream, and a scorer that throws would turn a cosmetic schema drift into a
    failed triage over a value that is not load-bearing for the disposition.
    """
    seen: dict[int, bool] = {}
    for g in grades:
        if 1 <= g.item <= len(JUDGE_RUBRIC_WEIGHTS):
            seen[g.item] = g.satisfied
    if not seen:
        return None

    # Normalize over the items actually graded, not over all ten. A partially-graded assessment
    # would otherwise be scored as if its missing items had failed, which reads as a weak
    # finding rather than as an incomplete grading.
    total_weight = sum(JUDGE_RUBRIC_WEIGHTS[i - 1] for i in seen)
    earned = sum(JUDGE_RUBRIC_WEIGHTS[i - 1] for i, ok in seen.items() if ok)
    score = earned / total_weight if total_weight > 0 else 0.0

    failed = sorted(i for i, ok in seen.items() if not ok)
    capped_by: int | None = None
    for item in failed:
        cap = _CAPS.get(item)
        if cap is not None and score > cap:
            score = cap
            capped_by = item

    score = round(max(0.0, min(1.0, score)), 4)
    return EvidenceConfidence(
        score=score,
        band=band_for(score),
        failed_items=failed,
        capped_by=capped_by,
        graded_items=len(seen),
    )


def aggregate_evidence_confidence(
    per_finding: Sequence[EvidenceConfidence | None],
) -> EvidenceConfidence | None:
    """Combine the surviving findings' scores into one incident-level value.

    The mean, not the max. An incident is presented to an analyst as a single claim, and the
    weakest surviving finding is part of that claim -- taking the max would let one airtight
    finding launder three shaky ones sitting in the same case file. `None` entries are skipped
    rather than counted as zero (see `evidence_confidence` on why absent differs from bad).

    Rejected findings never reach here: the orchestrator drops them before presentation, so
    they correctly contribute nothing rather than dragging the incident down twice.
    """
    scored = [c for c in per_finding if c is not None]
    if not scored:
        return None
    mean = sum(c.score for c in scored) / len(scored)
    # Union of what failed anywhere, so the incident-level explanation names every defect that
    # contributed -- an analyst asking "why 0.48?" wants all of them, not one finding's share.
    failed = sorted({i for c in scored for i in c.failed_items})
    capped = [c.capped_by for c in scored if c.capped_by is not None]
    mean = round(max(0.0, min(1.0, mean)), 4)
    return EvidenceConfidence(
        score=mean,
        band=band_for(mean),
        failed_items=failed,
        capped_by=capped[0] if capped else None,
        graded_items=sum(c.graded_items for c in scored),
    )
