"""`app.agent.confidence` — the rubric-to-number scorer.

Pure arithmetic over the Judge's grades, so this file needs no database, no fixtures, and no
recorded LLM responses. That is the point of keeping the scorer a free function over
`(item, satisfied)` pairs rather than a method on the agent's Pydantic layer.
"""

from __future__ import annotations

import pytest

from app.agent.confidence import (
    JUDGE_RUBRIC_WEIGHTS,
    RubricGrade,
    aggregate_evidence_confidence,
    band_for,
    evidence_confidence,
)
from app.agent.schemas import JUDGE_RUBRIC


def _grades(**overrides: bool) -> list[RubricGrade]:
    """All ten items satisfied unless named otherwise: `_grades(**{"3": False})`."""
    satisfied = {i: True for i in range(1, len(JUDGE_RUBRIC) + 1)}
    for key, value in overrides.items():
        satisfied[int(key)] = value
    return [RubricGrade(item=i, satisfied=v) for i, v in satisfied.items()]


# ---------------------------------------------------------------------------- invariants


def test_weights_align_with_the_rubric_and_sum_to_one() -> None:
    assert len(JUDGE_RUBRIC_WEIGHTS) == len(JUDGE_RUBRIC)
    assert sum(JUDGE_RUBRIC_WEIGHTS) == pytest.approx(1.0)
    assert all(w > 0 for w in JUDGE_RUBRIC_WEIGHTS)


def test_every_rubric_item_is_phrased_so_satisfied_is_good() -> None:
    """The scorer adds weight for `satisfied=True` on every item without exception, so a
    negatively-phrased item would move the score the wrong way with nothing to catch it. Two
    items were originally phrased that way ("Is required evidence missing?"). This asserts the
    obvious markers of that phrasing never come back."""
    inverted_markers = ("missing?", "fabricat", "unsupported?", "overclaim")
    for text in JUDGE_RUBRIC:
        lowered = text.lower()
        assert not any(
            m in lowered for m in inverted_markers
        ), f"rubric item reads as negatively-phrased, so satisfied=True would mean bad: {text!r}"


# ---------------------------------------------------------------------------- scoring


def test_all_satisfied_scores_one_and_bands_high() -> None:
    result = evidence_confidence(_grades())
    assert result is not None
    assert result.score == 1.0
    assert result.band == "high"
    assert result.failed_items == []
    assert result.capped_by is None


def test_all_unsatisfied_scores_zero() -> None:
    result = evidence_confidence([RubricGrade(item=i, satisfied=False) for i in range(1, 11)])
    assert result is not None
    assert result.score == 0.0
    assert result.band == "very_low"
    assert result.failed_items == list(range(1, 11))


def test_ungraded_returns_none_not_zero() -> None:
    """The distinction the nullable column exists for: never assessed is not assessed-and-bad."""
    assert evidence_confidence([]) is None


def test_a_light_failure_lowers_the_score_without_capping() -> None:
    # Item 8 carries the smallest weight and imposes no cap.
    result = evidence_confidence(_grades(**{"8": False}))
    assert result is not None
    assert result.score == pytest.approx(0.94)
    assert result.band == "high"
    assert result.capped_by is None
    assert result.failed_items == [8]


def test_unsupported_citations_cap_the_score_hard() -> None:
    """Nine cheap passes must not bury the one failure that matters. Without the cap this
    scores 0.85 — a finding whose citations do not support it presenting as high confidence."""
    result = evidence_confidence(_grades(**{"3": False}))
    assert result is not None
    assert result.score == 0.50
    assert result.capped_by == 3
    assert result.band == "moderate"


def test_the_rollup_item_does_not_cap_on_its_own() -> None:
    """Item 1 ("is *every* claim supported") fails whenever item 2 or 3 does, so capping on it
    charges one defect twice. Observed in production: a finding the Judge described as
    "supported by sigma rule 37561, ML detectors, and burst evidence" scored at item 1's old
    ceiling purely because some figures were written in a different form than the evidence."""
    result = evidence_confidence(_grades(**{"1": False, "2": False}))
    assert result is not None
    assert result.capped_by is None
    assert result.score == pytest.approx(0.70)
    assert result.band == "moderate"


def test_a_numeric_mismatch_alone_cannot_drag_a_finding_to_low() -> None:
    """The report-only verifier tolerates unmatched numbers by design; the score must not
    re-litigate that as if it were fabrication."""
    result = evidence_confidence(_grades(**{"2": False}))
    assert result is not None
    assert result.band in ("high", "moderate")


def test_tightest_cap_wins_when_several_apply() -> None:
    result = evidence_confidence(_grades(**{"3": False, "9": False}))
    assert result is not None
    assert result.capped_by in (3, 9)
    assert result.score == 0.50


def test_a_cap_is_a_ceiling_never_a_floor() -> None:
    """Failing a capped item alongside most others must not *raise* the score to the cap."""
    grades = [RubricGrade(item=i, satisfied=(i == 5)) for i in range(1, 11)]
    result = evidence_confidence(grades)
    assert result is not None
    assert result.score == pytest.approx(0.10)  # item 5's weight alone, well under the 0.50 cap


def test_caps_only_apply_to_items_that_are_not_rollups_of_other_items() -> None:
    """Guards the reasoning in `_CAPS`, not just its current contents: item 1's wording makes it
    fail whenever 2 or 3 fails, so it must never be a capping item however the weights change."""
    from app.agent.confidence import _CAPS

    assert 1 not in _CAPS
    assert 2 not in _CAPS


def test_partial_grading_normalizes_over_what_was_graded() -> None:
    """Three items graded, all satisfied, scores 1.0 — not 0.4. An incomplete assessment is not
    the same as a finding that failed the items nobody graded."""
    result = evidence_confidence([RubricGrade(item=i, satisfied=True) for i in (4, 5, 6)])
    assert result is not None
    assert result.score == 1.0
    assert result.graded_items == 3


def test_unknown_item_numbers_are_ignored_not_fatal() -> None:
    result = evidence_confidence([RubricGrade(item=99, satisfied=False), *_grades()])
    assert result is not None
    assert result.score == 1.0


def test_no_cap_can_reach_the_high_band() -> None:
    """Structural guarantee: a finding with a disqualifying defect can never present as high."""
    from app.agent.confidence import _BANDS, _CAPS

    high_threshold = next(t for t, b in _BANDS if b == "high")
    assert all(cap < high_threshold for cap in _CAPS.values())


# ---------------------------------------------------------------------------- bands


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1.0, "high"),
        (0.75, "high"),
        (0.7499, "moderate"),
        (0.5, "moderate"),
        (0.4999, "low"),
        (0.25, "low"),
        (0.2499, "very_low"),
        (0.0, "very_low"),
    ],
)
def test_band_boundaries(score: float, expected: str) -> None:
    assert band_for(score) == expected


# ---------------------------------------------------------------------------- aggregation


def test_aggregate_is_the_mean_not_the_max() -> None:
    """One airtight finding must not launder a weak one sharing the case file."""
    strong = evidence_confidence(_grades())
    weak = evidence_confidence([RubricGrade(item=i, satisfied=False) for i in range(1, 11)])
    result = aggregate_evidence_confidence([strong, weak])
    assert result is not None
    assert result.score == pytest.approx(0.5)


def test_aggregate_skips_none_rather_than_counting_it_as_zero() -> None:
    strong = evidence_confidence(_grades())
    result = aggregate_evidence_confidence([strong, None])
    assert result is not None
    assert result.score == 1.0


def test_aggregate_of_nothing_is_none() -> None:
    assert aggregate_evidence_confidence([]) is None
    assert aggregate_evidence_confidence([None, None]) is None


def test_aggregate_unions_the_failed_items_across_findings() -> None:
    a = evidence_confidence(_grades(**{"2": False}))
    b = evidence_confidence(_grades(**{"6": False}))
    result = aggregate_evidence_confidence([a, b])
    assert result is not None
    assert result.failed_items == [2, 6]


# ---------------------------------------------------------------------------- persisted basis


def test_basis_stores_rubric_text_so_a_score_survives_a_reworded_item() -> None:
    result = evidence_confidence(_grades(**{"7": False}))
    assert result is not None
    basis = result.as_basis()
    assert basis["capped_by"] is None
    assert basis["failed_items"] == [{"item": 7, "text": JUDGE_RUBRIC[6]}]
    assert basis["band"] == result.band
    assert basis["score"] == result.score
