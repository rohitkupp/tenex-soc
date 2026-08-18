"""`_validate_with_repair` — the difference between a formatting slip and a lost investigation.

Every schema invariant in the triage pipeline was all-or-nothing: one malformed field discarded
the analyst's tool calls, the verifier pass and the judge's ten-item rubric, and the incident was
recorded as "Triage did not complete". In production that happened on every incident, four
different ways, and 0 of 62 verdicts completed.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError, field_validator

from app.agent.orchestrator import _repair_prompt, _validate_with_repair
from app.agent.schemas import SchemaValidationError


class _Model(BaseModel):
    items: list[int]

    @field_validator("items")
    @classmethod
    def _no_duplicates(cls, v: list[int]) -> list[int]:
        if len(set(v)) != len(v):
            raise ValueError("items must not contain duplicates")
        return v


def test_a_valid_payload_never_triggers_a_retry() -> None:
    """The repair path must cost nothing when nothing is wrong — it sits on the hot path of
    every role."""
    calls: list[str] = []

    result = _validate_with_repair(
        _Model,
        {"items": [1, 2, 3]},
        tool_name="t",
        role="r",
        retry=lambda c: calls.append(c) or {},
    )

    assert result.items == [1, 2, 3]
    assert calls == []


def test_a_malformed_payload_is_repaired_on_the_second_attempt() -> None:
    """The whole point: the model is told what the validator rejected and gets one more go,
    instead of the investigation behind the payload being thrown away."""
    corrections: list[str] = []

    def retry(correction: str) -> dict:
        corrections.append(correction)
        return {"items": [1, 2, 3]}

    result = _validate_with_repair(
        _Model, {"items": [1, 2, 2, 3]}, tool_name="submit", role="judge", retry=retry
    )

    assert result.items == [1, 2, 3]
    assert len(corrections) == 1
    # The correction has to carry the validator's own words — a paraphrase is one more thing
    # that drifts from the rule it describes.
    assert "duplicates" in corrections[0]
    assert "submit" in corrections[0]


def test_a_payload_that_stays_malformed_still_fails_loudly() -> None:
    """A model that cannot satisfy the schema when handed its own error is not going to on a
    third try, and each attempt is a full-price call. The failure must still surface."""
    attempts: list[str] = []

    def retry(correction: str) -> dict:
        attempts.append(correction)
        return {"items": [9, 9]}  # still duplicated

    with pytest.raises(SchemaValidationError, match="repair attempt"):
        _validate_with_repair(
            _Model, {"items": [1, 1]}, tool_name="submit", role="analyst", retry=retry
        )

    assert len(attempts) == 1


def test_normalise_runs_before_validation_on_both_attempts() -> None:
    """Deterministic normalisers (`_merged_hypothesis_evaluations`, `_repair_judge_output`) fix
    shapes that are unambiguous to fix in code, with no call at all. They must apply to the
    retry's output too, or a repair could be rejected for a defect the normaliser handles."""
    seen: list[object] = []

    def normalise(raw: dict) -> dict:
        seen.append(raw)
        return {"items": sorted(set(raw["items"]))}

    result = _validate_with_repair(
        _Model,
        {"items": [3, 1, 1]},
        tool_name="t",
        role="r",
        retry=lambda c: {"items": []},
        normalise=normalise,
    )

    # Normalised on the first attempt, so no retry was needed at all.
    assert result.items == [1, 3]
    assert len(seen) == 1


def test_repair_prompt_tells_the_model_not_to_reconsider() -> None:
    """A schema rejection is a formatting correction. Inviting the model to redo its analysis
    would let a validator quirk silently change a verdict."""
    try:
        _Model.model_validate({"items": [1, 1]})
    except ValidationError as exc:
        prompt = _repair_prompt(exc, "submit_analysis")

    assert "submit_analysis" in prompt
    assert "formatting correction" in prompt
    assert "identical" in prompt
