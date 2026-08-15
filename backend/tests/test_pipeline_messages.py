"""`app.pipeline.messages` — the StageMessage envelope and its size bound.

docs/01: "Queues carry references, never rows." `encode_stage_message` is the
enforcement of that — this file proves it actually rejects an oversized payload rather
than silently truncating or accepting it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.pipeline.messages import (
    MAX_MESSAGE_BYTES,
    StageMessage,
    StageMessageTooLargeError,
    decode_stage_message,
    encode_stage_message,
)


def _message(**overrides: object) -> StageMessage:
    defaults: dict[str, object] = {
        "analysis_id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "stage": "parse",
        "storage_ref": "tenant/upload-key",
        "source_type": "zscaler",
        "attempt": 0,
        "emitted_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return StageMessage.model_validate(defaults)


def test_round_trips_through_encode_decode() -> None:
    message = _message()
    decoded = decode_stage_message(encode_stage_message(message))
    assert decoded == message


def test_matches_docs_01_field_set_exactly() -> None:
    message = _message()
    fields = set(message.model_dump().keys())
    assert fields == {
        "analysis_id",
        "tenant_id",
        "stage",
        "storage_ref",
        "source_type",
        "attempt",
        "emitted_at",
    }


def test_storage_ref_and_source_type_are_optional() -> None:
    message = _message(storage_ref=None, source_type=None)
    assert message.storage_ref is None
    assert message.source_type is None


def test_attempt_defaults_to_zero() -> None:
    raw = {
        "analysis_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "stage": "ingest",
        "emitted_at": datetime.now(UTC).isoformat(),
    }
    message = StageMessage.model_validate(raw)
    assert message.attempt == 0
    assert message.storage_ref is None
    assert message.source_type is None


def test_rejects_unknown_fields() -> None:
    """`extra="forbid"` — a stray field is a bug (or an attempt to smuggle a row through
    the envelope), not something to silently accept."""
    with pytest.raises(ValidationError):
        _message(unexpected_field="nope")


def test_oversized_payload_is_rejected_loudly() -> None:
    huge_storage_ref = "s3://tenex-uploads/" + ("x" * (MAX_MESSAGE_BYTES * 2))
    message = _message(storage_ref=huge_storage_ref)
    with pytest.raises(StageMessageTooLargeError):
        encode_stage_message(message)


def test_message_at_the_bound_is_accepted() -> None:
    """A message that fits comfortably (the envelope is a few hundred bytes for
    realistic values) never trips the bound — this isn't accidentally rejecting normal
    traffic."""
    message = _message()
    body = encode_stage_message(message)
    assert len(body) < MAX_MESSAGE_BYTES
