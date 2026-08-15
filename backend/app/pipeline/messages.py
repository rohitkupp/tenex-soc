"""The message envelope — docs/01-ARCHITECTURE.md "Message envelope", matched exactly:

```python
class StageMessage(BaseModel):
    analysis_id: UUID
    tenant_id: UUID
    stage: str
    storage_ref: str | None      # s3://bucket/key for raw or parsed artifacts
    source_type: str | None      # zscaler (the only registered source; Okta/CloudTrail removed)
    attempt: int = 0
    emitted_at: datetime
```

"Bulk data goes to Postgres or MinIO. Queues carry references, never rows." —
`MAX_MESSAGE_BYTES` and `encode_stage_message` are the enforcement: every publish call
site in `app.queue`/`app.pipeline` goes through `encode_stage_message`, which raises
`StageMessageTooLargeError` (loud, not a silent truncation) if the serialized envelope
exceeds the bound. The bound itself is generous for what this envelope actually needs
(two UUIDs, a couple of short strings, an int, a timestamp — a few hundred bytes in
practice) and stingy for what it must never smuggle in: a batch of event rows, a raw
log line, an LLM prompt. 4 KiB catches that class of mistake immediately rather than
letting it degrade queue throughput silently in production.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

MAX_MESSAGE_BYTES = 4096


class StageMessageTooLargeError(ValueError):
    """Raised instead of silently publishing an oversized message. Queues carry
    references, never rows (docs/01) — this is what makes that a fact, not a
    convention someone can forget."""


class StageMessage(BaseModel):
    """Every inter-service message uses this shape — docs/01, field-for-field."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: uuid.UUID
    tenant_id: uuid.UUID
    stage: str
    storage_ref: str | None = None
    source_type: str | None = None
    attempt: int = 0
    emitted_at: datetime


def encode_stage_message(message: StageMessage) -> bytes:
    """`StageMessage` -> wire bytes, enforcing `MAX_MESSAGE_BYTES`. Every publish call
    site (`app.queue.publish`, `app.pipeline.base_worker`'s retry/dead-letter paths)
    goes through this rather than calling `model_dump_json` directly."""
    body = message.model_dump_json().encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise StageMessageTooLargeError(
            f"StageMessage for analysis={message.analysis_id} stage={message.stage!r} "
            f"serialized to {len(body)} bytes, over the {MAX_MESSAGE_BYTES}-byte bound. "
            "Queues carry references, never rows — put the payload in Postgres or MinIO "
            "and reference it via storage_ref instead."
        )
    return body


def decode_stage_message(body: bytes) -> StageMessage:
    return StageMessage.model_validate_json(body)
