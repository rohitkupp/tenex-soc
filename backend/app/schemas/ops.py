"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's Ops section."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class QueueDepthOut(BaseModel):
    queue: str
    messages: int
    consumers: int


class QueueDepthsResponse(BaseModel):
    items: list[QueueDepthOut]


class DeadLetterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: uuid.UUID | None
    stage: str
    payload: dict[str, Any]
    error: str
    attempts: int
    created_at: datetime
    retried_at: datetime | None


class DeadLetterListResponse(BaseModel):
    items: list[DeadLetterOut]
    next_cursor: str | None


class DeadLetterRetryResponse(BaseModel):
    id: int
    republished_to: str
    retried_at: datetime
