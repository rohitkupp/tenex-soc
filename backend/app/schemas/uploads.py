"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's Uploads & analyses section."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, field_validator


class UploadCreateResponse(BaseModel):
    upload_id: uuid.UUID
    detected_sources: list[str]
    analysis_id: uuid.UUID


class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    upload_id: uuid.UUID
    status: str
    stage: str | None
    progress: float
    pending_parsers: int
    counters: dict[str, object]
    parse_failure_rate: float | None
    llm_cost_usd: Decimal | None
    # The Timeline tab's stored windowed summary (`analyses.event_timeline_summary`), so the tab
    # renders what was already generated instead of asking the analyst to pay again. NULL until
    # someone requests one — unlike `narrative`, the pipeline does not produce this.
    event_timeline_summary: dict[str, object] | None = None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None

    @field_validator("counters", mode="before")
    @classmethod
    def _drop_internal_counter_keys(cls, value: object) -> object:
        """`analyses.counters` (docs/02) is the pipeline's only place to keep a running
        per-analysis tally, so the parse stage's own cross-parser bookkeeping — a key
        like `_parse_failed_lines`, needed to aggregate `parse_failure_rate` correctly
        across concurrently-finishing parsers without a last-write-wins race; see
        `app.pipeline.stages.parse` — lives in the same JSONB column as the four public
        counters (`events`/`signals`/`incidents`/`needs_attention`, docs/09). This
        endpoint is the one place besides the SSE stream that surfaces `counters`
        externally (`app.api.stream` already filters via
        `app.pipeline.contracts.public_counters`), so it applies the same underscore
        convention here rather than leaking pipeline-internal keys into the API
        response."""
        if isinstance(value, dict):
            return {k: v for k, v in value.items() if not str(k).startswith("_")}
        return value


class AnalysisListResponse(BaseModel):
    items: list[AnalysisOut]
    next_cursor: str | None


class AnalysisRetryResponse(BaseModel):
    """`POST /api/analyses/{id}/retry` — docs/v2_migration change 27's replacement for
    `POST /api/ops/dead-letters/{id}/retry` (deleted along with the rest of `/ops`).
    Same republish semantics, just addressed by `analysis_id` instead of a dead-letter
    id, since the analyst-facing retry action starts from the failed analysis, not from
    an ops console the analyst never sees."""

    analysis_id: uuid.UUID
    republished_to: str
    retried_at: datetime
