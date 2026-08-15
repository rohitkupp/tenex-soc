"""Pipeline run state for one upload. M1 only creates the row (`status='queued'`) —
the orchestrator that actually advances `stage`/`progress`/`counters` lands at M4."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Numeric, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Float, Integer, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Analysis(Base, TenantScopedMixin):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    upload_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("uploads.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="queued")
    stage: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[float] = mapped_column(Float, nullable=False, server_default="0")
    pending_parsers: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    counters: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, server_default="{}")
    parse_failure_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # NOTE: docs/02-DATA-MODEL.md defines this table without a `created_at` column —
    # matched exactly, on purpose. "GET /api/analyses newest first" (docs/09) is
    # therefore implemented by ordering on the parent upload's `created_at` (uploads
    # and analyses are created together, 1:1, in the upload endpoint), not by adding a
    # column the data model doesn't specify. See app/api/analyses.py.
