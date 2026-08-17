"""Pipeline run state for one upload. M1 only creates the row (`status='queued'`) —
the orchestrator that actually advances `stage`/`progress`/`counters` lands at M4."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, text
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

    # Path A's narrative (migration change 14, `app.agent.orchestrator.narrate_analysis`). The
    # `triage` stage has always generated this once per analysis; before these columns existed it
    # kept only the cost and dropped the prose, so the UI had to offer a button that re-ran — and
    # re-paid for — a call the pipeline had already made. Persisted here so the run the analyst
    # already paid for is the one they read. `narrative` is NULL when the Narrator has not run or
    # failed; the other columns are only meaningful alongside a non-NULL `narrative`.
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_phases: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    narrative_citation_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    narrative_invalid_citations: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    narrative_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), nullable=True)
    narrative_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # change 8's semantic domain findings. `GET /analyses/{id}/overview` used to produce these
    # with a live `assess_domain_semantics` call *inside the request*, so every page load, reload
    # and tab switch waited on — and paid for — an LLM round trip. That was the single largest
    # cost in that endpoint. Computed once in `triage` now and read from here.
    domain_semantic_findings: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    domain_semantics_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # NOTE: docs/02-DATA-MODEL.md defines this table without a `created_at` column —
    # matched exactly, on purpose. "GET /api/analyses newest first" (docs/09) is
    # therefore implemented by ordering on the parent upload's `created_at` (uploads
    # and analyses are created together, 1:1, in the upload endpoint), not by adding a
    # column the data model doesn't specify. See app/api/analyses.py.
