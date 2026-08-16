"""`exemplar_bank_entries` — change 21 mechanism 10, "curated exemplar bank" (gated).

Distinct from mechanism 9 (`app.learning.memory`, dynamic pgvector retrieval, no approval): this
is "a stable set of analyst-corrected findings pinned into the prompt, covering the most frequent
error modes ... deliberate curriculum," per change 21. An analyst-corrected finding is proposed
(`app.models.learning_proposal`, `mechanism=10`) and only lands here — the durable, curated set a
future Analyst-stage prompt integration would pin verbatim — once a human accepts it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class ExemplarBankEntry(Base, TenantScopedMixin):
    __tablename__ = "exemplar_bank_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyst_feedback.id"), nullable=False
    )
    error_mode: Mapped[str] = mapped_column(Text, nullable=False)
    finding_summary: Mapped[str] = mapped_column(Text, nullable=False)
    corrected_summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["ExemplarBankEntry"]
