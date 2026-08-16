"""`evidence_relevance_feedback` — change 22's "Evidence relevance toggle in the evidence
section" and change 16's "Per-evidence relevance toggle — was this useful?" -- the other agent
renders the evidence section itself (`frontend/app/(dashboard)/analyses/[id]/incidents/[iid]`
overview sections are their ownership); this table, `app.learning.evidence_profiles.
record_evidence_relevance`, and the endpoint that calls it are the seam this milestone provides
for that toggle to write through.

**A documented reading of an ambiguity in the migration doc**: change 16's own text says this
toggle feeds "learning mechanism 13," but mechanism 13 (change 21's own table) is "retrieval
prior tuning" over MITRE *techniques*, not evidence extractors -- thematically mismatched, likely
a cross-reference slip inside the source doc (`docs/v2_migration/MIGRATION-01-evidence-first.md`
change 16 vs. change 21). This module instead routes the toggle to mechanism 15, "evidence
profile widening," which change 21 defines in exactly these terms ("track how often analysts
[find a bundle insufficient], per extractor. High rate means that profile's context window is
too narrow") -- the thematically correct target. Flagged here rather than silently building the
literal (mismatched) cross-reference.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class EvidenceRelevanceFeedback(Base, TenantScopedMixin):
    __tablename__ = "evidence_relevance_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(Text, nullable=False)
    extractor: Mapped[str] = mapped_column(Text, nullable=False)
    relevant: Mapped[bool] = mapped_column(Boolean, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["EvidenceRelevanceFeedback"]
