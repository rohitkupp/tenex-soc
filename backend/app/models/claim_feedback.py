"""`claim_feedback` — change 22, "Per-claim thumbs on narrative claims, hover-revealed."

One row per (incident, narrative step) an analyst rated. Feeds mechanism 14, "verifier rule
induction" (change 21): a thumbs-down on a specific claim is exactly "an analyst catching a
factual error the verifier missed" -- narrower and more direct evidence than a whole-incident
Dismiss, since it points at the exact claim, not just the verdict as a whole.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class ClaimFeedback(Base, TenantScopedMixin):
    __tablename__ = "claim_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    verdict_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("triage_verdicts.id"), nullable=False
    )
    step: Mapped[int] = mapped_column(Integer, nullable=False)
    helpful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["ClaimFeedback"]
