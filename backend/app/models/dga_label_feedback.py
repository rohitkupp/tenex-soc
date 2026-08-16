"""`dga_label_feedback` — change 21 mechanism 8, "DGA classifier retraining."

Raw corrected domain labels accumulated over time: an analyst's Override/Dismiss said a domain
the DGA logistic regression (`app.detection.evidence.dga`, docs/04 §L2) scored is (or is not)
algorithmically generated. `app.learning.dga_retrain.build_training_rows` reads this table's
full history to assemble a retrain candidate; the retrain itself is gated (change 21: "6, 7, 8 ...
Requires human approval") because it changes what the system *detects*, not merely how confident
it is.

One row per correction, not an upsert on `domain` — the same domain can be relabeled more than
once across incidents (an analyst correcting a prior, wrong correction), and the retrain reads the
*most recent* label per domain, so the history itself is worth keeping intact rather than
collapsed at write time.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class DgaLabelFeedback(Base, TenantScopedMixin):
    __tablename__ = "dga_label_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    is_dga: Mapped[bool] = mapped_column(Boolean, nullable=False)
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyst_feedback.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["DgaLabelFeedback"]
