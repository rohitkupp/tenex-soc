"""`evidence_profile_state` — change 21 mechanism 15, "evidence profile widening" (gated).

"Track how often analysts expand past the bundle to raw logs, per extractor. High rate means that
profile's context window is too narrow." Counting is continuous and unconditional (every raw-log
expansion recorded via `app.learning.evidence_profiles.record_raw_log_expansion` bumps
`expand_count`/`total_count` for that extractor, no approval needed — a counter is not a belief
change); only the *widening itself* — actually enlarging the evidence profile's context window —
is gated, per change 21's own line ("changes what the system detects or believes ... Requires
human approval"), proposed through `app.models.learning_proposal` once the rate crosses
`app.learning.evidence_profiles.WIDEN_RATE_THRESHOLD`.

One row per `(tenant_id, extractor)` — `extractor` is one of the six change-2 evidence extractor
keys (`beaconing | dga | burst | rarity | stl | url_entropy`).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Integer, PrimaryKeyConstraint, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime

from app.core.db import Base
from app.models.base import TenantScopedMixin


class EvidenceProfileState(Base, TenantScopedMixin):
    __tablename__ = "evidence_profile_state"

    extractor: Mapped[str] = mapped_column(Text)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    expand_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    widened: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (PrimaryKeyConstraint("tenant_id", "extractor"),)


__all__ = ["EvidenceProfileState"]
