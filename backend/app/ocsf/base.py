"""Common fields every OCSF event class carries, plus the hot-column projection contract.

docs/02's `events` table is explicit that the hot columns are "a projection of" the `ocsf` JSONB
blob, not a second source of truth. `hot_columns()` is that projection, written once here per
class so the bulk-COPY writer (a separate agent, docs/02) never has to re-derive OCSF paths
itself and risk disagreeing with the parser about where a value lives. See each subclass for the
exact mapping back to docs/03's tables.

`source_type` and `line_no` are not part of real OCSF — they are this pipeline's own bookkeeping,
carried on the event so a consumer of `registry.iter_events` never has to zip a separate line
counter back onto the objects it receives.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.ocsf.common import Actor, NetworkEndpoint


class OCSFEventBase(BaseModel):
    """Shared shape. Never instantiated directly — always one of the three concrete classes."""

    model_config = ConfigDict(extra="forbid")

    class_uid: int
    category_uid: int
    activity_name: str | None = None
    time: datetime

    # Pipeline bookkeeping, not OCSF taxonomy — see module docstring.
    source_type: str
    line_no: int
    event_key: str

    actor: Actor = Field(default_factory=Actor)
    src_endpoint: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    dst_endpoint: NetworkEndpoint | None = None

    # docs/03's escape hatch: "Include the `unmapped` escape hatch the doc references." Any
    # source field that has no first-class OCSF home lands here, keyed by a short, stable name
    # (see each parser for exactly which vendor fields end up here).
    unmapped: dict[str, Any] = Field(default_factory=dict)

    def hot_columns(self) -> dict[str, Any]:  # pragma: no cover - overridden by every subclass
        """The docs/02 `events` hot-column projection of this event. Overridden per class."""
        raise NotImplementedError
