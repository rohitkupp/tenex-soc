"""`SignalDraft` -- the DB-independent output shape every L2 detector produces.

Each detector (`beaconing.py`, `dga.py`, `burst.py`, `rarity.py`) is a pure function of a list
of already-fetched, lightweight event rows (`events_dao.EventRow`) to a `list[SignalDraft]`.
Keeping the scoring math free of any `Session`/`Engine` argument is what makes
`tests/test_signal_*.py` fast, deterministic unit tests against synthetic fixtures rather than
integration tests against the live Postgres -- CLAUDE.md's "Every detector needs a unit test
with a synthetic fixture that must fire and one that must not" is only cheap to satisfy if the
detector itself doesn't need a database to run. `events_dao.py` is the only module that turns a
`SignalDraft` into a persisted `app.models.signal.Signal` row.

## `confidence`, before M10 exists

docs/04's "Fusion & calibration" section calibrates `signals.confidence` via isotonic
regression fit on held-out labeled eval data, persisted per detector -- that is milestone M10.
`signals.confidence` is `NOT NULL` today, so every detector needs *something* to write in the
meantime. The interim policy, applied uniformly by `to_signal_kwargs` below rather than
reinvented per detector: `confidence = clamp01(confidence_raw)`, where `confidence_raw` is
supplied by the detector as its own best guess at a probability-like quantity (already `[0,1]`
for beaconing/DGA/rarity's own formulas; burst's raw z-score is squashed by `burst.py` before
it ever reaches here). This is explicitly *not* a calibrated probability and every caller
downstream of `signals.confidence` should keep treating it as one until M10 replaces it.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.detection.evidence.constants import EVIDENCE_CAP

if TYPE_CHECKING:
    from app.detection.evidence.events_dao import EventRow

__all__ = ["SignalDraft", "cap_evidence", "cap_evidence_rows", "clamp01"]


def clamp01(x: float) -> float:
    if math.isnan(x):
        return 0.0
    return max(0.0, min(1.0, x))


def cap_evidence(
    event_ids_by_ts: list[tuple[datetime, int]], *, cap: int = EVIDENCE_CAP
) -> tuple[list[int], bool]:
    """Evidence longer than `cap` is truncated to the earliest and latest events, split evenly,
    rather than dropped from one end -- a detector's evidence should still bound the window it
    fired over even when it can't list every event in it. Returns `(ids, truncated)`.
    """
    ordered = sorted(event_ids_by_ts, key=lambda pair: pair[0])
    if len(ordered) <= cap:
        return [eid for _, eid in ordered], False
    head = cap // 2
    tail = cap - head
    kept = ordered[:head] + (ordered[-tail:] if tail else [])
    return [eid for _, eid in kept], True


def cap_evidence_rows(
    rows: Sequence[EventRow], *, cap: int = EVIDENCE_CAP
) -> tuple[list[int], list[int], bool]:
    """`(evidence_event_ids, contributing_line_numbers, truncated)` for the *same* underlying
    rows, capped identically -- an `EvidencePayload`'s `contributing_line_numbers` (the file's
    own line numbers, docs/v2_migration change 2's `[1291, 1294, 1301]` example) must point at
    exactly the same subset of rows a `SignalDraft`'s `evidence_event_ids` (DB `events.id`
    values, `cap_evidence` above) does -- a human clicking an `[EVIDENCE-14]` citation and a human
    reading the `signals` row for the same finding should never see two different truncated
    windows. Reuses `cap_evidence`'s own truncation policy (earliest+latest split) via the same
    `(ts, id)` ordering, then reads `raw_line_no` off the identical kept rows rather than
    re-deriving a second cap independently.
    """
    ordered = sorted(rows, key=lambda r: r.ts)
    event_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered], cap=cap)
    kept_ids = set(event_ids)
    line_numbers = [r.raw_line_no for r in ordered if r.id in kept_ids]
    return event_ids, line_numbers, truncated


@dataclass(slots=True)
class SignalDraft:
    """Everything a detector knows about one finding, before `analysis_id`/`tenant_id` (known
    only to the caller that fetched the rows in the first place) are attached at persist time.
    """

    detector_key: str
    entity_type: str
    entity_value: str
    raw_score: float
    confidence_raw: float
    window_start: datetime | None
    window_end: datetime | None
    evidence_event_ids: list[int]
    explanation: dict[str, Any] = field(default_factory=dict)
    mitre_technique: str | None = None

    def to_signal_kwargs(self) -> dict[str, Any]:
        """`app.models.signal.Signal` constructor kwargs minus `analysis_id`/`tenant_id`/
        `detector_layer` (constant, supplied by the persistence layer) and `id`/`created_at`
        (DB-generated)."""
        from app.detection.evidence.constants import DETECTOR_LAYER

        return {
            "detector_key": self.detector_key,
            "detector_layer": DETECTOR_LAYER,
            "raw_score": self.raw_score,
            "confidence": clamp01(self.confidence_raw),
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "mitre_technique": self.mitre_technique,
            "evidence_event_ids": self.evidence_event_ids,
            "explanation": self.explanation,
        }
