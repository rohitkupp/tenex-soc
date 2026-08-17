"""Deterministic incident timeline (docs/05 "Timeline").

> Per incident, the timeline is built **deterministically** from member events, ordered by `ts`.
> The agent only annotates each phase with an ATT&CK tactic. Never let the model order events —
> ordering is a fact, and getting it from the database is both accurate and free.
>
> Output shape: `[{ "ts": "...", "tactic": "Initial Access", "event_ids": [123, 124],
> "summary": "..." }]`

One phase per contributing signal (a signal's `window_start`/evidence already *is* one coherent
episode of activity — a beaconing group, a burst bucket, a rule match), ordered by `window_start`
(falling back to the earliest evidence event when a detector didn't report a window, e.g. an L1
rule match on a single event). This module never orders raw events itself beyond that one sort —
consistent with docs/05's instruction that ordering must come from the data, not be inferred.

`TimelinePhase` also carries `detector_layer`/`confidence`/`mitre_technique` straight through
from the source signal (not just the mapped `tactic` name) — `app.api.incident_detail`'s
analysis-level timeline (`GET /api/analyses/{id}/timeline`) surfaces all three per docs/09 so an
analyst sees the same confidence score the queue and the event detail view show, without a
second round trip to `signals`. The per-incident timeline route deliberately keeps its own
response shape unchanged (`app.schemas.incident.TimelinePhaseOut` doesn't include them), so this
is purely additive at the dataclass level.

## Tactic annotation, before the agent exists

docs/05 assigns tactic annotation to the agent (M11, not built yet). `_TACTIC_BY_TECHNIQUE` below
is a small, deterministic placeholder so this module's output has a populated `tactic` field
today rather than leaving every phase `None` until M11 lands — restricted to the same technique
IDs `app.graph.titling` already covers (never a fabricated mapping), and every phase's `tactic`
is easy to tell apart from an agent-authored one (see `TimelinePhase.tactic_is_placeholder`) so
M11 knows exactly which phases it still needs to (re)annotate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

__all__ = ["TimelinePhase", "build_timeline"]

# Public, standard ATT&CK tactic names for the technique IDs `app.graph.titling` already maps —
# see that module's docstring for why this is a restricted lookup, not a generator.
_TACTIC_BY_TECHNIQUE: Final[dict[str, str]] = {
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1552.001": "Credential Access",
    "T1090": "Command and Control",
    "T1090.003": "Command and Control",
    "T1105": "Command and Control",
    "T1567": "Exfiltration",
    "T1567.002": "Exfiltration",
    "T1048": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1030": "Exfiltration",
    "T1020": "Exfiltration",
}
_UNKNOWN_TACTIC: Final[str] = "Unattributed"


@dataclass(frozen=True, slots=True)
class TimelinePhase:
    ts: datetime | None
    tactic: str
    tactic_is_placeholder: bool
    event_ids: list[int]
    summary: str
    detector_key: str
    detector_layer: str
    entity_type: str
    entity_value: str
    confidence: float
    # False when this detector had no fitted isotonic calibrator and `confidence` is therefore
    # `clamp01(raw_score)` — a raw detector score, not a probability
    # (`app.detection.calibration.CalibratorStore.calibrate`'s documented fallback). Carried so
    # the UI can say which of the two a number is instead of rendering both as "confidence
    # N%": a raw score clamped at 1.0 displayed as "100% confident" is the most misleading
    # thing this pipeline can show an analyst, and it is exactly what an unfitted detector
    # produces.
    calibrated: bool
    mitre_technique: str | None


def _tactic_for(technique: str | None) -> tuple[str, bool]:
    if technique is None:
        return _UNKNOWN_TACTIC, True
    tactic = _TACTIC_BY_TECHNIQUE.get(technique)
    return (tactic, False) if tactic is not None else (_UNKNOWN_TACTIC, True)


def build_timeline(signals: list[Any]) -> list[TimelinePhase]:
    """One `TimelinePhase` per signal (`app.graph.incidents.SignalRef`-shaped: needs
    `window_start`, `evidence_event_ids`, `detector_key`, `detector_layer`, `entity_type`,
    `entity_value`, `confidence`, `mitre_technique` — every field `app.models.signal.Signal`
    itself already carries, so ORM rows work here unmodified, same as `SignalRef`), ordered by
    `window_start` (or the earliest evidence event id as a stable tiebreak/fallback when no
    window was reported — event ids are assigned in ingestion order in this system, `docs/02`,
    so lower id is earlier in every practical case)."""

    def sort_key(s: Any) -> tuple[int, datetime | int]:
        if s.window_start is not None:
            return (0, s.window_start)
        lowest = min(s.evidence_event_ids) if s.evidence_event_ids else 0
        return (1, lowest)

    phases: list[TimelinePhase] = []
    for s in sorted(signals, key=sort_key):
        tactic, is_placeholder = _tactic_for(s.mitre_technique)
        phases.append(
            TimelinePhase(
                ts=s.window_start,
                tactic=tactic,
                tactic_is_placeholder=is_placeholder,
                event_ids=list(s.evidence_event_ids),
                summary=f"{s.detector_key} on {s.entity_type} {s.entity_value}",
                detector_key=s.detector_key,
                detector_layer=s.detector_layer,
                entity_type=s.entity_type,
                entity_value=s.entity_value,
                confidence=s.confidence,
                # `SignalRef` (graph-internal) predates the column and doesn't carry it; a
                # missing attribute means "we can't claim it was calibrated", which is the
                # safe direction to guess in.
                calibrated=bool(getattr(s, "calibrated", False)),
                mitre_technique=s.mitre_technique,
            )
        )
    return phases
