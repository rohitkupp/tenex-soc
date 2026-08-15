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
    entity_type: str
    entity_value: str


def _tactic_for(technique: str | None) -> tuple[str, bool]:
    if technique is None:
        return _UNKNOWN_TACTIC, True
    tactic = _TACTIC_BY_TECHNIQUE.get(technique)
    return (tactic, False) if tactic is not None else (_UNKNOWN_TACTIC, True)


def build_timeline(signals: list[Any]) -> list[TimelinePhase]:
    """One `TimelinePhase` per signal (`app.graph.incidents.SignalRef`-shaped: needs
    `window_start`, `evidence_event_ids`, `detector_key`, `entity_type`, `entity_value`,
    `mitre_technique`), ordered by `window_start` (or the earliest evidence event id as a stable
    tiebreak/fallback when no window was reported — event ids are assigned in ingestion order in
    this system, `docs/02`, so lower id is earlier in every practical case)."""

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
                entity_type=s.entity_type,
                entity_value=s.entity_value,
            )
        )
    return phases
