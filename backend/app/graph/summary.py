"""Deterministic incident summary — every incident gets one, computed at correlate time, zero LLM
cost. Modeled on `app.graph.titling`'s conventions: a small pure template function, string
manipulation only, restricted lookups documented as restricted (never a generator).

## Why every incident, not just the triaged top few

`triage_verdicts.summary` is the LLM's own two-or-three-sentence read of an incident (docs/10 "the
case file", section 2) — but `MAX_TRIAGE_INCIDENTS` triages only the top few incidents per
analysis by `fused_score` (docs/07 "Scope discipline"), so most incidents never get one. Nothing
about *what fired, on which entities, how many events, over what window, which layers
corroborated* requires an LLM — every one of those facts is already sitting on the incident's own
member signals (`app.graph.incidents.SignalRef`) by the time `app.pipeline.stages.correlate`
persists the row. This module turns those facts into the same three-sentence shape docs/10
specifies for the human-written one, so the case file's Summary section is never empty.

## Two summaries, never conflated

`Incident.summary` (this module's output) and `TriageVerdict.summary` (the LLM's) are separate
columns with separate provenance, exactly like `Incident.anomaly_confidence` vs
`TriageVerdict.threat_confidence` (docs/v2_migration change 3's "two confidences, never mixed" —
the same discipline applied to prose instead of a score). Neither is ever overwritten by the
other: `Incident.summary` is written once, at correlate time, by `app.pipeline.stages.correlate`,
and nothing in `app.agent` (which never runs in this environment — see CLAUDE.md's cost
constraint) writes to the `incidents` table at all. The API and the frontend render both, labelled,
never one silently standing in for the other — see `app.schemas.incident.IncidentDetail.summary`'s
docstring and `frontend/components/incidents/case/`'s Summary section.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final, cast

from app.graph.incidents import SignalRef
from app.graph.titling import technique_name

__all__ = ["summary_for_incident"]

# Same restricted-lookup philosophy as `app.graph.titling._TECHNIQUE_NAMES`: irregular plurals
# only for the six entity types `app.graph.builder` actually produces (docs/05 "Graph
# construction"); anything else (there is nothing else today) falls back to a bare `+ "s"`.
_IRREGULAR_PLURALS: Final[dict[str, str]] = {"country": "countries"}


def _pluralize(entity_type: str, count: int) -> str:
    if count == 1:
        return entity_type
    return _IRREGULAR_PLURALS.get(entity_type, f"{entity_type}s")


def _join_and(items: Sequence[str]) -> str:
    """`["a"] -> "a"`, `["a", "b"] -> "a and b"`, `["a", "b", "c"] -> "a, b, and c"` — plain
    English list joining, deterministic (caller sorts `items` first)."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _entity_phrase(entity_type_counts: Mapping[str, int]) -> str:
    if not entity_type_counts:
        return "an unspecified set of entities"
    parts = [
        f"{count} {_pluralize(etype, count)}"
        for etype, count in sorted(entity_type_counts.items())
        if count > 0
    ]
    return _join_and(parts) if parts else "an unspecified set of entities"


# Minute precision -- enough to distinguish two windows in a fast-moving beaconing campaign
# without a second/microsecond suffix that adds noise no analyst reads. `replace(tzinfo=None)`
# before formatting: every timestamp in this system is UTC (docs/09 "Timestamps: RFC 3339 UTC"),
# and the caller already appends the literal " UTC" itself -- without stripping it,
# `datetime.isoformat()` on a tz-aware value appends its own `+00:00` too, producing a doubled,
# unreadable `...T12:00+00:00 UTC`.
def _fmt_ts(ts: datetime) -> str:
    return ts.replace(tzinfo=None).isoformat(timespec="minutes")


def _window_clause(signals: Sequence[SignalRef]) -> str:
    # `SignalRef.window_start`/`window_end` are typed `object` (that dataclass's own choice, not
    # this module's -- see `app.graph.incidents`), but every real signal populates them with a
    # `datetime` or `None` (`app.models.signal.Signal.window_start`/`window_end`'s own type) --
    # the `cast` below documents that fact for mypy rather than widening this function's own
    # types to `object` and losing the return-type checking `_fmt_ts` relies on.
    starts = [cast(datetime, s.window_start) for s in signals if s.window_start is not None]
    ends = [cast(datetime, s.window_end) for s in signals if s.window_end is not None]
    if not starts or not ends:
        return ""
    window_start, window_end = min(starts), max(ends)
    if window_start == window_end:
        return f" at {_fmt_ts(window_start)} UTC"
    return f" between {_fmt_ts(window_start)} and {_fmt_ts(window_end)} UTC"


def summary_for_incident(
    *,
    signals: Sequence[SignalRef],
    entity_type_counts: Mapping[str, int],
    top_technique_id: str | None,
    severity: str,
) -> str:
    """Three sentences (docs/10's Summary section: "two or three sentences"): what fired and
    where, how much evidence supports it, and the fusion-computed severity. `entity_type_counts`
    is `{entity_type: count}` over the incident's own community (`IncidentCandidate.entity_keys`,
    docs/05 step 3's induced subgraph) — the same population the entity graph view renders, not
    just the seeds, so "on 1 user and 2 domains" matches what the analyst sees on the graph tab.

    Every incident produced by `app.graph.incidents.form_incidents` carries at least one signal
    (a community only becomes a candidate when it contains >= 1 seed, and a seed is by
    definition an entity carrying >= 1 signal) -- the `not signals` branch below is a defensive
    fallback for a call site this module cannot itself guarantee, never the expected path.
    """
    if not signals:
        return "No signals were recorded for this incident."

    n_signals = len(signals)
    layers = sorted({s.detector_layer for s in signals})
    layer_word = "layer" if len(layers) == 1 else "layers"
    entity_phrase = _entity_phrase(entity_type_counts)
    window_clause = _window_clause(signals)

    sentence_1 = (
        f"{n_signals} signal{'s' if n_signals != 1 else ''} from the {_join_and(layers)} "
        f"{layer_word} fired on {entity_phrase}{window_clause}."
    )

    event_ids: set[int] = set()
    for s in signals:
        event_ids.update(s.evidence_event_ids)
    n_events = len(event_ids)
    verb = "supports" if n_events == 1 else "support"
    if top_technique_id is not None:
        technique_clause = (
            f"; top technique {technique_name(top_technique_id)} ({top_technique_id})"
        )
    else:
        technique_clause = "; no MITRE technique was identified among these signals"
    sentence_2 = (
        f"{n_events} event{'s' if n_events != 1 else ''} {verb} this finding{technique_clause}."
    )

    sentence_3 = f"Fused severity: {severity}."

    return f"{sentence_1} {sentence_2} {sentence_3}"
