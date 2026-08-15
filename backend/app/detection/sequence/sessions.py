"""Session construction (docs/04 §L4 "Sequence construction") — identity sources only.

"Per principal, session = events within a 30-minute idle gap. Truncate/pad to 64 tokens."

Reads real Okta log files (the benign corpus and the eval scenario files, both `.jsonl`) through
the same parser M3 built for the ingest pipeline (`app.parsers.registry.iter_events` +
`app.parsers.okta.make_parser` via `make_parser("okta")`) rather than re-deriving `event_key`
here. Two things that buys, both load-bearing for this milestone:

1. `event_key` is produced exactly once, by the parser that owns it -- this module and the real
   ingest pipeline can never disagree about what `user.mfa.factor.deactivate:SUCCESS` is called.
2. `iter_events`'s 1-based `line_no` is, by that module's own contract, "the file line numbers
   datagen's `GroundTruth.malicious_line_numbers` uses" -- so a session built here carries the
   exact line numbers needed to check it against a scenario's ground truth without any
   re-numbering step that could silently drift from what `.labels.json` actually says.

## Truncation, not chunking

A principal's contiguous run of events (no gap in it exceeds `SESSION_IDLE_GAP_S`) longer than
`SESSION_MAX_LEN` is truncated to its first `SESSION_MAX_LEN` events, not split into several
64-token sessions. This is a deliberate reading of docs/04's "truncate/pad to 64 tokens" (singular
session, not "chunk into 64-token pieces") and it does cost information for the small tail of
principals whose single busy stretch exceeds 64 events (mostly service accounts) -- `truncated`
records exactly when this happened so a caller can report how often, rather than the loss being
silent. It does not affect scenarios 5 or 6: both chains are on the order of 10-20 events, far
under the cap (see each scenario module's own docstring on why they are deliberately short).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from app.detection.sequence.vocabulary import PAD_ID, Vocabulary
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events, make_parser

__all__ = [
    "SESSION_IDLE_GAP_S",
    "SESSION_MAX_LEN",
    "RawEvent",
    "Session",
    "SessionEvent",
    "SessionStats",
    "build_sessions",
    "iter_okta_raw_events",
    "read_okta_file",
    "session_stats",
    "token_ids",
]

SESSION_IDLE_GAP_S: Final[float] = 1800.0  # 30 minutes, docs/04 §L4
SESSION_MAX_LEN: Final[int] = 64  # docs/04 §L4 "Truncate/pad to 64 tokens"


# ---------------------------------------------------------------------------- raw event reading


@dataclass(slots=True, frozen=True)
class RawEvent:
    """One parsed Okta event, reduced to exactly what session construction needs."""

    ts: datetime
    principal: str
    event_key: str
    line_no: int


def iter_okta_raw_events(lines: Iterable[str]) -> Iterator[RawEvent]:
    """Parse an open Okta `.jsonl` file (or any line iterable in that format) into `RawEvent`s,
    in file order. `ParseFailure`s are skipped -- consistent with every other consumer of
    `iter_events`, a malformed line is not this layer's concern -- as are the rare events with no
    resolvable principal (`actor.user.email_addr` unset), since a session has no meaning without
    one.
    """
    parser = make_parser("okta")
    for result in iter_events("okta", lines, parser=parser):
        if isinstance(result, ParseFailure):
            continue
        principal = result.actor.user.email_addr
        if not principal:
            continue
        yield RawEvent(
            ts=result.time, principal=principal, event_key=result.event_key, line_no=result.line_no
        )


def read_okta_file(path: Path) -> list[RawEvent]:
    """Materialize every `RawEvent` in `path`. Fine for the ~40-50k-event files this milestone
    trains and evaluates on; a corpus the size of `docs/11`'s full ~2M-event benign corpus would
    want the streaming form (`iter_okta_raw_events` directly against an open handle) instead."""
    with path.open("r", encoding="utf-8") as fh:
        return list(iter_okta_raw_events(fh))


# ---------------------------------------------------------------------------- session construction


@dataclass(slots=True, frozen=True)
class SessionEvent:
    ts: datetime
    event_key: str
    line_no: int


@dataclass(slots=True, frozen=True)
class Session:
    """One principal's contiguous run of events, already capped at `SESSION_MAX_LEN`."""

    principal: str
    events: tuple[SessionEvent, ...]
    truncated: bool

    @property
    def token_keys(self) -> tuple[str, ...]:
        return tuple(e.event_key for e in self.events)

    @property
    def line_numbers(self) -> tuple[int, ...]:
        return tuple(e.line_no for e in self.events)

    @property
    def start(self) -> datetime:
        return self.events[0].ts

    @property
    def end(self) -> datetime:
        return self.events[-1].ts

    def __len__(self) -> int:
        return len(self.events)


def build_sessions(
    events: Iterable[RawEvent],
    *,
    idle_gap_s: float = SESSION_IDLE_GAP_S,
    max_len: int = SESSION_MAX_LEN,
) -> list[Session]:
    """Group `events` by principal, sort each principal's stream by time, and split on any gap
    exceeding `idle_gap_s`. `events` need not already be sorted or grouped -- this function does
    both. Ties on `ts` break on `line_no` (the file's own order), which matters for `inject_sequence`
    chains where two steps can share a timestamp after rounding.
    """
    by_principal: dict[str, list[RawEvent]] = {}
    for event in events:
        by_principal.setdefault(event.principal, []).append(event)

    sessions: list[Session] = []
    for principal, principal_events in by_principal.items():
        ordered = sorted(principal_events, key=lambda e: (e.ts, e.line_no))
        run: list[RawEvent] = []
        for event in ordered:
            if run and (event.ts - run[-1].ts).total_seconds() > idle_gap_s:
                sessions.append(_finish_run(principal, run, max_len))
                run = []
            run.append(event)
        if run:
            sessions.append(_finish_run(principal, run, max_len))
    return sessions


def _finish_run(principal: str, run: list[RawEvent], max_len: int) -> Session:
    truncated = len(run) > max_len
    kept = run[:max_len]
    session_events = tuple(
        SessionEvent(ts=e.ts, event_key=e.event_key, line_no=e.line_no) for e in kept
    )
    return Session(principal=principal, events=session_events, truncated=truncated)


def token_ids(session: Session, vocab: Vocabulary, *, max_len: int = SESSION_MAX_LEN) -> list[int]:
    """`session`'s tokens as vocabulary ids, right-padded with `<PAD>` to exactly `max_len`.

    Sessions are already truncated to `max_len` by `build_sessions`, so the slice below is
    defensive (a caller passing a smaller `max_len` than the one `build_sessions` used, or a
    hand-built `Session` in a test) rather than load-bearing in the normal path.
    """
    ids = [vocab.encode(key) for key in session.token_keys[:max_len]]
    if len(ids) < max_len:
        ids = ids + [PAD_ID] * (max_len - len(ids))
    return ids


@dataclass(slots=True, frozen=True)
class SessionStats:
    n_sessions: int
    n_principals: int
    n_truncated: int
    n_events: int
    mean_len: float
    max_len_observed: int


def session_stats(sessions: Iterable[Session]) -> SessionStats:
    """Summary numbers for a report -- how many sessions, how many principals, how often
    truncation actually bit. Consumes `sessions` once; pass a list if you need it again."""
    materialized = list(sessions)
    n = len(materialized)
    principals = {s.principal for s in materialized}
    n_truncated = sum(1 for s in materialized if s.truncated)
    lengths = [len(s) for s in materialized]
    n_events = sum(lengths)
    mean_len = n_events / n if n else 0.0
    max_len_observed = max(lengths) if lengths else 0
    return SessionStats(
        n_sessions=n,
        n_principals=len(principals),
        n_truncated=n_truncated,
        n_events=n_events,
        mean_len=mean_len,
        max_len_observed=max_len_observed,
    )
