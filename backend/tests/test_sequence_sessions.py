"""Unit tests for `app.detection.sequence.sessions` -- session construction against real Okta
`.jsonl` lines (round-tripped through the actual parser, not a hand-rolled stand-in for it, so a
test failure here would also mean the real ingest pipeline disagrees about `event_key`/`line_no`).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from app.detection.sequence.sessions import (
    SESSION_IDLE_GAP_S,
    SESSION_MAX_LEN,
    build_sessions,
    iter_okta_raw_events,
    session_stats,
    token_ids,
)
from app.detection.sequence.vocabulary import PAD_ID, build_vocabulary

_T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)


def _okta_line(ts: datetime, principal: str, event_type: str, result: str = "SUCCESS") -> str:
    payload = {
        "published": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "eventType": event_type,
        "outcome": {"result": result},
        "actor": {"alternateId": principal, "displayName": principal},
        "client": {"ipAddress": "10.0.0.1", "userAgent": {}, "geographicalContext": {}},
    }
    return json.dumps(payload)


def test_iter_okta_raw_events_round_trips_event_key() -> None:
    lines = [_okta_line(_T0, "alice@corp.example", "user.session.start", "SUCCESS")]
    events = list(iter_okta_raw_events(lines))
    assert len(events) == 1
    assert events[0].event_key == "user.session.start:SUCCESS"
    assert events[0].principal == "alice@corp.example"
    assert events[0].line_no == 1


def test_build_sessions_splits_on_idle_gap() -> None:
    # Two events 10 minutes apart (one session), then a third event 40 minutes after that
    # (over SESSION_IDLE_GAP_S == 1800s) -- must produce two sessions, not one.
    lines = [
        _okta_line(_T0, "alice@corp.example", "user.session.start"),
        _okta_line(_T0 + timedelta(minutes=10), "alice@corp.example", "user.authentication.sso"),
        _okta_line(_T0 + timedelta(minutes=50), "alice@corp.example", "user.session.start"),
    ]
    events = list(iter_okta_raw_events(lines))
    sessions = build_sessions(events)

    assert len(sessions) == 2
    assert [len(s) for s in sessions] == [2, 1]
    assert all(s.principal == "alice@corp.example" for s in sessions)
    # Exactly at the boundary: 1800.0s apart is still one session (docs/04 "within a 30-minute
    # idle gap" -- inclusive), only a gap *exceeding* it splits.
    boundary_lines = [
        _okta_line(_T0, "bob@corp.example", "user.session.start"),
        _okta_line(
            _T0 + timedelta(seconds=SESSION_IDLE_GAP_S), "bob@corp.example", "user.session.end"
        ),
    ]
    boundary_events = list(iter_okta_raw_events(boundary_lines))
    boundary_sessions = build_sessions(boundary_events)
    assert len(boundary_sessions) == 1
    assert len(boundary_sessions[0]) == 2


def test_build_sessions_separates_principals() -> None:
    lines = [
        _okta_line(_T0, "alice@corp.example", "user.session.start"),
        _okta_line(_T0 + timedelta(seconds=5), "bob@corp.example", "user.session.start"),
    ]
    events = list(iter_okta_raw_events(lines))
    sessions = build_sessions(events)
    assert {s.principal for s in sessions} == {"alice@corp.example", "bob@corp.example"}
    assert len(sessions) == 2


def test_build_sessions_truncates_long_run() -> None:
    lines = [
        _okta_line(_T0 + timedelta(seconds=30 * i), "carol@corp.example", "user.authentication.sso")
        for i in range(SESSION_MAX_LEN + 6)
    ]
    events = list(iter_okta_raw_events(lines))
    sessions = build_sessions(events)

    assert len(sessions) == 1
    session = sessions[0]
    assert len(session) == SESSION_MAX_LEN
    assert session.truncated is True
    # The kept events are the *earliest* ones in the run, not an arbitrary slice.
    assert session.events[0].line_no == 1
    assert session.events[-1].line_no == SESSION_MAX_LEN


def test_session_stats_reports_truncation() -> None:
    short_lines = [_okta_line(_T0, "dave@corp.example", "user.session.start")]
    long_lines = [
        _okta_line(_T0 + timedelta(seconds=30 * i), "erin@corp.example", "user.authentication.sso")
        for i in range(SESSION_MAX_LEN + 3)
    ]
    events = list(iter_okta_raw_events(short_lines + long_lines))
    sessions = build_sessions(events)
    stats = session_stats(sessions)

    assert stats.n_sessions == 2
    assert stats.n_principals == 2
    assert stats.n_truncated == 1
    assert stats.max_len_observed == SESSION_MAX_LEN


def test_token_ids_pads_and_encodes() -> None:
    lines = [
        _okta_line(_T0, "frank@corp.example", "user.session.start"),
        _okta_line(_T0 + timedelta(seconds=5), "frank@corp.example", "user.session.end"),
    ]
    events = list(iter_okta_raw_events(lines))
    sessions = build_sessions(events)
    vocab = build_vocabulary(key for s in sessions for key in s.token_keys)

    ids = token_ids(sessions[0], vocab, max_len=8)
    assert len(ids) == 8
    assert ids[0] == vocab.encode("user.session.start:SUCCESS")
    assert ids[1] == vocab.encode("user.session.end:SUCCESS")
    assert ids[2:] == [PAD_ID] * 6
