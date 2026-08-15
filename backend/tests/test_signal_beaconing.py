"""Unit tests for `app.detection.signal.beaconing.detect_beaconing` -- CLAUDE.md's "every
detector needs a synthetic fixture that must fire and one that must not," against pure
`EventRow` lists (no DB, no fitted artifact -- beaconing has neither).
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from app.detection.signal.beaconing import detect_beaconing
from app.detection.signal.constants import BEACONING_SCORE_THRESHOLD, SIGNAL_BEACONING
from app.detection.signal.events_dao import EventRow

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _rows(
    *, n: int, interval_s: float, src_ip: str, domain: str, jitter_s: float = 0.0, seed: int = 1
) -> list[EventRow]:
    rng = random.Random(seed)
    ts = _T0
    rows: list[EventRow] = []
    for i in range(n):
        rows.append(
            EventRow(id=i, ts=ts, src_ip=src_ip, domain=domain, principal="victim@corp.example")
        )
        step = interval_s + (rng.uniform(-jitter_s, jitter_s) if jitter_s else 0.0)
        ts = ts + timedelta(seconds=max(0.001, step))
    return rows


def test_regular_beacon_fires() -> None:
    # 60 check-ins, exactly 240s apart: n/50 factor saturates at 1.0, duration is ~3.93h
    # (duration_h/4 factor ~0.98), and cv == 0 (regularity == 1.0) -- comfortably above
    # BEACONING_SCORE_THRESHOLD without having been tuned to just barely clear it.
    rows = _rows(n=60, interval_s=240.0, src_ip="10.0.0.5", domain="abcdefgh.top")

    drafts = detect_beaconing(rows)

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.detector_key == SIGNAL_BEACONING
    assert draft.entity_type == "src_ip"
    assert draft.entity_value == "10.0.0.5"
    assert draft.raw_score > BEACONING_SCORE_THRESHOLD
    assert draft.explanation["cv"] == 0.0
    assert draft.explanation["n_events"] == 60
    assert draft.explanation["domain"] == "abcdefgh.top"
    # docs/04's exact explanation shape must be present.
    for key in ("mean_interval", "cv", "mad_jitter", "n_events", "duration_h", "dominant_lag"):
        assert key in draft.explanation


def test_irregular_browsing_does_not_fire() -> None:
    # Mostly-tiny gaps (a burst of clicks) punctuated by occasional huge ones (the user walked
    # away) -- a *uniform* jitter can't push CV much past ~0.58 (bounded by construction), but
    # this heavy-tailed mix pushes CV comfortably past 1.0, so regularity clips to exactly 0 and
    # the score collapses to 0 regardless of volume/duration -- not just "probably below
    # threshold," but deterministically so.
    rng = random.Random(7)
    ts = _T0
    rows: list[EventRow] = []
    for i in range(60):
        rows.append(
            EventRow(id=i, ts=ts, src_ip="10.0.0.9", domain="news.example", principal="u@corp")
        )
        step = rng.uniform(5000, 20000) if rng.random() < 0.1 else rng.uniform(0.5, 2.0)
        ts = ts + timedelta(seconds=step)

    drafts = detect_beaconing(rows)

    assert drafts == []


def test_group_below_minimum_event_count_does_not_fire() -> None:
    # Perfectly regular, but only 5 events -- below the n >= 8 floor docs/04 requires before a
    # group is even eligible for scoring.
    rows = _rows(n=5, interval_s=60.0, src_ip="10.0.0.7", domain="fast-beacon.top")

    assert detect_beaconing(rows) == []


def test_events_without_src_ip_or_domain_are_ignored() -> None:
    rows = [
        EventRow(id=1, ts=_T0, src_ip=None, domain="example.com", principal="u"),
        EventRow(id=2, ts=_T0, src_ip="10.0.0.1", domain=None, principal="u"),
    ]
    assert detect_beaconing(rows) == []


def test_different_src_ip_domain_pairs_are_scored_independently() -> None:
    regular = _rows(n=60, interval_s=240.0, src_ip="10.0.0.5", domain="beacon-one.top")
    other_regular = _rows(n=60, interval_s=90.0, src_ip="10.0.0.6", domain="beacon-two.top")

    drafts = detect_beaconing(regular + other_regular)

    entity_values = {d.entity_value for d in drafts}
    assert entity_values == {"10.0.0.5", "10.0.0.6"}


def test_jitter_degrades_the_score_monotonically() -> None:
    # A sanity check on the shape of the degradation curve the M7 verification report measures
    # against real generated data: more jitter (as a fraction of the interval) should never
    # produce a *higher* score than less jitter, for the same volume/duration.
    scores = []
    for jitter_pct in (0.0, 0.1, 0.3, 0.6):
        rows = _rows(
            n=80,
            interval_s=60.0,
            jitter_s=60.0 * jitter_pct,
            src_ip="10.0.0.20",
            domain="jitter-test.top",
            seed=42,
        )
        drafts = detect_beaconing(rows)
        scores.append(drafts[0].raw_score if drafts else 0.0)

    assert scores == sorted(scores, reverse=True)
