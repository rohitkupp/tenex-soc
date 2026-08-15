"""`app.parsers.registry` against docs/03's registry contract:

"Registry in `parsers/registry.py` runs every `sniff()` and picks the highest score above 0.6."

ZScaler is the only registered source (Okta and CloudTrail were removed, narrowing this project
to ZScaler web proxy logs only), so the "mixed export, multiple sources in one sample" cases the
registry was originally built to handle (docs/03) have no second parser to exercise them against
today — those regression tests were deleted along with the sources, not left behind skipped. What
remains here is everything the registry contract still promises with one registered parser: it
still runs every `sniff()` (one call), still reports the whole set above threshold rather than
assuming exactly one match, and a non-log file still sniffs to nothing.

Also covers the seam this module owns with the event-store writer: `iter_events`, `ParseStats`,
and the replacement for M1's placeholder sniffer (`app/storage/source_sniffer.py`).
"""

from __future__ import annotations

from pathlib import Path

from app.ocsf import HTTPActivity
from app.parsers.base import ParseFailure
from app.parsers.registry import (
    DEFAULT_REGISTRY,
    SNIFF_THRESHOLD,
    ParserRegistry,
    ParseStats,
    detect_source_types,
    iter_events,
    make_parser,
)
from app.parsers.zscaler import _CANONICAL_FIELDS
from app.storage.source_sniffer import detect_source_types as legacy_detect_source_types
from datagen import corpus
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)


def _write_zscaler_corpus(tmp_path: Path, *, n: int = 30) -> Path:
    org = corpus.build_org(29, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(29, corpus.ROLE_BENIGN))
    corpus.write_benign_corpus(org, root, TimeWindow.of_days(3), tmp_path, proxy_events=n)
    return tmp_path / "benign_zscaler.log"


# ---------------------------------------------------------------------------- pure-file detection


def test_detects_the_zscaler_format(tmp_path: Path) -> None:
    path = _write_zscaler_corpus(tmp_path)
    detected = detect_source_types(path.read_text())
    assert detected == ["zscaler"], f"misdetected as {detected}"


def test_non_log_file_returns_nothing() -> None:
    """The exact regression case named in the M3 brief: a non-log text file (a domain list, not
    a known format) must sniff to nothing -- and does; this is *correct* behavior, not the
    sniffer bug that motivated replacing the M1 placeholder."""
    top_domains = Path(__file__).parent.parent / "datagen" / "data" / "top_domains.txt"
    text = top_domains.read_text(encoding="utf-8")
    assert detect_source_types(text) == []


def test_storage_shim_delegates_to_the_real_registry() -> None:
    """`app/storage/source_sniffer.py` is a thin re-export now, not a second implementation."""
    assert legacy_detect_source_types is detect_source_types


# ---------------------------------------------------------------------------- best_match / get


def test_best_match_picks_the_single_registered_source(tmp_path: Path) -> None:
    path = _write_zscaler_corpus(tmp_path)
    parser = DEFAULT_REGISTRY.best_match(path.read_text())
    assert parser is not None
    assert parser.source_type == "zscaler"


def test_best_match_returns_none_below_threshold() -> None:
    assert DEFAULT_REGISTRY.best_match("nothing recognizable here\njust prose") is None


def test_registry_get_raises_for_unknown_source() -> None:
    registry = ParserRegistry()
    try:
        registry.get("splunk")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for an unregistered source_type")


def test_make_parser_raises_for_unknown_source() -> None:
    try:
        make_parser("splunk")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for an unregistered source_type")


# ---------------------------------------------------------------------------- iter_events


def test_iter_events_dispatches_to_http_activity(tmp_path: Path) -> None:
    path = _write_zscaler_corpus(tmp_path, n=20)
    with path.open(encoding="utf-8") as fh:
        results = list(iter_events("zscaler", fh))
    assert results, "no events parsed"
    assert all(isinstance(r, HTTPActivity) for r in results)


def test_iter_events_skips_blank_lines() -> None:
    header = "\t".join(_CANONICAL_FIELDS)
    valid_row = "2026-01-01T00:00:00Z\t" + "\t".join(["x"] * (len(_CANONICAL_FIELDS) - 1))
    lines = iter(
        [
            header + "\n",  # header_lines=1 -- consumed to bind columns, never yielded
            "onlyonefield\n",  # too few fields -- a parse failure, not a blank line
            "\n",  # genuinely blank -- skipped, no result at all
            valid_row + "\n",
        ]
    )
    results = list(iter_events("zscaler", lines))
    # The header is consumed and the blank line produced no result at all; the malformed row and
    # the valid row each produced exactly one.
    assert len(results) == 2


# ---------------------------------------------------------------------------- ParseStats


def test_parse_stats_tracks_total_and_failure_rate() -> None:
    stats = ParseStats()
    parser = make_parser("zscaler")
    stats.record(parser.parse_line("bad", 1))
    stats.record(parser.parse_line("also,bad", 2))
    good = "2026-01-01T00:00:00Z\t" + "\t".join(["x"] * 24)
    stats.record(parser.parse_line(good, 3))

    assert stats.total == 3
    assert stats.failed == 2
    assert stats.failure_rate == 2 / 3
    assert all(isinstance(f, ParseFailure) for f in stats.failures)


def test_parse_stats_failure_rate_is_zero_for_empty_stats() -> None:
    assert ParseStats().failure_rate == 0.0


def test_sniff_threshold_is_docs03s_point_six() -> None:
    assert SNIFF_THRESHOLD == 0.6
