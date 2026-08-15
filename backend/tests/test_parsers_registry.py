"""`app.parsers.registry` against docs/03's registry contract:

"Registry in `parsers/registry.py` runs every `sniff()` and picks the highest score above 0.6.
A single upload may contain multiple source types (mixed export) -- detect per-line-block and
fan out to multiple parser queues on that basis."

Also covers the seam this module owns with the event-store writer: `iter_events`, `ParseStats`,
and the replacement for M1's placeholder sniffer (`app/storage/source_sniffer.py`).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.ocsf import APIActivity, Authentication, HTTPActivity
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
from app.storage.source_sniffer import detect_source_types as legacy_detect_source_types
from datagen import corpus
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)


def _write_one_of_each(tmp_path: Path, *, n: int = 30) -> dict[str, Path]:
    org = corpus.build_org(29, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(29, corpus.ROLE_BENIGN))
    corpus.write_benign_corpus(
        org,
        root,
        TimeWindow.of_days(3),
        tmp_path,
        proxy_events=n,
        okta_events=n,
        cloudtrail_events=n,
    )
    return {
        "zscaler": tmp_path / "benign_zscaler.log",
        "okta": tmp_path / "benign_okta.jsonl",
        "cloudtrail": tmp_path / "benign_cloudtrail.jsonl",
    }


# ---------------------------------------------------------------------------- pure-file detection


def test_detects_each_pure_format(tmp_path: Path) -> None:
    files = _write_one_of_each(tmp_path)
    for source, path in files.items():
        detected = detect_source_types(path.read_text())
        assert detected == [source], f"{source} misdetected as {detected}"


def test_non_log_file_returns_nothing() -> None:
    """The exact regression case named in the M3 brief: a non-log text file (a domain list, not
    one of the three known formats) must sniff to nothing -- and does; this is *correct*
    behavior, not the sniffer bug that motivated replacing the M1 placeholder (see
    `app/parsers/_json_lines.py` and `test_mixed_export_detects_every_present_source` below for
    the actual bug that was found and fixed here)."""
    top_domains = Path(__file__).parent.parent / "datagen" / "data" / "top_domains.txt"
    text = top_domains.read_text(encoding="utf-8")
    assert detect_source_types(text) == []


def test_storage_shim_delegates_to_the_real_registry() -> None:
    """`app/storage/source_sniffer.py` is a thin re-export now, not a second implementation."""
    assert legacy_detect_source_types is detect_source_types


# ---------------------------------------------------------------------------- mixed export


def test_mixed_export_detects_every_present_source(tmp_path: Path) -> None:
    """Regression test for a real bug found while building this registry: interleaving three
    formats so no single one dominates the sample used to make each per-line ratio's
    denominator *every* line in the sample (including the other two formats' lines) rather than
    just its own candidates. Split evenly three ways, each format's naive ratio topped out at
    1/3 and never cleared `SNIFF_THRESHOLD`, so `detect_source_types` returned `[]` on a sample
    that plainly contained all three -- the same failure mode the M3 brief warns about ("that
    placeholder currently returns [] for real log files"). Fixed in
    `app/parsers/_json_lines.py` (JSON sources) and `ZScalerParser.sniff`'s body-heuristic
    fallback (the delimited side) by excluding confidently-other-format lines from each
    format's own denominator instead of counting them as misses.
    """
    files = _write_one_of_each(tmp_path, n=15)
    zs_lines = files["zscaler"].read_text().splitlines()[1:11]  # skip header
    okta_lines = files["okta"].read_text().splitlines()[:10]
    ct_lines = files["cloudtrail"].read_text().splitlines()[:10]

    mixed: list[str] = []
    for a, b, c in zip(zs_lines, okta_lines, ct_lines, strict=True):
        mixed.extend([a, b, c])
    sample = "\n".join(mixed)

    scores = DEFAULT_REGISTRY.sniff_scores(sample)
    assert all(score >= SNIFF_THRESHOLD for score in scores.values()), scores
    assert set(detect_source_types(sample)) == {"zscaler", "okta", "cloudtrail"}


def test_evenly_mixed_two_source_sample_still_detects_both(tmp_path: Path) -> None:
    files = _write_one_of_each(tmp_path, n=15)
    okta_lines = files["okta"].read_text().splitlines()[:10]
    ct_lines = files["cloudtrail"].read_text().splitlines()[:10]
    mixed = []
    for a, b in zip(okta_lines, ct_lines, strict=True):
        mixed.extend([a, b])
    detected = set(detect_source_types("\n".join(mixed)))
    assert detected == {"okta", "cloudtrail"}


# ---------------------------------------------------------------------------- best_match / get


def test_best_match_picks_the_single_highest_scorer(tmp_path: Path) -> None:
    files = _write_one_of_each(tmp_path)
    parser = DEFAULT_REGISTRY.best_match(files["okta"].read_text())
    assert parser is not None
    assert parser.source_type == "okta"


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


def test_iter_events_dispatches_to_the_right_ocsf_class(tmp_path: Path) -> None:
    files = _write_one_of_each(tmp_path, n=20)
    expected = {
        "zscaler": HTTPActivity,
        "okta": Authentication,
        "cloudtrail": APIActivity,
    }
    for source, path in files.items():
        with path.open(encoding="utf-8") as fh:
            results = list(iter_events(source, fh))
        assert results, f"no events parsed for {source}"
        assert all(isinstance(r, expected[source]) for r in results)


def test_iter_events_skips_blank_lines() -> None:
    lines = iter(
        [
            "{}\n",  # blank-ish but valid JSON dict; still a parse failure (missing published)
            "\n",  # genuinely blank
            json.dumps({"published": "2026-01-01T00:00:00.000Z", "eventType": "x", "outcome": {}})
            + "\n",
        ]
    )
    results = list(iter_events("okta", lines))
    # The blank line produced no result at all; the other two each produced exactly one.
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
