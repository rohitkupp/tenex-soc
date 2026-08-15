"""`app.parsers.zscaler` against docs/03 "ZScaler NSS Web -> OCSF HTTP Activity (4002)".

Round-trip fixtures come from `datagen.emitters.zscaler` (M2's generator), not hand-rolled
strings — CLAUDE.md's M3 brief: "M2 already built a synthetic log generator ... Its output is
your test corpus — do NOT invent sample data." Only the deliberately-malformed edge cases below
are hand-written, because a real emitter cannot produce garbage by construction.
"""

from __future__ import annotations

from pathlib import Path

from app.ocsf import HTTPActivity
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events
from app.parsers.zscaler import (
    ZScalerParser,
    _normalize_action,
    _status_class,
)
from datagen import corpus
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)


def _write_corpus(tmp_path: Path, *, events: int = 400) -> Path:
    org = corpus.build_org(11, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(11, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(3)
    corpus.write_benign_corpus(org, root, window, tmp_path, proxy_events=events)
    return tmp_path / "benign_zscaler.log"


# ---------------------------------------------------------------------------- sniff


def test_sniff_recognizes_the_real_header(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    sample = "\n".join(log_path.read_text().splitlines()[:50])
    assert ZScalerParser().sniff(sample) >= 0.6


def test_sniff_recognizes_a_headerless_data_block(tmp_path: Path) -> None:
    """A mid-file chunk of a mixed export never carries the header line -- the body-heuristic
    fallback must still recognize it (docs/03 "detect per-line-block")."""
    log_path = _write_corpus(tmp_path)
    lines = log_path.read_text().splitlines()[1:41]  # skip header, take 40 data rows
    assert ZScalerParser().sniff("\n".join(lines)) >= 0.6


def test_sniff_rejects_unrelated_text() -> None:
    prose = "\n".join(
        [
            "# Top-sites list used to ground domain-popularity sampling.",
            "google.com",
            "facebook.com",
            "youtube.com",
        ]
    )
    assert ZScalerParser().sniff(prose) < 0.6


def test_sniff_empty_sample_scores_zero() -> None:
    assert ZScalerParser().sniff("") == 0.0


# ---------------------------------------------------------------------------- round trip


def test_round_trip_maps_every_docs03_field(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    lines = log_path.read_text().splitlines()
    header, first_line = lines[0], lines[1]

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(first_line, 2)

    assert isinstance(result, HTTPActivity)
    raw = dict(zip(header.split("\t"), first_line.split("\t"), strict=True))

    # docs/03's ZScaler -> OCSF HTTP Activity (4002) table, row by row.
    assert result.time.strftime("%Y-%m-%dT%H:%M:%SZ") == raw["datetime"]
    assert result.actor.user.email_addr == raw["user"]
    assert result.src_endpoint.ip == raw["clientip"]
    assert result.dst_endpoint is not None and result.dst_endpoint.ip == raw["serverip"]
    assert result.http_request is not None and result.http_request.url is not None
    assert result.http_request.url.hostname == raw["host"]
    assert result.http_request.url.path == raw["url"]
    assert result.http_request.http_method == raw["requestmethod"]
    assert result.http_response is not None and result.http_response.code == int(raw["status"])
    assert result.traffic is not None
    assert result.traffic.bytes_out == int(raw["requestsize"])
    assert result.traffic.bytes_in == int(raw["responsesize"])
    assert result.http_request.user_agent == raw["useragent"]
    assert result.activity_name == raw["action"]
    assert result.disposition == _normalize_action(raw["action"])
    assert result.http_request.url.category_ids == [raw["urlcategory"]]
    assert result.unmapped.get("url_supercategory") == raw["urlsupercategory"]
    assert result.unmapped.get("app_name") == raw["appname"]
    assert result.unmapped.get("app_class") == raw["appclass"]
    assert result.risk_score == int(raw["riskscore"])
    assert result.http_request.referrer == (None if raw["referer"] == "None" else raw["referer"])
    assert raw["location"] in result.actor.user.groups
    assert raw["department"] in result.actor.user.groups

    # Hot columns (docs/02) are the projection of the same data.
    hot = result.hot_columns()
    assert hot["ts"] == result.time
    assert hot["principal"] == raw["user"]
    assert hot["src_ip"] == raw["clientip"]
    assert hot["dst_ip"] == raw["serverip"]
    assert hot["domain"] == raw["host"]
    assert hot["url_path"] == raw["url"]
    assert hot["action"] == _normalize_action(raw["action"])
    assert hot["http_method"] == raw["requestmethod"]
    assert hot["status_code"] == int(raw["status"])
    assert hot["bytes_out"] == int(raw["requestsize"])
    assert hot["bytes_in"] == int(raw["responsesize"])
    assert hot["user_agent"] == raw["useragent"]
    assert hot["event_key"] == result.event_key


def test_threat_fields_map_to_malware(tmp_path: Path) -> None:
    """`threatname`/`threatcategory` -> `malware[].name`/`.classification_ids` (docs/03) --
    absent from the benign corpus by design (docs/11), so this is built directly."""
    parser = ZScalerParser()
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tbad.example\t/x\t"
        "GET\t200\t100\t200\tMozilla/5.0\tBlocked\tMalware Sites\tSecurity\tGeneral Browsing\t"
        "General Browsing\tEmotet\tTrojan\t95\tBlocked by AV\tNone\tNone\tNone\tUS-CA\tIT"
    )
    result = parser.parse_line(line, 2)
    assert isinstance(result, HTTPActivity)
    assert len(result.malware) == 1
    assert result.malware[0].name == "Emotet"
    assert result.malware[0].classification_ids == ["Trojan"]
    assert result.unmapped["block_reason"] == "Blocked by AV"


# ---------------------------------------------------------------------------- event_key


def test_action_normalization_rule() -> None:
    assert _normalize_action("Allowed") == "allowed"
    assert _normalize_action("Blocked") == "blocked"
    assert _normalize_action("Redirected") == "other"
    assert _normalize_action(None) == "other"


def test_status_class_buckets() -> None:
    assert _status_class(200) == "2xx"
    assert _status_class(404) == "4xx"
    assert _status_class(503) == "5xx"
    assert _status_class(None) == "unknown"


def test_event_key_matches_docs03_formula() -> None:
    parser = ZScalerParser()
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tgood.example\t/x\t"
        "POST\t403\t100\t200\tcurl/8.0\tBlocked\tFile Host\tInternet Services\tGeneral Browsing\t"
        "File Share\tNone\tNone\t25\tPolicy\tNone\tNone\tNone\tUS-CA\tIT"
    )
    result = parser.parse_line(line, 2)
    assert isinstance(result, HTTPActivity)
    assert result.event_key == "POST:File Host:blocked:4xx"


# ---------------------------------------------------------------------------- None sentinel


def test_literal_none_string_becomes_null() -> None:
    """docs/03 + the emitter's own contract: the wire value `None` means absent, not the word."""
    parser = ZScalerParser()
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tNone\texample.com\t/\t"
        "GET\t200\t0\t0\tNone\tAllowed\tWeb Search\tInternet Services\tGeneral Browsing\t"
        "Web Search\tNone\tNone\t0\tNone\tNone\tNone\tNone\tNone\tNone"
    )
    result = parser.parse_line(line, 2)
    assert isinstance(result, HTTPActivity)
    assert result.dst_endpoint is None
    assert result.http_request is not None
    assert result.http_request.user_agent is None
    assert result.actor.user.groups == []
    assert "block_reason" not in result.unmapped


# ---------------------------------------------------------------------------- header binding


def test_bind_header_rebinds_a_reordered_subset_header() -> None:
    """A real NSS export's configured field list rarely matches the canonical 25-column order.
    `bind_header` must still map columns correctly by name."""
    header = (
        "datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction\turlcategory\tuseragent"
    )
    line = "2024-01-01T00:00:00Z\tu1@example.com\t10.0.0.1\texample.com\t/\tGET\t200\tAllowed\tGeneral\tMozilla/5.0"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.actor.user.email_addr == "u1@example.com"
    assert result.src_endpoint.ip == "10.0.0.1"
    assert result.http_request is not None and result.http_request.url is not None
    assert result.http_request.url.hostname == "example.com"
    assert result.http_response is not None and result.http_response.code == 200
    assert result.disposition == "allowed"


# ---------------------------------------------------------------------------- failure tracking


def test_too_few_fields_is_a_parse_failure() -> None:
    result = ZScalerParser().parse_line("onlyonefield", 5)
    assert isinstance(result, ParseFailure)
    assert result.line_no == 5
    assert result.source_type == "zscaler"
    assert "field" in result.reason


def test_unparseable_datetime_is_a_parse_failure() -> None:
    line = "not-a-date\t" + "\t".join(["x"] * 24)
    result = ZScalerParser().parse_line(line, 7)
    assert isinstance(result, ParseFailure)
    assert result.line_no == 7
    assert "datetime" in result.reason


def test_iter_events_skips_the_header_line_and_counts_line_numbers(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path, events=50)
    with log_path.open(encoding="utf-8") as fh:
        results = list(iter_events("zscaler", fh))
    # Header occupies physical line 1; data starts at line 2 (docs/11 line-number contract).
    assert all(isinstance(r, HTTPActivity) for r in results)
    line_nos = [r.line_no for r in results if isinstance(r, HTTPActivity)]
    assert line_nos[0] == 2
    assert line_nos == sorted(line_nos)
