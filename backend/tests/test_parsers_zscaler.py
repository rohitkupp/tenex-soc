"""`app.parsers.zscaler` against docs/03 "ZScaler NSS Web -> OCSF HTTP Activity (4002)".

Round-trip fixtures come from `datagen.emitters.zscaler` (M2's generator), not hand-rolled
strings — CLAUDE.md's M3 brief: "M2 already built a synthetic log generator ... Its output is
your test corpus — do NOT invent sample data." Only the deliberately-malformed edge cases below
are hand-written, because a real emitter cannot produce garbage by construction.
"""

from __future__ import annotations

import base64
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
from datagen.scenarios import scenario_keys
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
    assert result.unmapped.get("location") == raw["location"]
    assert result.unmapped.get("department") == raw["department"]

    # Asset/device extension (this task) -- the benign corpus interleaves human and service-
    # account traffic, so the first record may be either; service accounts carry no Client
    # Connector device at all (`datagen.emitters.zscaler._device_profile`'s own docstring), which
    # `test_device_fields_map_to_ocsf_device`/`test_device_fields_absent_stay_absent_and_do_not_
    # crash` below cover as their own dedicated fire/no-fire fixtures. This assertion just checks
    # both branches map consistently, whichever one this particular first record happens to be.
    if raw["devicehostname"] == "None":
        assert result.device is None
    else:
        assert result.device is not None
        assert result.device.hostname == raw["devicehostname"]
        assert result.device.name == raw["devicename"]
        assert result.device.owner == raw["deviceowner"]
        assert result.device.os is not None
        assert result.device.os.version == raw["deviceosversion"]
    assert result.flow_type == raw["flow_type"]
    assert result.bypassed_traffic == (raw["bypassed_traffic"] == "1")

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
    if raw["devicehostname"] == "None":
        assert hot["hostname"] is None
    else:
        assert hot["hostname"] == raw["devicehostname"]
        assert hot["device_name"] == raw["devicename"]
        assert hot["device_owner"] == raw["deviceowner"]
        assert hot["os_version"] == raw["deviceosversion"]
    assert hot["flow_type"] == raw["flow_type"]
    assert hot["bypassed_traffic"] == (raw["bypassed_traffic"] == "1")


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


# ---------------------------------------------------------------------------- device fields


def test_device_fields_map_to_ocsf_device() -> None:
    """Fire case: a transaction with real Client Connector device fields maps them onto
    `HTTPActivity.device` (docs/v1/zscaler-nss-web-fields.md "Zscaler Client Connector Device
    Information"), normalized OS type and all."""
    parser = ZScalerParser()
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tgood.example\t/x\t"
        "GET\t200\t100\t200\tMozilla/5.0\tAllowed\tGeneral Browsing\tGeneral\tGeneral Browsing\t"
        "General Browsing\tNone\tNone\t0\tNone\tNone\tNone\tNone\tUS-CA\tIT\t"
        "THINKPADSMITH\tPC11NLPA:5F08D97BBF43257A8FB4BBF4061A38AE324EF734\tWindows OS\t"
        "Version 10.14.2 (Build 18C54)\tjsmith\t0\tZIA"
    )
    result = parser.parse_line(line, 2)
    assert isinstance(result, HTTPActivity)
    assert result.device is not None
    assert result.device.hostname == "THINKPADSMITH"
    assert result.device.name == "PC11NLPA:5F08D97BBF43257A8FB4BBF4061A38AE324EF734"
    assert result.device.owner == "jsmith"
    assert result.device.os is not None
    assert result.device.os.type == "windows"
    assert result.device.os.version == "Version 10.14.2 (Build 18C54)"
    assert result.bypassed_traffic is False
    assert result.flow_type == "ZIA"

    hot = result.hot_columns()
    assert hot["hostname"] == "THINKPADSMITH"
    assert hot["os_type"] == "windows"


def test_device_fields_absent_stay_absent_and_do_not_crash() -> None:
    """No-fire case: the `None` sentinel on every device column (service-account/headless-host
    traffic, `datagen.emitters.zscaler._device_profile`'s own realistic case) must not fabricate a
    `device`, not raise, and must leave `bypassed_traffic`/`flow_type` genuinely `None` rather than
    a falsy-looking default."""
    parser = ZScalerParser()
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tgood.example\t/x\t"
        "GET\t200\t100\t200\tMozilla/5.0\tAllowed\tGeneral Browsing\tGeneral\tGeneral Browsing\t"
        "General Browsing\tNone\tNone\t0\tNone\tNone\tNone\tNone\tUS-CA\tIT\t"
        "None\tNone\tNone\tNone\tNone\tNone\tNone"
    )
    result = parser.parse_line(line, 2)
    assert isinstance(result, HTTPActivity)
    assert result.device is None
    assert result.bypassed_traffic is None
    assert result.flow_type is None

    hot = result.hot_columns()
    assert hot["hostname"] is None
    assert hot["os_type"] is None
    assert hot["bypassed_traffic"] is None


def test_deviceostype_normalizes_the_zscaler_enum() -> None:
    """Every value of `deviceostype`'s documented 5-value enum normalizes to the tag-friendly
    vocabulary `app.ocsf.normalize_os_type` defines."""
    cases = {
        "iOS": "ios",
        "Android OS": "android",
        "Windows OS": "windows",
        "MAC OS": "macos",
        "Other OS": "other",
    }
    for raw_type, expected in cases.items():
        line = (
            "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tNone\texample.com\t/\t"
            "GET\t200\t0\t0\tNone\tAllowed\tWeb Search\tInternet Services\tGeneral Browsing\t"
            "Web Search\tNone\tNone\t0\tNone\tNone\tNone\tNone\tNone\tNone\t"
            f"HOST1\tNone\t{raw_type}\tNone\tNone\tNone\tNone"
        )
        result = ZScalerParser().parse_line(line, 2)
        assert isinstance(result, HTTPActivity), raw_type
        assert result.device is not None and result.device.os is not None
        assert result.device.os.type == expected, raw_type


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


# ---------------------------------------------------------------------------- regression: every
# generator output must round-trip through this parser
#
# The legacy `datagen/generate_corpus.py` (deleted; see `datagen/labeled_corpus.py`'s module
# docstring and docs/v1/11-SYNTHETIC-DATA.md) wrote `datetime.strftime("%Y-%m-%d %H:%M:%S")`
# while this parser only ever accepted `...THH:MM:SSZ` (`_DATETIME_FORMATS` above) — every one of
# the 271 files under `backend/data/corpus/` plus the 30 under `backend/data/eval/golden/` it
# produced was 100% `ParseFailure`, 0 events. The two generators drifted because they were
# maintained independently with no test tying either one's output back to this parser. This is
# that test for the generator that survived the consolidation: every scenario `datagen` can
# register, plus the unlabeled benign corpus, must still produce a file this parser reads with
# zero failures. A future scenario module or a future emitter timestamp change that breaks this
# contract fails here, in seconds, instead of silently shipping an unparseable corpus again.
#
# Seed 7 (docs/11's own CLI example seed) at 10,000 background events is the smallest
# empirically-verified-reliable combination for every scenario currently registered, including
# the three with a real statistical acceptance check (`peer_group_deviation`, `seasonal_deviation`,
# `low_and_slow_exfil` — see their own `*AcceptanceError` classes): their gates are sensitive to
# the specific (seed, org) pair, not just event volume, so this pin is deliberate, not an
# arbitrary default that happened to work once.
_REGRESSION_SEED = 7
_REGRESSION_EVENTS = 10_000


def test_every_registered_scenario_parses_with_zero_failures(tmp_path: Path) -> None:
    assert scenario_keys(), "no scenarios registered — datagen.scenarios discovery is broken"

    for key in scenario_keys():
        written = corpus.run_scenario(
            key, _REGRESSION_SEED, tmp_path / key, total_events=_REGRESSION_EVENTS
        )
        log_path = next(p for p in written if p.suffix == ".log")

        n_events = n_failures = 0
        with log_path.open(encoding="utf-8") as fh:
            for result in iter_events("zscaler", fh):
                if isinstance(result, ParseFailure):
                    n_failures += 1
                else:
                    n_events += 1

        assert n_failures == 0, f"{key}: {n_failures} parse failures in {log_path}"
        assert n_events > 0, f"{key}: parser yielded zero events from {log_path}"


def test_benign_corpus_parses_with_zero_failures(tmp_path: Path) -> None:
    """The large unlabeled benign corpus (`python -m datagen benign`) writes through a different
    path (`write_benign_corpus`, external-merge-sorted) than the eval scenarios above — its own
    assertion rather than assuming the scenario check covers it. This is also the single largest
    share of `make gen-data`'s output by volume, and the file the original bug report's "upload
    the result and get nothing" scenario would hit first."""
    log_path = _write_corpus(tmp_path, events=2_000)

    n_events = n_failures = 0
    with log_path.open(encoding="utf-8") as fh:
        for result in iter_events("zscaler", fh):
            if isinstance(result, ParseFailure):
                n_failures += 1
            else:
                n_events += 1

    assert n_failures == 0
    assert n_events > 0


# ---------------------------------------------------------------------------- encoding variants
#
# docs/NSS_Feed_Output_Format__Web_Logs.pdf "Obfuscated Fields" / "Base64 Fields" /
# "Hex-Encoded Fields" (docs/v1/zscaler-nss-web-fields.md carries the full extracted lists). A
# real NSS feed's field list is customer-configurable per column, so any of these can arrive in
# place of the plain field this parser already maps. One fire/no-fire fixture pair per encoding,
# per CLAUDE.md.


def test_base64_fields_decode_to_the_real_value() -> None:
    """Fire case: a header declaring `b64login`/`b64host` instead of `login`/`host` still
    resolves to the real, decoded value -- never the base64 text itself."""
    login_b64 = base64.b64encode(b"user@corp.example").decode()
    host_b64 = base64.b64encode(b"good.example").decode()
    header = "datetime\tb64login\tclientip\tb64host\turl\trequestmethod\tstatus\taction"
    line = f"2026-01-01T00:00:00Z\t{login_b64}\t10.0.0.1\t{host_b64}\t/\tGET\t200\tAllowed"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.actor.user.email_addr == "user@corp.example"
    assert result.http_request is not None and result.http_request.url is not None
    assert result.http_request.url.hostname == "good.example"
    assert "obfuscated_fields" not in result.unmapped


def test_malformed_base64_is_a_recorded_parse_failure() -> None:
    """No-fire case: a `b64host` column that is not valid base64 must fail the parse -- never
    pass the raw base64 text through as if it were a real hostname."""
    header = "datetime\tuser\tclientip\tb64host\turl\trequestmethod\tstatus\taction"
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t***not-base64***\t/\tGET\t200\tAllowed"
    )

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 3)

    assert isinstance(result, ParseFailure)
    assert result.line_no == 3
    assert "base64" in result.reason
    assert "host" in result.reason


def test_hex_encoded_fields_decode_non_printable_escapes() -> None:
    """Fire case: `eurl` percent-decodes a non-printable escape (docs: "<=0x20 or >=0x7F", the
    PDF's own `%20` example) while leaving the surrounding printable characters untouched."""
    header = "datetime\tuser\tclientip\thost\teurl\trequestmethod\tstatus\taction"
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tgood.example\t"
        "/search%20term\tGET\t200\tAllowed"
    )

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.http_request is not None and result.http_request.url is not None
    assert result.http_request.url.path == "/search term"


def test_hex_encoded_login_decodes_to_the_real_user() -> None:
    """Fire case, identity field: `elogin` decodes even when a real feed fully escapes the value
    (not just its non-printable bytes) -- decoding must handle any well-formed `%HH` escape."""
    encoded = "".join(f"%{b:02X}" for b in b"user@corp.example")
    header = "datetime\telogin\tclientip\thost\turl\trequestmethod\tstatus\taction"
    line = f"2026-01-01T00:00:00Z\t{encoded}\t10.0.0.1\tgood.example\t/\tGET\t200\tAllowed"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.actor.user.email_addr == "user@corp.example"


def test_malformed_hex_escape_is_a_recorded_parse_failure() -> None:
    """No-fire case: a truncated/invalid `%`-escape in an `e`-prefixed field must fail the parse,
    never silently pass the literal `%zz` text through."""
    header = "datetime\tuser\tclientip\thost\teurl\trequestmethod\tstatus\taction"
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tgood.example\t"
        "/bad%zzpath\tGET\t200\tAllowed"
    )

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 4)

    assert isinstance(result, ParseFailure)
    assert result.line_no == 4
    assert "hex" in result.reason


def test_obfuscated_login_is_nulled_and_flagged_not_treated_as_identity() -> None:
    """Fire case (obfuscation recognized): an `ologin` column carries a random string per spec --
    it must never become `actor.user.email_addr`, and must be recorded as obfuscated so a
    downstream consumer can see that identity-linked detection/correlation is degraded for this
    feed configuration instead of silently joining on a random per-line token."""
    header = "datetime\tologin\tclientip\thost\turl\trequestmethod\tstatus\taction"
    line = "2026-01-01T00:00:00Z\tQxV9zK2p\t10.0.0.1\tgood.example\t/\tGET\t200\tAllowed"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.actor.user.email_addr is None
    assert result.unmapped["obfuscated_fields"] == ["user"]


def test_plain_login_is_not_flagged_obfuscated() -> None:
    """No-fire case: when the feed is not configured to obfuscate `login`, nothing is flagged and
    the real value flows through exactly as before this change."""
    header = "datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction"
    line = "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tgood.example\t/\tGET\t200\tAllowed"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.actor.user.email_addr == "user@corp.example"
    assert "obfuscated_fields" not in result.unmapped


def test_obfuscated_non_identity_fields_are_nulled_too() -> None:
    """The obfuscation rule is uniform, not identity-only: `urlcategory`/`dlpengine`/
    `dlpdictionaries` are value-matched fields (Sigma rules, DLP policy), and a random string can
    never satisfy that match -- carrying it through would silently stop those rules from firing
    with no signal anything changed, so they are nulled and flagged exactly like `user`/`clientip`."""
    header = (
        "datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction\t"
        "ourlcat\todlpeng\todlpdict"
    )
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tgood.example\t/\tGET\t200\tAllowed\t"
        "9fQpz2\tR8mLxo\tzT4kQw"
    )

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.http_request is not None and result.http_request.url is not None
    assert result.http_request.url.category_ids == []
    assert "dlp_engine" not in result.unmapped
    assert "dlp_dictionaries" not in result.unmapped
    assert result.unmapped["obfuscated_fields"] == ["dlpdictionaries", "dlpengine", "urlcategory"]


def test_obfuscated_clientip_is_nulled_and_flagged() -> None:
    """Fire case: `%d{ocip}` is documented with the `%d` format specifier even though the
    obfuscated payload is a random string, not a number -- the decoder must not try to coerce it
    and must still null + flag exactly like every other obfuscated field."""
    header = "datetime\tuser\tocip\thost\turl\trequestmethod\tstatus\taction"
    line = "2026-01-01T00:00:00Z\tuser@corp.example\tzk3-random-str\tgood.example\t/\tGET\t200\tAllowed"

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.src_endpoint.ip is None
    assert result.unmapped["obfuscated_fields"] == ["clientip"]


# ---------------------------------------------------------------------------- Phase 2 detection
# fields (this task) — docs/v1/zscaler-nss-web-fields.md "SSL/TLS", "Server Connection",
# "Sandbox", "File Type Control", "Network", "Threat Protection". No detector ships in this
# change (CLAUDE.md); these tests only prove the twenty new fields land where the field-inventory
# doc's reconciliation says they should -- `tls`/`tls.certificate`, `file`,
# `src_endpoint.location`/`dst_endpoint.location`, and the two fields with no natural OCSF home.

_PHASE2_HEADER = (
    "datetime\tuser\tclientip\tserverip\thost\turl\trequestmethod\tstatus\taction\t"
    "ja4_str\tdf_hostname\tdf_hosthead\tssldecrypted\tis_sslselfsigned\tis_sslexpiredca\t"
    "is_ssluntrustedca\tsrvcertvalidityperiod\tsrvocspresult\tsha256\tbamd5\t"
    "srcip_country\tdstip_country\tis_src_cntry_risky\tis_dst_cntry_risky\t"
    "upload_filename\tupload_filetype\tfiletype\tunscannabletype\tthreatseverity"
)


def test_phase2_fields_map_to_tls_file_and_location() -> None:
    """Fire case: a transaction with every Phase 2 field populated."""
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tsuspicious.example\t"
        "/gate\tGET\t200\tAllowed\t"
        "t13d191000_9dc949149365_e7c285222651\tfronted.example\tcdn.example\tYes\tYes\tNo\tFail\t"
        "Short (0-3 months)\tUnknown\t"
        "81ec78bc8298568bb5ea66d3c2972b670d0f7459b6cdbbcaacce90ab417ab15c\t"
        "196a3d797bfee07fe4596b69f4ce1141\t"
        "Afghanistan\tPortugal\tYes\tNo\t"
        "results.dat\tWindows Executables\tRAR Files\tEncrypted File\tCritical"
    )
    parser = ZScalerParser()
    parser.bind_header(_PHASE2_HEADER)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.tls is not None
    assert result.tls.ja4_hash == "t13d191000_9dc949149365_e7c285222651"
    assert result.tls.decrypted is True
    assert result.tls.certificate is not None
    assert result.tls.certificate.is_self_signed is True
    assert result.tls.certificate.is_expired is False
    assert result.tls.certificate.is_untrusted_ca is True  # "Fail" -> untrusted -> True
    assert result.tls.certificate.validity_period == "Short (0-3 months)"
    assert result.tls.certificate.ocsp_status == "Unknown"

    assert result.file is not None
    assert (
        result.file.hash_sha256
        == "81ec78bc8298568bb5ea66d3c2972b670d0f7459b6cdbbcaacce90ab417ab15c"
    )
    assert result.file.hash_md5 == "196a3d797bfee07fe4596b69f4ce1141"
    assert result.file.name == "results.dat"
    assert result.file.upload_type == "Windows Executables"
    assert result.file.download_type == "RAR Files"
    assert result.file.unscannable_type == "Encrypted File"

    assert result.src_endpoint.location is not None
    assert result.src_endpoint.location.country == "Afghanistan"
    assert result.src_endpoint.location.is_risky is True
    assert result.dst_endpoint is not None and result.dst_endpoint.location is not None
    assert result.dst_endpoint.location.country == "Portugal"
    assert result.dst_endpoint.location.is_risky is False

    assert result.df_hostname == "fronted.example"
    assert result.df_hosthead == "cdn.example"
    assert result.threat_severity == "Critical"

    hot = result.hot_columns()
    assert hot["ja4_hash"] == "t13d191000_9dc949149365_e7c285222651"


def test_is_ssluntrustedca_pass_maps_to_trusted() -> None:
    """The other half of the `Fail`/`Pass` polarity check: `Pass` -> the CA *is* trusted ->
    `is_untrusted_ca = False`."""
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tgood.example\t/\tGET\t"
        "200\tAllowed\t"
        "None\tNone\tNone\tYes\tNo\tNo\tPass\tLong (More than 12 months)\tGood\tNone\tNone\t"
        "United States\tUnited States\tNo\tNo\tNone\tNone\tNone\tNone\tNone"
    )
    parser = ZScalerParser()
    parser.bind_header(_PHASE2_HEADER)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.tls is not None and result.tls.certificate is not None
    assert result.tls.certificate.is_untrusted_ca is False
    # The wire value here is the literal sentinel "None" (docs/03's "absent values are the
    # literal string None"), not the threatseverity enum's own `"None"` bucket -- `_none_if_
    # sentinel` correctly collapses both to a real null, so this is `is None`, not `== "None"`.
    assert result.threat_severity is None


def test_phase2_fields_absent_stay_absent_and_do_not_crash() -> None:
    """No-fire case: the `None` sentinel on every Phase 2 column must not fabricate `tls`/`file`/
    `location` objects, and must leave `df_hostname`/`df_hosthead`/`threat_severity` genuinely
    `None` -- the same discipline `test_device_fields_absent_stay_absent_and_do_not_crash` already
    proves for the device-field family."""
    line = (
        "2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\t93.184.216.34\tgood.example\t/\tGET\t"
        "200\tAllowed\t"
        "None\tNone\tNone\tNone\tNone\tNone\tNone\tNone\tNone\tNone\tNone\t"
        "None\tNone\tNone\tNone\tNone\tNone\tNone\tNone\tNone"
    )
    parser = ZScalerParser()
    parser.bind_header(_PHASE2_HEADER)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.tls is None
    assert result.file is None
    assert result.src_endpoint.location is None
    assert result.dst_endpoint is not None and result.dst_endpoint.location is None
    assert result.df_hostname is None
    assert result.df_hosthead is None
    assert result.threat_severity is None

    hot = result.hot_columns()
    assert hot["ja4_hash"] is None


def test_upload_filename_base64_and_hex_variants() -> None:
    """`upload_filename` is the one Phase 2 field with a documented encoded variant
    (`b64upload_filename`/`eupload_filename`) -- proves the Phase 1 encoding-resolution
    infrastructure generalizes to a field introduced after it, not just the original twelve."""
    encoded = base64.b64encode(b"invoice Q3 2026.pdf.exe").decode()
    header = (
        "datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction\tb64upload_filename"
    )
    line = (
        f"2026-01-01T00:00:00Z\tuser@corp.example\t10.0.0.1\tgood.example\t/\tGET\t200\tAllowed\t"
        f"{encoded}"
    )

    parser = ZScalerParser()
    parser.bind_header(header)
    result = parser.parse_line(line, 2)

    assert isinstance(result, HTTPActivity)
    assert result.file is not None
    assert result.file.name == "invoice Q3 2026.pdf.exe"
