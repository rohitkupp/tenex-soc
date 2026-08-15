"""`app.parsers.okta` against docs/03 "Okta System Log -> OCSF Authentication (3002)".

Round-trip fixtures come from `datagen.emitters.okta` (M2's generator) -- see
`tests/test_parsers_zscaler.py`'s module docstring for why hand-rolled JSON is avoided wherever
a real emitted line will do.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.ocsf import Authentication
from app.parsers.base import ParseFailure
from app.parsers.okta import OktaParser
from app.parsers.registry import iter_events
from datagen import corpus
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)


def _write_corpus(tmp_path: Path, *, events: int = 400) -> Path:
    org = corpus.build_org(13, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(13, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(3)
    corpus.write_benign_corpus(
        org, root, window, tmp_path, proxy_events=0, okta_events=events, cloudtrail_events=0
    )
    return tmp_path / "benign_okta.jsonl"


# ---------------------------------------------------------------------------- sniff


def test_sniff_recognizes_real_okta_lines(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    sample = "\n".join(log_path.read_text().splitlines()[:50])
    assert OktaParser().sniff(sample) >= 0.6


def test_sniff_rejects_unrelated_json() -> None:
    sample = "\n".join(json.dumps({"a": 1, "b": 2}) for _ in range(5))
    assert OktaParser().sniff(sample) < 0.6


def test_sniff_rejects_non_json_text() -> None:
    assert OktaParser().sniff("hello\nworld\nnot json at all") < 0.6


def test_sniff_empty_sample_scores_zero() -> None:
    assert OktaParser().sniff("") == 0.0


# ---------------------------------------------------------------------------- round trip


def test_round_trip_maps_every_docs03_field(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    first_line = log_path.read_text().splitlines()[0]
    raw = json.loads(first_line)

    result = OktaParser().parse_line(first_line, 1)
    assert isinstance(result, Authentication)

    # docs/03's Okta -> OCSF Authentication (3002) table, row by row.
    assert result.time.strftime("%Y-%m-%dT%H:%M:%S.") == raw["published"][:20]
    assert result.activity_name == raw["eventType"]
    assert result.status == raw["outcome"]["result"]
    assert result.status_detail == raw["outcome"]["reason"]
    assert result.actor.user.email_addr == raw["actor"]["alternateId"]
    assert result.actor.user.name == raw["actor"]["displayName"]
    assert result.src_endpoint.ip == raw["client"]["ipAddress"]
    assert result.http_request is not None
    assert result.http_request.user_agent == raw["client"]["userAgent"]["rawUserAgent"]
    geo = raw["client"]["geographicalContext"]
    assert result.src_endpoint.location is not None
    assert result.src_endpoint.location.country == geo["country"]
    assert result.src_endpoint.location.city == geo["city"]
    assert result.src_endpoint.location.coordinates is not None
    assert result.src_endpoint.location.coordinates.lat == geo["geolocation"]["lat"]
    assert result.src_endpoint.location.coordinates.lon == geo["geolocation"]["lon"]
    assert result.src_endpoint.autonomous_system is not None
    assert result.src_endpoint.autonomous_system.number == raw["securityContext"]["asNumber"]
    assert result.unmapped["is_proxy"] == raw["securityContext"]["isProxy"]
    assert result.auth_protocol == raw["authenticationContext"]["authenticationStep"]
    assert result.unmapped["debug"] == raw["debugContext"]["debugData"]
    assert len(result.resources) == len(raw["target"])
    for resource, target in zip(result.resources, raw["target"], strict=True):
        assert resource.type == target["type"]
        assert resource.uid == target["id"]

    hot = result.hot_columns()
    assert hot["ts"] == result.time
    assert hot["principal"] == raw["actor"]["alternateId"]
    assert hot["src_ip"] == raw["client"]["ipAddress"]
    assert hot["action"] == raw["outcome"]["result"]
    assert hot["user_agent"] == raw["client"]["userAgent"]["rawUserAgent"]
    assert hot["event_key"] == f"{raw['eventType']}:{raw['outcome']['result']}"
    # Authentication events never populate the proxy-shaped hot columns.
    assert hot["domain"] is None
    assert hot["dst_ip"] is None
    assert hot["status_code"] is None


# ---------------------------------------------------------------------------- event_key


def test_event_key_matches_docs03_formula() -> None:
    line = json.dumps(
        {
            "published": "2026-01-01T00:00:00.000Z",
            "eventType": "user.mfa.factor.deactivate",
            "outcome": {"result": "SUCCESS", "reason": None},
            "actor": {"alternateId": "user@corp.example", "displayName": "User"},
            "client": {"ipAddress": "10.0.0.5", "userAgent": {"rawUserAgent": "curl/8.0"}},
        }
    )
    result = OktaParser().parse_line(line, 1)
    assert isinstance(result, Authentication)
    assert result.event_key == "user.mfa.factor.deactivate:SUCCESS"


def test_failure_outcome_survives_normalization() -> None:
    """docs/03 explicitly calls out event types that "matter for detection" -- prove a FAILURE
    outcome on one of them (MFA) round-trips intact, both the event_key token and status_detail."""
    line = json.dumps(
        {
            "published": "2026-01-01T00:00:00.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            "actor": {"alternateId": "user@corp.example", "displayName": "User"},
            "client": {"ipAddress": "10.0.0.5", "userAgent": {"rawUserAgent": "Mozilla/5.0"}},
        }
    )
    result = OktaParser().parse_line(line, 1)
    assert isinstance(result, Authentication)
    assert result.event_key == "user.authentication.auth_via_mfa:FAILURE"
    assert result.status_detail == "INVALID_CREDENTIALS"
    assert result.hot_columns()["action"] == "FAILURE"


# ---------------------------------------------------------------------------- failure tracking


def test_invalid_json_is_a_parse_failure() -> None:
    result = OktaParser().parse_line("{not valid json", 3)
    assert isinstance(result, ParseFailure)
    assert result.line_no == 3
    assert result.source_type == "okta"
    assert "JSON" in result.reason


def test_missing_published_is_a_parse_failure() -> None:
    line = json.dumps({"eventType": "user.session.start", "outcome": {"result": "SUCCESS"}})
    result = OktaParser().parse_line(line, 9)
    assert isinstance(result, ParseFailure)
    assert "published" in result.reason


def test_json_array_is_a_parse_failure() -> None:
    result = OktaParser().parse_line("[1, 2, 3]", 1)
    assert isinstance(result, ParseFailure)
    assert "object" in result.reason


def test_iter_events_has_no_header_and_starts_at_line_one(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path, events=50)
    with log_path.open(encoding="utf-8") as fh:
        results = list(iter_events("okta", fh))
    assert all(isinstance(r, Authentication) for r in results)
    line_nos = [r.line_no for r in results if isinstance(r, Authentication)]
    assert line_nos[0] == 1
    assert line_nos == sorted(line_nos)
