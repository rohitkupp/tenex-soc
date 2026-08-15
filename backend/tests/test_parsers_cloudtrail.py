"""`app.parsers.cloudtrail` against docs/03 "AWS CloudTrail -> OCSF API Activity (6003)".

Round-trip fixtures come from `datagen.emitters.cloudtrail` (M2's generator) -- see
`tests/test_parsers_zscaler.py`'s module docstring for why hand-rolled JSON is avoided wherever
a real emitted line will do. The one exception is the errored-call fixture: docs/11's benign
corpus keeps CloudTrail's error rate low (~1-2%) on purpose, so a small benign sample may not
contain one; that case is built directly from `CloudTrailEmitter.build_event`, still through the
real emitter, not by hand-writing JSON.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.ocsf import APIActivity
from app.parsers.base import ParseFailure
from app.parsers.cloudtrail import CloudTrailParser
from app.parsers.registry import iter_events
from datagen import corpus
from datagen.emitters.cloudtrail import CloudTrailEmitter
from datagen.rng import SeededRandom
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=4)


def _write_corpus(tmp_path: Path, *, events: int = 400) -> Path:
    org = corpus.build_org(17, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(17, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(3)
    corpus.write_benign_corpus(
        org, root, window, tmp_path, proxy_events=0, okta_events=0, cloudtrail_events=events
    )
    return tmp_path / "benign_cloudtrail.jsonl"


# ---------------------------------------------------------------------------- sniff


def test_sniff_recognizes_real_cloudtrail_lines(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    sample = "\n".join(log_path.read_text().splitlines()[:50])
    assert CloudTrailParser().sniff(sample) >= 0.6


def test_sniff_rejects_okta_shaped_json(tmp_path: Path) -> None:
    """Okta and CloudTrail are both JSON Lines -- disjoint required-key sets must keep them from
    cross-matching (`app/parsers/_json_lines.py`)."""
    okta_dir = tmp_path / "okta"
    org = corpus.build_org(19, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(19, corpus.ROLE_BENIGN))
    corpus.write_benign_corpus(
        org,
        root,
        TimeWindow.of_days(3),
        okta_dir,
        proxy_events=0,
        okta_events=200,
        cloudtrail_events=0,
    )
    sample = "\n".join((okta_dir / "benign_okta.jsonl").read_text().splitlines()[:50])
    assert CloudTrailParser().sniff(sample) < 0.6


def test_sniff_empty_sample_scores_zero() -> None:
    assert CloudTrailParser().sniff("") == 0.0


# ---------------------------------------------------------------------------- round trip


def test_round_trip_maps_every_docs03_field(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    first_line = log_path.read_text().splitlines()[0]
    raw = json.loads(first_line)

    result = CloudTrailParser().parse_line(first_line, 1)
    assert isinstance(result, APIActivity)

    # docs/03's CloudTrail -> OCSF API Activity (6003) table, row by row.
    assert result.time.strftime("%Y-%m-%dT%H:%M:%SZ") == raw["eventTime"]
    assert result.api is not None
    assert result.api.operation == raw["eventName"]
    assert result.api.service is not None and result.api.service.name == raw["eventSource"]
    assert result.actor.user.uid == raw["userIdentity"]["arn"]
    assert result.actor.user.type == raw["userIdentity"]["type"]
    assert result.src_endpoint.ip == raw["sourceIPAddress"]
    assert result.http_request is not None
    assert result.http_request.user_agent == raw["userAgent"]
    assert result.status_code == raw.get("errorCode")
    assert result.cloud is not None and result.cloud.region == raw["awsRegion"]
    assert result.api.request == raw.get("requestParameters")
    assert result.api.response == raw.get("responseElements")

    hot = result.hot_columns()
    assert hot["ts"] == result.time
    assert hot["principal"] == raw["userIdentity"]["arn"]
    assert hot["src_ip"] == raw["sourceIPAddress"]
    assert hot["user_agent"] == raw["userAgent"]
    error_code = raw.get("errorCode")
    assert hot["event_key"] == f"{raw['eventSource']}:{raw['eventName']}:{error_code or 'OK'}"
    # API Activity events never populate the proxy/identity-shaped hot columns.
    assert hot["domain"] is None
    assert hot["action"] is None
    assert hot["http_method"] is None


# ---------------------------------------------------------------------------- event_key


def test_event_key_omits_error_code_on_success(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    first_line = log_path.read_text().splitlines()[0]
    raw = json.loads(first_line)
    assert "errorCode" not in raw  # benign corpus's first record in this fixture is a success

    result = CloudTrailParser().parse_line(first_line, 1)
    assert isinstance(result, APIActivity)
    assert result.event_key == f"{raw['eventSource']}:{raw['eventName']}:OK"
    assert result.status_code is None


def test_event_key_and_hot_status_code_on_an_errored_call() -> None:
    """docs/03: `errorCode -> status_code -> status_code`. `errorCode` is a string
    ("AccessDenied", ...), not an HTTP-style int -- events.status_code (docs/02) is INTEGER, so
    the hot column is deliberately left None while the OCSF field keeps the real value. See
    `app/ocsf/api_activity.py`'s docstring for the full writeup of this disagreement."""
    org = corpus.build_org(23, corpus.ROLE_EVAL, _ORG_SPEC)
    user = next(u for u in org.principals if not u.is_service_account)
    emitter = CloudTrailEmitter()
    rng = SeededRandom(1)
    record = emitter.build_event(
        user=user,
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        event_name="GetSecretValue",
        event_source="secretsmanager.amazonaws.com",
        rng=rng,
        error_code="AccessDenied",
    )
    line = emitter.serialize(record)

    result = CloudTrailParser().parse_line(line, 1)
    assert isinstance(result, APIActivity)
    assert result.event_key == "secretsmanager.amazonaws.com:GetSecretValue:AccessDenied"
    assert result.status_code == "AccessDenied"  # full fidelity, in the OCSF field
    assert result.hot_columns()["status_code"] is None  # but not in the INT hot column


# ---------------------------------------------------------------------------- failure tracking


def test_invalid_json_is_a_parse_failure() -> None:
    result = CloudTrailParser().parse_line("{bad json", 2)
    assert isinstance(result, ParseFailure)
    assert result.line_no == 2
    assert result.source_type == "cloudtrail"


def test_missing_event_time_is_a_parse_failure() -> None:
    line = json.dumps({"eventName": "GetObject", "eventSource": "s3.amazonaws.com"})
    result = CloudTrailParser().parse_line(line, 4)
    assert isinstance(result, ParseFailure)
    assert "eventTime" in result.reason


def test_missing_event_name_is_a_parse_failure() -> None:
    line = json.dumps({"eventTime": "2026-01-01T00:00:00Z", "eventSource": "s3.amazonaws.com"})
    result = CloudTrailParser().parse_line(line, 6)
    assert isinstance(result, ParseFailure)


def test_iter_events_has_no_header_and_starts_at_line_one(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path, events=100)
    with log_path.open(encoding="utf-8") as fh:
        results = list(iter_events("cloudtrail", fh))
    assert all(isinstance(r, APIActivity) for r in results)
    line_nos = [r.line_no for r in results if isinstance(r, APIActivity)]
    assert line_nos[0] == 1
    assert line_nos == sorted(line_nos)
