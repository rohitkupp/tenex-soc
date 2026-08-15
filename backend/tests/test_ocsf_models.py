"""`app.ocsf` — the typed OCSF event classes (docs/03: HTTP Activity 4002, Authentication 3002,
API Activity 6003), independent of any particular parser.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.ocsf import (
    Actor,
    APIActivity,
    Authentication,
    HTTPActivity,
    HttpRequest,
    HttpResponse,
    NetworkEndpoint,
    OCSFEventBase,
    Traffic,
)
from app.ocsf import User as OcsfUser

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def test_class_and_category_uids_match_real_ocsf_numbering() -> None:
    """docs/03 "Why OCSF": the reviewing team came from Chronicle/UDM, so these numbers are
    real OCSF taxonomy values, not invented ones -- category = class_uid's leading digit."""
    http = HTTPActivity(
        class_uid=4002,
        category_uid=4,
        time=_TS,
        source_type="zscaler",
        line_no=1,
        event_key="k",
    )
    auth = Authentication(
        class_uid=3002, category_uid=3, time=_TS, source_type="okta", line_no=1, event_key="k"
    )
    api = APIActivity(
        class_uid=6003,
        category_uid=6,
        time=_TS,
        source_type="cloudtrail",
        line_no=1,
        event_key="k",
    )
    assert (http.class_uid, http.category_uid) == (4002, 4)
    assert (auth.class_uid, auth.category_uid) == (3002, 3)
    assert (api.class_uid, api.category_uid) == (6003, 6)
    assert isinstance(http, OCSFEventBase)
    assert isinstance(auth, OCSFEventBase)
    assert isinstance(api, OCSFEventBase)


def test_unmapped_escape_hatch_holds_arbitrary_data() -> None:
    """docs/03: "Include the `unmapped` escape hatch the doc references.\""""
    event = HTTPActivity(
        class_uid=4002,
        category_uid=4,
        time=_TS,
        source_type="zscaler",
        line_no=1,
        event_key="k",
        unmapped={"app_name": "Slack", "dlp_engine": "content-filter-3"},
    )
    assert event.unmapped == {"app_name": "Slack", "dlp_engine": "content-filter-3"}


def test_default_unmapped_is_empty_and_independent_per_instance() -> None:
    a = HTTPActivity(
        class_uid=4002, category_uid=4, time=_TS, source_type="zscaler", line_no=1, event_key="k"
    )
    b = HTTPActivity(
        class_uid=4002, category_uid=4, time=_TS, source_type="zscaler", line_no=2, event_key="k"
    )
    a.unmapped["x"] = 1
    assert b.unmapped == {}  # Field(default_factory=dict) — no shared mutable default


def test_models_reject_unknown_fields() -> None:
    """`ConfigDict(extra="forbid")` everywhere -- a typo in a field name must fail loudly, not
    silently vanish into a dict."""
    with pytest.raises(ValidationError):
        HTTPActivity(
            class_uid=4002,
            category_uid=4,
            time=_TS,
            source_type="zscaler",
            line_no=1,
            event_key="k",
            not_a_real_field="oops",
        )


def test_base_hot_columns_is_not_implemented_directly() -> None:
    base = OCSFEventBase(
        class_uid=0, category_uid=0, time=_TS, source_type="x", line_no=1, event_key="k"
    )
    with pytest.raises(NotImplementedError):
        base.hot_columns()


# ---------------------------------------------------------------------------- hot_columns per class


def test_http_activity_hot_columns() -> None:
    event = HTTPActivity(
        class_uid=4002,
        category_uid=4,
        activity_name="Allowed",
        time=_TS,
        source_type="zscaler",
        line_no=42,
        event_key="GET:Web Search:allowed:2xx",
        actor=Actor(user=OcsfUser(email_addr="u@corp.example")),
        src_endpoint=NetworkEndpoint(ip="10.0.0.1"),
        dst_endpoint=NetworkEndpoint(ip="93.184.216.34"),
        http_request=HttpRequest(
            url={"hostname": "example.com", "path": "/x"},
            http_method="GET",
            user_agent="Mozilla/5.0",
        ),
        http_response=HttpResponse(code=200),
        traffic=Traffic(bytes_out=100, bytes_in=2000),
        disposition="allowed",
    )
    hot = event.hot_columns()
    assert hot == {
        "ts": _TS,
        "source_type": "zscaler",
        "raw_line_no": 42,
        "ocsf_class_uid": 4002,
        "principal": "u@corp.example",
        "src_ip": "10.0.0.1",
        "dst_ip": "93.184.216.34",
        "domain": "example.com",
        "url_path": "/x",
        "action": "allowed",
        "http_method": "GET",
        "status_code": 200,
        "bytes_out": 100,
        "bytes_in": 2000,
        "user_agent": "Mozilla/5.0",
        "event_key": "GET:Web Search:allowed:2xx",
    }


def test_authentication_hot_columns_leave_proxy_fields_null() -> None:
    event = Authentication(
        class_uid=3002,
        category_uid=3,
        time=_TS,
        source_type="okta",
        line_no=1,
        event_key="user.session.start:SUCCESS",
        actor=Actor(user=OcsfUser(email_addr="u@corp.example")),
        src_endpoint=NetworkEndpoint(ip="10.0.0.5"),
        http_request=HttpRequest(user_agent="Mozilla/5.0"),
        status="SUCCESS",
    )
    hot = event.hot_columns()
    assert hot["principal"] == "u@corp.example"
    assert hot["action"] == "SUCCESS"
    assert hot["user_agent"] == "Mozilla/5.0"
    for key in (
        "dst_ip",
        "domain",
        "url_path",
        "http_method",
        "status_code",
        "bytes_out",
        "bytes_in",
    ):
        assert hot[key] is None


def test_api_activity_hot_columns_use_uid_as_principal_and_null_status_code() -> None:
    event = APIActivity(
        class_uid=6003,
        category_uid=6,
        time=_TS,
        source_type="cloudtrail",
        line_no=1,
        event_key="s3.amazonaws.com:GetObject:OK",
        actor=Actor(user=OcsfUser(uid="arn:aws:iam::123:user/svc")),
        src_endpoint=NetworkEndpoint(ip="10.0.0.9"),
        http_request=HttpRequest(user_agent="aws-cli/2.0"),
        status_code="AccessDenied",
    )
    hot = event.hot_columns()
    # principal reads from `uid`, not `email_addr` -- CloudTrail is the ARN-identified source.
    assert hot["principal"] == "arn:aws:iam::123:user/svc"
    # OCSF fidelity keeps the real errorCode string...
    assert event.status_code == "AccessDenied"
    # ...but the hot column is deliberately None (events.status_code is INTEGER; see
    # app/ocsf/api_activity.py's docstring for the full writeup of this docs/02 vs docs/03 gap).
    assert hot["status_code"] is None
    for key in ("dst_ip", "domain", "url_path", "action", "http_method", "bytes_out", "bytes_in"):
        assert hot[key] is None
