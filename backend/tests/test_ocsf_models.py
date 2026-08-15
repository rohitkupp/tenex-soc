"""`app.ocsf` — the typed OCSF event classes (docs/03: HTTP Activity 4002, the only class
registered now that Okta's Authentication (3002) and CloudTrail's API Activity (6003) were
removed along with those sources), independent of any particular parser.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.ocsf import (
    Actor,
    HTTPActivity,
    HttpRequest,
    HttpResponse,
    NetworkEndpoint,
    OCSFEventBase,
    Traffic,
)
from app.ocsf import User as OcsfUser

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def test_class_and_category_uid_match_real_ocsf_numbering() -> None:
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
    assert (http.class_uid, http.category_uid) == (4002, 4)
    assert isinstance(http, OCSFEventBase)


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


# ---------------------------------------------------------------------------- hot_columns


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
