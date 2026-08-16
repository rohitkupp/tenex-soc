"""Unit tests for `app.detection.ml.events._department_from_groups` -- the department extraction
this milestone added to feed `features.py`'s department-cohort z-score family (docs/04 §L3 "Peer-
group cohorts"). See that function's own docstring for the `actor.user.groups` ordering
guarantee this relies on (`app/parsers/zscaler.py`'s `[g for g in (location, department) if g is
not None]`, out of this package's ownership but read-only here).

Also covers `_from_http_activity`'s `referrer` mapping -- migration change 18's navigation chain
extractor (`app.detection.ml.navigation`) needs `MLEvent.referrer`, sourced the same "no hot-
column home, read straight off the parsed OCSF object" way `department` already is (see
`events.py`'s module docstring, "Referer field availability" in `navigation.py`'s).
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.detection.ml.events import _department_from_groups, _from_http_activity
from app.ocsf import HTTPActivity
from app.ocsf.common import HttpRequest

_TS = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def test_department_is_the_last_group_when_both_location_and_department_present() -> None:
    assert _department_from_groups(["US-CA", "engineering"]) == "engineering"


def test_department_is_the_lone_group_when_only_department_present() -> None:
    # `[g for g in (location, department) if g is not None]` with location=None.
    assert _department_from_groups(["engineering"]) == "engineering"


def test_department_is_none_when_no_groups_present() -> None:
    assert _department_from_groups([]) is None


def test_referrer_is_read_from_http_request() -> None:
    event = HTTPActivity(
        class_uid=4002,
        category_uid=4,
        time=_TS,
        source_type="zscaler",
        line_no=1,
        event_key="k",
        http_request=HttpRequest(referrer="https://mail.corp.example/inbox"),
    )
    assert _from_http_activity(event).referrer == "https://mail.corp.example/inbox"


def test_referrer_is_none_when_http_request_is_absent() -> None:
    event = HTTPActivity(
        class_uid=4002, category_uid=4, time=_TS, source_type="zscaler", line_no=1, event_key="k"
    )
    assert _from_http_activity(event).referrer is None
