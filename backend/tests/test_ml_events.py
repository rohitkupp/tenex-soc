"""Unit tests for `app.detection.ml.events._department_from_groups` -- the department extraction
this milestone added to feed `features.py`'s department-cohort z-score family (docs/04 §L3 "Peer-
group cohorts"). See that function's own docstring for the `actor.user.groups` ordering
guarantee this relies on (`app/parsers/zscaler.py`'s `[g for g in (location, department) if g is
not None]`, out of this package's ownership but read-only here).
"""

from __future__ import annotations

from app.detection.ml.events import _department_from_groups


def test_department_is_the_last_group_when_both_location_and_department_present() -> None:
    assert _department_from_groups(["US-CA", "engineering"]) == "engineering"


def test_department_is_the_lone_group_when_only_department_present() -> None:
    # `[g for g in (location, department) if g is not None]` with location=None.
    assert _department_from_groups(["engineering"]) == "engineering"


def test_department_is_none_when_no_groups_present() -> None:
    assert _department_from_groups([]) is None
