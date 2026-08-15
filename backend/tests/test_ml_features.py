"""Unit tests for `app.detection.ml.features` — the ~50-feature entity-window extractor
(docs/04 §L3). Fixtures build `MLEvent` directly (no real log parsing, no enrichment lookups
needed — every enrichment-derived field on `MLEvent` is already a plain bool/str the test sets
itself), matching the rest of this codebase's convention of pure, DB-free detector unit tests
(see `tests/test_signal_burst.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from app.detection.ml.events import MLEvent
from app.detection.ml.features import (
    ENTITY_WINDOW_MODEL_FEATURES,
    build_entity_window_features,
    estimate_work_hours,
    to_feature_matrix,
)

_T0 = datetime(2026, 1, 5, tzinfo=UTC)  # a Monday


def _event(
    *,
    line_no: int = 1,
    ts: datetime = _T0,
    kind: str = "proxy",
    principal: str | None = "alice@corp.example",
    src_ip: str | None = "10.0.0.1",
    domain: str | None = "example.com",
    registrable_domain: str | None = "example.com",
    url_path: str | None = "/",
    http_method: str | None = "GET",
    status_code: int | None = 200,
    bytes_in: int | None = 1000,
    bytes_out: int | None = 500,
    user_agent: str | None = "Mozilla/5.0",
    action: str | None = "allowed",
    activity_name: str | None = None,
    event_key: str | None = "k",
    country: str | None = "US",
    asn: int | None = 12345,
    is_hosting: bool = False,
    is_automation_ua: bool = False,
    is_browser_ua: bool = True,
    domain_newly_registered: bool = False,
    domain_high_risk_tld: bool = False,
    domain_is_top_site: bool = True,
    threat_present: bool = False,
    is_direct_ip: bool = False,
) -> MLEvent:
    return MLEvent(
        line_no=line_no,
        ts=ts,
        source_type="zscaler" if kind == "proxy" else "okta",
        kind=kind,  # type: ignore[arg-type]
        principal=principal,
        src_ip=src_ip,
        domain=domain,
        registrable_domain=registrable_domain,
        url_path=url_path,
        http_method=http_method,
        status_code=status_code,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        user_agent=user_agent,
        action=action,
        activity_name=activity_name,
        event_key=event_key,
        country=country,
        asn=asn,
        is_hosting=is_hosting,
        is_automation_ua=is_automation_ua,
        is_browser_ua=is_browser_ua,
        domain_newly_registered=domain_newly_registered,
        domain_high_risk_tld=domain_high_risk_tld,
        domain_is_top_site=domain_is_top_site,
        threat_present=threat_present,
        is_direct_ip=is_direct_ip,
    )


# ---------------------------------------------------------------------------- feature vector shape


def test_feature_vector_has_approximately_fifty_unique_features() -> None:
    assert 45 <= len(ENTITY_WINDOW_MODEL_FEATURES) <= 55
    assert len(ENTITY_WINDOW_MODEL_FEATURES) == len(set(ENTITY_WINDOW_MODEL_FEATURES))


def test_feature_vector_includes_every_docs04_named_feature() -> None:
    # docs/04 §L3's feature list, verbatim names -- a regression test against silently dropping
    # one of the doc-specified features while adding the "~50" padding features.
    named = {
        "n_events",
        "n_events_z_vs_own_history",
        "n_events_z_vs_cohort",
        "off_hours_ratio",
        "weekend_ratio",
        "iat_mean",
        "iat_cv",
        "hour_entropy",
        "burstiness",
        "n_unique_domains",
        "n_rare_domains",
        "rare_domain_ratio",
        "n_new_domains_for_user",
        "mean_domain_entropy",
        "max_domain_entropy",
        "n_newly_registered_domains",
        "bytes_out_sum",
        "bytes_in_sum",
        "out_in_ratio",
        "bytes_out_max",
        "bytes_out_z_vs_own",
        "n_large_uploads",
        "post_ratio",
        "blocked_ratio",
        "error_ratio",
        "n_unique_status_codes",
        "direct_ip_ratio",
        "n_unique_user_agents",
        "automation_ua_ratio",
        "n_unique_asns",
        "n_unique_countries",
        "hosting_provider_ratio",
        "n_auth_failures",
        "n_auth_successes",
        "auth_failure_ratio",
        "n_mfa_challenges",
        "n_distinct_geos",
        "privilege_events",
    }
    assert named <= set(ENTITY_WINDOW_MODEL_FEATURES)


# ---------------------------------------------------------------------------- estimate_work_hours


def test_estimate_work_hours_recovers_a_clear_nine_to_five_pattern() -> None:
    # Exactly nine distinct populated hours (9..17 inclusive), matching `_WORK_HOURS_SPAN_H` --
    # anything narrower ties between two equally-good windows (verified directly), which would
    # make this a test of the tie-break rule rather than of the recovered pattern.
    timestamps = []
    for day in range(10):
        base = _T0 + timedelta(days=day)
        for hour in range(9, 18):
            timestamps.append(base.replace(hour=hour))
    estimated = estimate_work_hours(timestamps)
    assert estimated.start_h == 9.0
    assert estimated.end_h - estimated.start_h == 9.0  # _WORK_HOURS_SPAN_H


def test_estimate_work_hours_falls_back_with_too_little_history() -> None:
    estimated = estimate_work_hours([_T0, _T0 + timedelta(hours=1)])
    assert estimated.start_h == 9.0
    assert estimated.end_h == 17.5


# ---------------------------------------------------------------------------- basic entity-window counts


def test_build_entity_window_features_counts_events_correctly() -> None:
    events = [
        _event(line_no=1, ts=_T0.replace(hour=10, minute=0)),
        _event(line_no=2, ts=_T0.replace(hour=10, minute=15)),
        _event(line_no=3, ts=_T0.replace(hour=10, minute=30)),
        _event(line_no=4, ts=_T0.replace(hour=14, minute=0)),  # different hour bucket
    ]
    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"]
    assert set(user_rows["n_events"]) == {3.0, 1.0}
    row_10h = user_rows[user_rows["n_events"] == 3.0].iloc[0]
    assert row_10h["line_numbers"] == [1, 2, 3]


def test_build_entity_window_features_empty_input() -> None:
    df = build_entity_window_features([])
    assert df.empty
    assert list(df.columns)[:5] == [
        "entity_type",
        "entity_value",
        "window_start",
        "window_end",
        "line_numbers",
    ]


def test_both_entity_dimensions_are_scored() -> None:
    events = [_event(principal="alice@corp.example", src_ip="10.0.0.1")]
    df = build_entity_window_features(events)
    assert set(df["entity_type"]) == {"user", "src_ip"}
    assert set(df["entity_value"]) == {"alice@corp.example", "10.0.0.1"}


# ---------------------------------------------------------------------------- temporal


def test_off_hours_ratio_is_zero_for_events_inside_estimated_business_hours() -> None:
    # A long, clean 9-17 pattern so estimate_work_hours locks onto it, then one more event
    # squarely inside that window -- off_hours_ratio for that window must read 0.0.
    events = [
        _event(line_no=i, ts=_T0 + timedelta(days=d, hours=h - 9))
        for i, (d, h) in enumerate(((d, h) for d in range(10) for h in (9, 10, 11, 12)), start=1)
    ]
    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"]
    assert (user_rows["off_hours_ratio"] == 0.0).all()


def test_night_ratio_flags_deep_night_activity() -> None:
    events = [
        _event(line_no=1, ts=_T0.replace(hour=3, minute=0)),
        _event(line_no=2, ts=_T0.replace(hour=3, minute=10)),
    ]
    df = build_entity_window_features(events)
    row = df[df["entity_type"] == "user"].iloc[0]
    assert row["night_ratio"] == 1.0


# ---------------------------------------------------------------------------- volume z-scores: must fire / must not fire


def test_n_events_z_vs_own_history_fires_on_a_genuine_spike() -> None:
    # Five quiet hours of 2 events each, one hour with 40 -- a textbook robust-z outlier, the
    # same "must fire" shape as tests/test_signal_burst.py's own extreme-spike fixture.
    events = []
    line_no = 1
    for hour in range(5):
        for _ in range(2):
            events.append(_event(line_no=line_no, ts=_T0 + timedelta(hours=hour)))
            line_no += 1
    for _ in range(40):
        events.append(_event(line_no=line_no, ts=_T0 + timedelta(hours=5)))
        line_no += 1

    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"].sort_values("window_start")
    spike_row = user_rows[user_rows["n_events"] == 40.0].iloc[0]
    quiet_row = user_rows[user_rows["n_events"] == 2.0].iloc[0]
    assert spike_row["n_events_z_vs_own_history"] > quiet_row["n_events_z_vs_own_history"]
    assert spike_row["n_events_z_vs_own_history"] > 3.5  # docs/04's own burst threshold


def test_n_events_z_vs_own_history_does_not_fire_on_mild_natural_variation() -> None:
    counts = [3, 4, 5, 4, 3, 5, 4, 6, 5, 4]
    events = []
    line_no = 1
    for hour, n in enumerate(counts):
        for _ in range(n):
            events.append(_event(line_no=line_no, ts=_T0 + timedelta(hours=hour)))
            line_no += 1
    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"]
    assert (user_rows["n_events_z_vs_own_history"].abs() <= 3.5).all()


def test_n_events_z_vs_cohort_fires_when_one_entity_spikes_relative_to_peers() -> None:
    events = []
    line_no = 1
    # Five quiet peers, 2 events each, same hour.
    for i in range(5):
        for _ in range(2):
            events.append(_event(line_no=line_no, principal=f"user{i}@corp.example"))
            line_no += 1
    # One loud entity, same hour, way more events.
    for _ in range(40):
        events.append(_event(line_no=line_no, principal="loud@corp.example"))
        line_no += 1

    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"]
    loud_row = user_rows[user_rows["entity_value"] == "loud@corp.example"].iloc[0]
    quiet_row = user_rows[user_rows["entity_value"] == "user0@corp.example"].iloc[0]
    assert loud_row["n_events_z_vs_cohort"] > quiet_row["n_events_z_vs_cohort"]
    assert loud_row["n_events_z_vs_cohort"] > 3.5


# ---------------------------------------------------------------------------- domains


def test_high_risk_tld_ratio_and_non_top_site_ratio() -> None:
    events = [
        _event(line_no=1, domain_high_risk_tld=True, domain_is_top_site=False),
        _event(line_no=2, domain_high_risk_tld=False, domain_is_top_site=True),
    ]
    df = build_entity_window_features(events)
    row = df[df["entity_type"] == "user"].iloc[0]
    assert row["high_risk_tld_ratio"] == 0.5
    assert row["non_top_site_ratio"] == 0.5


def test_n_new_domains_for_user_only_counts_first_seen_windows() -> None:
    events = [
        _event(line_no=1, ts=_T0, registrable_domain="a.com"),
        _event(line_no=2, ts=_T0 + timedelta(hours=1), registrable_domain="a.com"),  # repeat
        _event(line_no=3, ts=_T0 + timedelta(hours=1), registrable_domain="b.com"),  # new
    ]
    df = build_entity_window_features(events)
    user_rows = df[df["entity_type"] == "user"].sort_values("window_start")
    assert user_rows.iloc[0]["n_new_domains_for_user"] == 1.0  # a.com, first hour
    assert user_rows.iloc[1]["n_new_domains_for_user"] == 1.0  # b.com only, not a.com again


# ---------------------------------------------------------------------------- transfer


def test_out_in_ratio_and_large_uploads() -> None:
    events = [
        _event(line_no=1, bytes_out=2_000_000, bytes_in=1000),
        _event(line_no=2, bytes_out=100, bytes_in=100),
    ]
    df = build_entity_window_features(events)
    row = df[df["entity_type"] == "user"].iloc[0]
    assert row["bytes_out_sum"] == 2_000_100
    assert row["n_large_uploads"] == 1.0  # LARGE_UPLOAD_BYTES == 1_000_000
    assert row["out_in_ratio"] == pytest.approx(2_000_100 / 1100)


# ---------------------------------------------------------------------------- identity


def test_mfa_and_auth_failure_features() -> None:
    events = [
        _event(line_no=1, kind="identity", principal="bob@corp.example", action="FAILURE"),
        _event(line_no=2, kind="identity", principal="bob@corp.example", action="SUCCESS"),
        _event(
            line_no=3,
            kind="identity",
            principal="bob@corp.example",
            action="FAILURE",
            activity_name="user.authentication.auth_via_mfa",
        ),
        _event(
            line_no=4,
            kind="identity",
            principal="bob@corp.example",
            action="SUCCESS",
            activity_name="user.account.privilege.grant",
        ),
    ]
    df = build_entity_window_features(events)
    row = df[(df["entity_type"] == "user") & (df["entity_value"] == "bob@corp.example")].iloc[0]
    assert row["n_auth_failures"] == 2.0
    assert row["n_auth_successes"] == 2.0
    assert row["auth_failure_ratio"] == 0.5
    assert row["n_mfa_challenges"] == 1.0
    assert row["mfa_failure_ratio"] == 1.0
    assert row["privilege_events"] == 1.0


def test_identity_features_are_zero_on_a_pure_proxy_window() -> None:
    events = [_event(line_no=1, kind="proxy")]
    df = build_entity_window_features(events)
    row = df[df["entity_type"] == "user"].iloc[0]
    assert row["n_auth_failures"] == 0.0
    assert row["n_mfa_challenges"] == 0.0
    assert row["privilege_events"] == 0.0


# ---------------------------------------------------------------------------- to_feature_matrix


def test_to_feature_matrix_substitutes_infinite_z_scores_with_a_finite_sentinel() -> None:
    # A single-window entity: robust_z's own MAD==0 policy makes every "own history" z either
    # 0.0 (x == median, trivially true with one point) -- construct a second window with the
    # same entity but a different n_events to force MAD == 0 -> inf on the differing value.
    events = [
        _event(line_no=1, ts=_T0, principal="alice@corp.example"),
        _event(line_no=2, ts=_T0 + timedelta(hours=1), principal="alice@corp.example"),
        _event(line_no=3, ts=_T0 + timedelta(hours=1), principal="alice@corp.example"),
    ]
    df = build_entity_window_features(events)
    matrix = to_feature_matrix(df)
    assert np.isfinite(matrix).all()


def test_to_feature_matrix_never_clips_ordinary_large_finite_values() -> None:
    # Regression test for a real bug: an earlier version clipped every column (not just the
    # inf-valued z-score ones) to +/-Z_SCORE_CLIP, silently flattening a multi-megabyte
    # `bytes_out_sum` down to 100 and destroying the volumetric signal every model needs most.
    row = dict.fromkeys(ENTITY_WINDOW_MODEL_FEATURES, 0.0)
    row["bytes_out_sum"] = 5_000_000.0  # comfortably above Z_SCORE_CLIP
    df = pd.DataFrame([row])
    matrix = to_feature_matrix(df)
    idx = ENTITY_WINDOW_MODEL_FEATURES.index("bytes_out_sum")
    assert matrix[0, idx] == 5_000_000.0
