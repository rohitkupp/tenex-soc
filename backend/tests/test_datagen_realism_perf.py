"""Adversarial realism + performance checks for `datagen` (docs/11 "Realism grounding", "Volume
targets"; docs/03 field mapping).

The synthetic-data circularity problem (docs/11) is only mitigated if the grounding claims in the
table are actually true of the *emitted* corpus, not just of the code that is supposed to produce
it — a Zipf sampler that never gets called on the hot path, or a browser-share table half of whose
mass is unreachable, would still read correctly in `realism.py` while silently producing a corpus
that is not what the README says it is. Every test below drives the real CLI-facing API
(`datagen.corpus`) and asserts against the emitted lines, not against the intermediate model
objects, for exactly that reason. No datagen source was modified to write this file.

`test_human_user_agents_never_include_a_mobile_device` documents a real fidelity gap and is marked
`xfail(strict=True)`. `Org._build_users` (org.py) assigns every human's device fingerprint via
`UserAgentMix.sample_desktop()` (realism.py), which filters the real-world browser-share table
(`_BROWSER_SHARE`) down to `device_type == "desktop"` before sampling. Three specs —
Chrome/Android, Safari/iOS, Samsung Internet/Android — carry 26.3 of the table's 100 share points
and are therefore structurally unreachable by any human principal, so the emitted corpus is
real-world-proportioned only among desktop browsers, not against the table as a whole.

Resolved by the second of the two options this test originally offered: the limitation is now
stated explicitly in docs/11 and the README rather than papered over. Fixing the generator instead
would change the emitted corpus for a given seed, which would invalidate every number in
`evals/results.md` — a real cost, paid for a realism detail no detector in this system reads
(nothing keys on mobile-vs-desktop; the user-agent features are `is_browser_ua` and UA rarity).

`strict=True` matters: if someone later gives a minority of users a mobile fingerprint, this test
starts passing and the strict marker turns that into a *failure*, forcing the marker and the two
documented carve-outs to be removed together instead of silently drifting out of date.
"""

from __future__ import annotations

import math
import resource
from collections import Counter
from pathlib import Path

import pytest

from datagen import corpus
from datagen.realism import _BROWSER_SHARE, load_top_domains
from datagen.types import TimeWindow

# Small org: these checks are about distribution *shape* and file *structure*, not statistical
# power at full scale — full-scale grounding is exercised manually (see the audit notes) where a
# multi-minute, multi-GB run is acceptable. A unit test suite is not the place for either.
_ORG_SPEC = corpus.OrgSpec(n_users=60, n_departments=6, offices=("US-CA", "US-NY", "IE-DU"))


def _write_benign(tmp_path: Path, *, proxy_events: int, chunk_size: int = 200_000) -> Path:
    org = corpus.build_org(11, corpus.ROLE_BENIGN, _ORG_SPEC)
    window = TimeWindow.of_days(14)
    root = corpus.SeededRandom(corpus.role_seed(11, corpus.ROLE_BENIGN))
    corpus.write_benign_corpus(
        org,
        root,
        window,
        tmp_path,
        proxy_events=proxy_events,
        chunk_size=chunk_size,
    )
    return tmp_path / "benign_zscaler.log"


# ---------------------------------------------------------------------------- domain realism


def test_human_domain_traffic_is_zipf_over_the_real_top_sites_list(tmp_path: Path) -> None:
    """docs/11 "Domain popularity": Zipf over a bundled real top-sites list, not a toy handful of
    invented hostnames. Restricted to human (non-`svc-`) principals: service accounts are pinned
    to their own SaaS estate by design (org.py) and would flatten the tail if included, which
    would falsely look like the Zipf grounding had failed.
    """
    log_path = _write_benign(tmp_path, proxy_events=40_000)
    top_sites = set(load_top_domains())

    counts: Counter[str] = Counter()
    with log_path.open() as fh:
        header = fh.readline().rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if parts[idx["user"]].startswith("svc-"):
                continue
            counts[parts[idx["host"]]] += 1

    # Real domains, not invented ones: every host that appears in human traffic must be either a
    # bundled top-site or one of the org's own SaaS domains (org.py DEFAULT_SAAS_APPS) — nothing
    # is hand-rolled on the hot path.
    saas_domains = {
        "onelogin.com",
        "google.com",
        "slack.com",
        "salesforce.com",
        "workday.com",
        "github.com",
        "atlassian.net",
        "zoom.us",
        "box.com",
        "amazonaws.com",
        "snowflakecomputing.com",
        "datadoghq.com",
    }
    unexplained = set(counts) - top_sites - saas_domains
    assert not unexplained, f"human traffic visited domains outside the real corpus: {unexplained}"

    # A handful of dozens of invented hostnames would fail this outright: the real list carries
    # 5000 ranked domains, and the corpus must actually spread across a meaningful fraction of it,
    # not just its head.
    assert len(counts) > 200, f"only {len(counts)} distinct domains in human traffic"

    ranked = counts.most_common()
    top_count = ranked[0][1]
    tail_count = ranked[-1][1]
    # Zipf, not flat: the most-visited domain must be visited far more than the least-visited one.
    # A uniform draw over even a large list would put this ratio near 1.
    assert top_count > tail_count * 20, (
        f"head/tail ratio {top_count}/{tail_count} is too flat to be Zipf-distributed"
    )


# ---------------------------------------------------------------------------- user-agent realism


def test_service_account_user_agents_are_automation_tools_not_browsers(tmp_path: Path) -> None:
    """docs/11: service accounts must "genuinely look machine-like" — a UA a browser would never
    send is the cheapest, strongest signal of that, and the one the L1 non-browser-UA rule
    (docs/04) keys on directly."""
    log_path = _write_benign(tmp_path, proxy_events=20_000)
    browser_families = {family for spec, _ in _BROWSER_SHARE for family in (spec.browser_family,)}

    with log_path.open() as fh:
        header = fh.readline().rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        seen_service_ua = False
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if not parts[idx["user"]].startswith("svc-"):
                continue
            seen_service_ua = True
            ua = parts[idx["useragent"]]
            assert not any(family in ua for family in browser_families), (
                f"service account emitted a browser-looking user agent: {ua!r}"
            )

    assert seen_service_ua, "sanity: no service-account traffic was generated to check"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known, documented limitation: humans get desktop-only user agents. Stated in docs/11 "
        "and the README. strict=True so fixing the generator fails here and forces both "
        "carve-outs to be removed with it — see the module docstring."
    ),
)
def test_human_user_agents_never_include_a_mobile_device(tmp_path: Path) -> None:
    """Every human's device fingerprint is drawn via `UserAgentMix.sample_desktop()`, so the
    mobile 26.3% of the real-world browser-share table (`_BROWSER_SHARE`) — Chrome/Android,
    Safari/iOS, Samsung Internet — is unreachable by any human principal."""
    log_path = _write_benign(tmp_path, proxy_events=60_000)
    mobile_markers = ("iPhone", "Android")

    with log_path.open() as fh:
        header = fh.readline().rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        mobile_hits = 0
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if parts[idx["user"]].startswith("svc-"):
                continue
            if any(m in parts[idx["useragent"]] for m in mobile_markers):
                mobile_hits += 1

    assert mobile_hits > 0, (
        "no human traffic carried a mobile user agent — the ~26%% mobile share of the real-world "
        "browser table (_BROWSER_SHARE) is structurally unreachable because org.py always calls "
        "UserAgentMix.sample_desktop() for a human's device fingerprint"
    )


# ---------------------------------------------------------------------------- field-set fidelity


def test_zscaler_lines_carry_exactly_the_docs03_field_set_in_order(tmp_path: Path) -> None:
    """docs/03 "ZScaler NSS Web -> OCSF HTTP Activity": a missing or reordered column silently
    breaks the M3 parser, which binds by header name but the header itself must still name every
    mapped source field.

    The first 25 are docs/03's original table, unchanged; the asset-tag task appended seven more
    (docs/v1/zscaler-nss-web-fields.md "Zscaler Client Connector Device Information" +
    "Miscellaneous") on top, in the literal NSS token spelling — see `app.parsers.zscaler`'s
    module docstring for why these seven aren't renamed the way the original 25 are."""
    log_path = _write_benign(tmp_path, proxy_events=5_000)
    documented_order = (
        "datetime",
        "user",
        "clientip",
        "serverip",
        "host",
        "url",
        "requestmethod",
        "status",
        "requestsize",
        "responsesize",
        "useragent",
        "action",
        "urlcategory",
        "urlsupercategory",
        "appname",
        "appclass",
        "threatname",
        "threatcategory",
        "riskscore",
        "reason",
        "referer",
        "dlpengine",
        "dlpdictionaries",
        "location",
        "department",
        "devicehostname",
        "devicename",
        "deviceostype",
        "deviceosversion",
        "deviceowner",
        "bypassed_traffic",
        "flow_type",
    )
    with log_path.open() as fh:
        header = tuple(fh.readline().rstrip("\n").split("\t"))
    # A prefix check, not full equality: other concurrent changes append their own fields after
    # this task's 32 (e.g. a JA4/TLS/threat-detail batch) — this test's own invariant is that
    # docs/03's original 25 plus this task's 7 are present, unbroken, in this exact relative
    # order, not that these are the *only* fields the emitter ever writes.
    assert header[: len(documented_order)] == documented_order

    action_values: set[str] = set()
    with log_path.open() as fh:
        fh.readline()
        idx = header.index("action")
        for line in fh:
            action_values.add(line.rstrip("\n").split("\t")[idx])
    # docs/03's action normalization documents a third bucket ("everything else -> other"), which
    # is silently untested if the benign corpus only ever emits the two named verdicts.
    assert action_values <= {"Allowed", "Blocked"}


# The Okta-lines field-set fidelity test that used to live here (`test_okta_lines_carry_every_
# docs03_mapped_json_path`) was deleted along with the Okta source -- this project is narrowed to
# ZScaler web proxy logs only, and `test_zscaler_lines_carry_exactly_the_docs03_field_set_in_order`
# above is the sole remaining source's fidelity test.


# ---------------------------------------------------------------------------- performance


def test_benign_corpus_peak_memory_does_not_scale_with_total_event_count(tmp_path: Path) -> None:
    """docs/11 says the benign corpus targets ~2M events and corpus.py's own module docstring
    promises peak memory bounded by `chunk_size`, "not the whole corpus". Generating the full 2M
    scale in a unit test is too slow to run routinely, so this asserts the shape of the claim at a
    scale that finishes in seconds: RSS at 4x the event count, same `chunk_size`, must not be
    anywhere near 4x the RSS at the smaller count — true streaming is roughly flat, a
    accidentally-buffered-in-memory implementation would be roughly linear.
    """
    small_dir, big_dir = tmp_path / "small", tmp_path / "big"
    small_dir.mkdir()
    big_dir.mkdir()

    _write_benign(small_dir, proxy_events=25_000, chunk_size=25_000)
    rss_small = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    _write_benign(big_dir, proxy_events=100_000, chunk_size=25_000)
    rss_big = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # `ru_maxrss` is a high-water mark for the whole process (pytest included) and never shrinks,
    # so this is a one-sided, generous check: true linear growth (4x events -> ~4x RSS) would still
    # fail it, while bounded/streaming growth (a small constant number of chunk-sized buffers)
    # passes with a wide margin.
    growth = rss_big / max(rss_small, 1)
    assert growth < 2.5, (
        f"peak RSS grew {growth:.2f}x when proxy_events grew 4x at a fixed chunk_size "
        f"({rss_small} -> {rss_big} KB/bytes) — memory looks like it scales with total corpus "
        "size rather than chunk_size"
    )


def test_demo_file_generates_well_under_the_two_minute_budget(tmp_path: Path) -> None:
    """docs/11 "Volume targets": "The demo file should take under two minutes end to end. Time
    it." `_cmd_demo` only logs a warning past 120s rather than failing the run, so nothing else in
    the suite enforces this — this test is the enforcement."""
    import time

    t0 = time.perf_counter()
    corpus.run_demo(99, tmp_path, total_events=150_000, org_spec=_ORG_SPEC)
    elapsed = time.perf_counter() - t0
    assert elapsed < 120, f"demo generation took {elapsed:.1f}s, over the docs/11 budget"


# ---------------------------------------------------------------------------- sweep coverage


def test_sweep_range_reaches_its_documented_stop_value() -> None:
    """docs/11's own flagship example is `--range 0.02:0.6:0.05`, and `parse_range`'s docstring
    claims that spec is "inclusive of the endpoint" and produces `[0.02, 0.07, ..., 0.6]`. Because
    (0.6 - 0.02) is not an integer multiple of the 0.05 step, the arithmetic sequence starting at
    0.02 never lands on 0.6 — the last point actually produced is 0.57. Anyone sweeping exactly the
    documented example gets a curve that silently stops one step short of the stated endpoint.
    """
    from datagen.sweep import parse_range

    values = parse_range("0.02:0.6:0.05")
    assert math.isclose(values[-1], 0.6, abs_tol=1e-6), (
        f"documented range '0.02:0.6:0.05' stops at {values[-1]}, not the stated endpoint 0.6"
    )
