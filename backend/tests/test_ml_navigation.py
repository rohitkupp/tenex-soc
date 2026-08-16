"""Unit tests for `app.detection.ml.navigation` -- the navigation chain extractor (docs/04 §L3
"Navigation", migration change 18). Per CLAUDE.md's rule for every detector, each of the five
features gets one fixture that must fire and one that must not.

Fixtures build the plain `pandas.DataFrame` `annotate_navigation_hops` itself consumes (`entity_
col`, `ts`, `registrable_domain`, `url_path`, `referrer`) rather than going through the full
`MLEvent` -> `build_entity_window_features` pipeline -- `test_ml_features.py` already covers that
end-to-end wiring; this file isolates the per-event chain-reconstruction logic itself, matching
how `test_ml_ecod.py` tests `ECODArtifact` directly rather than through `evaluate.py`.

**Domain choice matters here, deliberately.** `entry_domain`/`cross_domain_redirect_chain` compare
*registrable* domains, and the referer side of that comparison runs through the real
`app.enrichment.enrich_domain` (tldextract against the public suffix list) -- reserved test TLDs
like `.example` are not on that list, so `enrich_domain` cannot strip a subdomain off them and a
domain like `portal.corp.example` comes back unchanged, unlike a real `.com`. Every domain below is
a plain, suffix-free `*.com` name for exactly that reason: predictable, verified registrable-
domain behavior rather than an accident of what tldextract does with a non-standard TLD.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pandas as pd

from app.detection.ml.navigation import (
    NAV_CROSS_DOMAIN_REDIRECT_CHAIN,
    NAV_DOWNLOAD_WITHOUT_NAVIGATION,
    NAV_ENTRY_DOMAIN,
    NAV_NAVIGATION_DEPTH,
    NAV_REFERER_LESS_DEEP_PATH,
    annotate_navigation_hops,
)

_T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def _hops(rows: list[dict[str, object]]) -> pd.DataFrame:
    """`rows`: dicts with `principal` (default "alice@corp.com"), `ts`, `domain`, `url_path`,
    `referrer` (default `None`). Builds the frame `annotate_navigation_hops` expects and returns
    its output, indexed identically to the input."""
    defaults = {"principal": "alice@corp.com", "referrer": None}
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records).rename(columns={"domain": "registrable_domain"})
    return annotate_navigation_hops(df, entity_col="principal")


# ---------------------------------------------------------------------------- referer_less_deep_path


def test_referer_less_deep_path_fires_on_a_deep_path_with_no_referer() -> None:
    hops = _hops([{"ts": _T0, "domain": "corp.com", "url_path": "/account/settings/billing"}])
    assert bool(hops.iloc[0][NAV_REFERER_LESS_DEEP_PATH]) is True


def test_referer_less_deep_path_does_not_fire_on_a_shallow_landing_page() -> None:
    # Single-segment path, no referer -- an ordinary landing page (typed URL / bookmark), not the
    # anomalous shape this feature flags.
    hops = _hops([{"ts": _T0, "domain": "corp.com", "url_path": "/login"}])
    assert bool(hops.iloc[0][NAV_REFERER_LESS_DEEP_PATH]) is False


def test_referer_less_deep_path_does_not_fire_when_a_referer_is_present() -> None:
    hops = _hops(
        [
            {
                "ts": _T0,
                "domain": "corp.com",
                "url_path": "/account/settings/billing",
                "referrer": "https://corp.com/account",
            }
        ]
    )
    assert bool(hops.iloc[0][NAV_REFERER_LESS_DEEP_PATH]) is False


# ---------------------------------------------------------------------------- navigation_depth


def test_navigation_depth_increments_across_a_verified_in_session_chain() -> None:
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp.com", "url_path": "/"},
            {
                "ts": _T0 + timedelta(seconds=5),
                "domain": "corp.com",
                "url_path": "/account",
                "referrer": "https://corp.com/",
            },
            {
                "ts": _T0 + timedelta(seconds=10),
                "domain": "corp.com",
                "url_path": "/account/settings",
                "referrer": "https://corp.com/account",
            },
        ]
    )
    assert list(hops[NAV_NAVIGATION_DEPTH]) == [0.0, 1.0, 2.0]


def test_navigation_depth_resets_to_zero_when_the_referer_is_unverified() -> None:
    # A referer whose domain this principal was never observed on in-session (an external link,
    # an email client) does not corroborate a chain -- depth starts over at 0, not "1".
    hops = _hops(
        [
            {
                "ts": _T0,
                "domain": "corp.com",
                "url_path": "/dashboard",
                "referrer": "https://mail-provider.com/inbox",
            }
        ]
    )
    assert hops.iloc[0][NAV_NAVIGATION_DEPTH] == 0.0


# ---------------------------------------------------------------------------- entry_domain


def test_entry_domain_carries_forward_through_a_verified_chain() -> None:
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp.com", "url_path": "/"},
            {
                "ts": _T0 + timedelta(seconds=5),
                "domain": "corp.com",
                "url_path": "/reports",
                "referrer": "https://corp.com/",
            },
        ]
    )
    # Row 0 has no referer, so it is its own entry point; row 1's referer verifiably continues
    # row 0's chain, so it inherits the same entry_domain.
    assert list(hops[NAV_ENTRY_DOMAIN]) == ["corp.com", "corp.com"]


def test_entry_domain_is_the_unverified_referers_domain_when_nothing_else_precedes_it() -> None:
    # No in-session corroboration, but the referer itself is still the best available fact about
    # "how the user reached this destination" -- an external link, not this event's own domain.
    hops = _hops(
        [
            {
                "ts": _T0,
                "domain": "corp.com",
                "url_path": "/landing",
                "referrer": "https://mail-provider.com/newsletter",
            }
        ]
    )
    assert hops.iloc[0][NAV_ENTRY_DOMAIN] == "mail-provider.com"


# ---------------------------------------------------------------------------- cross_domain_redirect_chain


def test_cross_domain_redirect_chain_fires_on_a_verified_domain_handoff() -> None:
    # A typosquat-shaped domain, then a same-session hop to a different domain whose referer
    # points straight back at it -- the "typosquat -> legitimate site handoff" shape docs/04
    # names for this feature.
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp-portal-login.com", "url_path": "/"},
            {
                "ts": _T0 + timedelta(seconds=3),
                "domain": "corp.com",
                "url_path": "/sso/callback",
                "referrer": "https://corp-portal-login.com/",
            },
        ]
    )
    assert bool(hops.iloc[1][NAV_CROSS_DOMAIN_REDIRECT_CHAIN]) is True


def test_cross_domain_redirect_chain_does_not_fire_within_the_same_domain() -> None:
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp.com", "url_path": "/"},
            {
                "ts": _T0 + timedelta(seconds=3),
                "domain": "corp.com",
                "url_path": "/account",
                "referrer": "https://corp.com/",
            },
        ]
    )
    assert bool(hops.iloc[1][NAV_CROSS_DOMAIN_REDIRECT_CHAIN]) is False


def test_cross_domain_redirect_chain_does_not_fire_on_an_unverified_external_referer() -> None:
    # Different domain from the referer, but the referer's domain was never actually observed
    # in-session -- an ordinary "arrived via an external link" event, not a verified handoff.
    hops = _hops(
        [
            {
                "ts": _T0,
                "domain": "corp.com",
                "url_path": "/landing",
                "referrer": "https://news-site.com/article",
            }
        ]
    )
    assert bool(hops.iloc[0][NAV_CROSS_DOMAIN_REDIRECT_CHAIN]) is False


# ---------------------------------------------------------------------------- download_without_navigation


def test_download_without_navigation_fires_on_a_direct_file_fetch() -> None:
    hops = _hops([{"ts": _T0, "domain": "files-cdn.com", "url_path": "/setup/tool.exe"}])
    assert bool(hops.iloc[0][NAV_DOWNLOAD_WITHOUT_NAVIGATION]) is True


def test_download_without_navigation_does_not_fire_after_a_verified_page_load() -> None:
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp.com", "url_path": "/downloads"},
            {
                "ts": _T0 + timedelta(seconds=4),
                "domain": "corp.com",
                "url_path": "/downloads/agent-installer.zip",
                "referrer": "https://corp.com/downloads",
            },
        ]
    )
    assert bool(hops.iloc[1][NAV_DOWNLOAD_WITHOUT_NAVIGATION]) is False


def test_download_without_navigation_does_not_fire_on_an_ordinary_page_path() -> None:
    hops = _hops([{"ts": _T0, "domain": "corp.com", "url_path": "/dashboard"}])
    assert bool(hops.iloc[0][NAV_DOWNLOAD_WITHOUT_NAVIGATION]) is False


# ---------------------------------------------------------------------------- session boundary


def test_a_session_gap_clears_chain_state_so_depth_restarts() -> None:
    hops = _hops(
        [
            {"ts": _T0, "domain": "corp.com", "url_path": "/"},
            {
                "ts": _T0 + timedelta(seconds=5),
                "domain": "corp.com",
                "url_path": "/account",
                "referrer": "https://corp.com/",
            },
            # > 30 minutes later: a fresh session. Even though the referer names a domain this
            # principal visited last session, it is no longer in the (cleared) chain state.
            {
                "ts": _T0 + timedelta(minutes=45),
                "domain": "corp.com",
                "url_path": "/account/settings",
                "referrer": "https://corp.com/account",
            },
        ]
    )
    assert list(hops[NAV_NAVIGATION_DEPTH]) == [0.0, 1.0, 0.0]


def test_annotate_navigation_hops_returns_empty_frame_for_empty_input() -> None:
    empty = pd.DataFrame(columns=["principal", "ts", "registrable_domain", "url_path", "referrer"])
    result = annotate_navigation_hops(empty, entity_col="principal")
    assert result.empty
