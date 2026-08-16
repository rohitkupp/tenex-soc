"""Navigation chain extractor (docs/04 §L3 "Navigation"; migration change 18,
`docs/v2_migration/MIGRATION-01-evidence-first.md`).

## Why this exists, and why it is not a sequence model

Change 18 rejected sequence modelling for this corpus outright -- proxy click-paths are unstable
as *grammar* (browser parallelism fires 20-80 subresource requests per page load in
nondeterministic order; multi-tab concurrency interleaves unrelated concurrent tasks; there is no
grammar to learn, and no scenario in this corpus has an ordering signal no other detector already
catches) -- but it commissioned this module as "the part of the sequence idea that pays for
itself": the HTTP `Referer` header is not an inferred transition probability a model has to learn,
it is the browser's own ground-truth statement of which page a request followed. Reconstructing it
needs bookkeeping, not a grammar.

## Why `app/detection/ml/`, not `app/detection/signal/`

These five features read like L2 in spirit ("Not ML. The right tool for the job" -- docs/04's own
framing for that layer, and this module fits it: no fitted parameters, no training corpus, pure
deterministic bookkeeping over a chronological event stream). But L2's DB-backed row type,
`EventRow` (`app.detection.signal.events_dao`), is deliberately five/six columns wide and does not
carry `referrer` -- it is not a docs/02 hot column on `events` (see `app/models/event.py`: only
`principal`/`src_ip`/`domain`/`url_path`/`action`/... are indexed columns). `referrer` exists, end
to end, only inside `http_request.referrer` on the parsed OCSF object and, nested rather than
flattened, inside the persisted `events.ocsf` JSONB blob -- the same "not a hot column, lives in
the JSONB" situation `url_path.py`'s own docstring already documents for ZScaler's `urlcategory`.

`app/detection/ml/events.py` is the one place in this detection package that already reads the
*parsed OCSF object* directly, bypassing the DB/hot-column path entirely (see that module's own
docstring on why L3 does this at all) -- which is exactly what a referrer chain needs.
`MLEvent.referrer` (added alongside this module) is sourced the same way `MLEvent.department`
already is: a real field with no hot-column home, read once at parse time. Building this as an L2
detector instead would require either a docs/02 migration to add a hot column (out of this
package's ownership -- see `events.py`'s own stated boundary) or a per-row JSONB path extraction
with no supporting index. Extending `app/detection/ml/**`, which already parses the field, is the
only path that does not invent a new persistence column this milestone does not own.

## Referer field availability -- stated plainly, per the task brief's own request

`referrer` is parsed end to end from the raw ZScaler `referer` field through to
`HttpRequest.referrer` on every `HTTPActivity` (`app/parsers/zscaler.py`, `app/ocsf/common.py`),
and it does survive into the persisted `events.ocsf` JSONB via `OCSFEventBase.model_dump()`
(`app/pipeline/stages/parse.py`) -- but nested under `ocsf->'http_request'->>'referrer'`, not a
top-level JSONB key and not a docs/02 hot column on the `events` table itself. It is *not*
currently read into `EventRow` (the L2 signal package's DB-query surface) or, before this module,
`MLEvent`. This module reads it the same way `events.py` already reads `department`: off the
parsed object, before hot-column projection -- which is why it lives here rather than in
`app.detection.signal`.

## Entity scope -- `principal` only, never `src_ip`

Reconstructed per `principal`, never per `src_ip`. A `src_ip` can be a shared office egress or
NAT'd across many concurrent principals -- `app.detection.ml.features`'s own module docstring
makes the identical point about why the department-cohort feature family falls back for this
dimension. Interleaving several people's independent referer chains into one "sequence" under a
shared IP is exactly the multi-tab/multi-user disorder change 18's own rejection is about, except
here it is avoidable outright by simply never attempting reconstruction for that dimension, rather
than by modelling the disorder away. `features.py` zero-fills the whole navigation family for
`entity_type == "src_ip"`, the same documented scope cut `IDENTITY_FEATURES` and the department-
cohort fallback already make elsewhere in that module.

## The five features (docs/04, migration table, verbatim names)

| Feature | Meaning |
|---|---|
| `referer_less_deep_path` | arrived at a deep path (>= `_DEEP_PATH_MIN_SEGMENTS` segments) with no referer at all |
| `navigation_depth` | verified hops from this chain's entry point, by referer linkage |
| `entry_domain` | the registrable domain this chain is attributed to having started from |
| `cross_domain_redirect_chain` | this hop's referer domain (verified, in-chain) differs from the domain it landed on |
| `download_without_navigation` | a downloadable-extension path fetched at `navigation_depth == 0` -- no preceding page load in this chain |

One row per proxy event (not per entity-window yet) -- `features.py`'s "Navigation" aggregation
block folds these into the `(entity, hour)` grain the rest of L3 uses: ratio/mean for the four
boolean/numeric features, distinct-count for `entry_domain`.

## Chain reconstruction, precisely

Per principal, events in timestamp order. A **session** is a run of events with no gap longer than
`_CHAIN_IDLE_GAP_SECONDS` (1800s -- the same 30-minute idle-gap sessionisation docs/04 §L3 already
names for the *session* feature family: "per principal, 30-minute idle gap," that module's own
docstring under "Session (derived, not sequence-modeled -- see §L4)"). A session gap clears all
in-progress chain state for that principal -- the same fresh start the session family gets.

Within a session, `chains: dict[registrable_domain, (depth, entry_domain)]` tracks every domain
this principal has been verifiably observed on so far this session. For each event:

* No referer, or a referer whose registrable domain is not yet in `chains` (an external link, a
  bookmark, an email client -- not corroborated by anything this principal did in-session): this
  event starts a **new** chain. `navigation_depth = 0`; `entry_domain` is the referer's own
  registrable domain if there was one (the best available fact about "how the user reached this
  destination," even though unverified) else this event's own domain (nothing else to attribute it
  to).
* A referer whose registrable domain *is* in `chains`: this event **continues** that chain.
  `navigation_depth` is the referenced hop's depth plus one; `entry_domain` carries forward from
  it. `cross_domain_redirect_chain` is true exactly when this event's own domain differs from the
  referer's -- a *verified* domain handoff inside an active chain, not merely "this event happens
  to carry an external referer" (see "Entity scope" above for why an unverified one does not
  count at all).

Every event's own domain is then recorded into `chains` (its own depth, its own entry_domain) so
later hops in the same session can reference it, whether or not this event itself continued a
chain.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final
from urllib.parse import urlsplit

import pandas as pd

from app.enrichment import enrich_domain

__all__ = [
    "NAVIGATION_HOP_COLUMNS",
    "NAV_CROSS_DOMAIN_REDIRECT_CHAIN",
    "NAV_DOWNLOAD_WITHOUT_NAVIGATION",
    "NAV_ENTRY_DOMAIN",
    "NAV_NAVIGATION_DEPTH",
    "NAV_REFERER_LESS_DEEP_PATH",
    "annotate_navigation_hops",
]

# Column names this module adds -- `features.py` reads these back off the frame
# `annotate_navigation_hops` returns, and aggregates them into its own, differently-named,
# entity-window-grain feature columns (see that module's "Navigation" section).
NAV_REFERER_LESS_DEEP_PATH: Final[str] = "referer_less_deep_path"
NAV_NAVIGATION_DEPTH: Final[str] = "navigation_depth"
NAV_ENTRY_DOMAIN: Final[str] = "entry_domain"
NAV_CROSS_DOMAIN_REDIRECT_CHAIN: Final[str] = "cross_domain_redirect_chain"
NAV_DOWNLOAD_WITHOUT_NAVIGATION: Final[str] = "download_without_navigation"

NAVIGATION_HOP_COLUMNS: Final[tuple[str, ...]] = (
    NAV_REFERER_LESS_DEEP_PATH,
    NAV_NAVIGATION_DEPTH,
    NAV_ENTRY_DOMAIN,
    NAV_CROSS_DOMAIN_REDIRECT_CHAIN,
    NAV_DOWNLOAD_WITHOUT_NAVIGATION,
)

# "Deep" means "more than one path segment." A single-segment path (`/login`, `/dashboard`) is an
# ordinary landing page a user legitimately reaches with no referer at all (typed URL, bookmark, a
# fresh tab); two or more segments (`/account/settings/billing`) is the shape of a page normally
# reached by clicking through from somewhere shallower, so seeing it with *no* referer at all is
# the anomalous case this feature exists to flag.
_DEEP_PATH_MIN_SEGMENTS: Final[int] = 2

# Same 30-minute idle-gap sessionisation docs/04 §L3 already names for the *session* feature
# family -- reused here rather than inventing a second, undocumented boundary.
_CHAIN_IDLE_GAP_SECONDS: Final[float] = 1800.0

# Mirrors `app.detection.sigma.fields._DOWNLOAD_EXTENSION_RE`'s pattern list -- re-derived
# independently rather than imported, the same cross-package boundary
# `app.detection.ml.features.RARE_DOMAIN_MAX_EVENT_COUNT` already states a reason for (this
# package does not import `app.detection.sigma`/`app.detection.signal`, concurrently-developed
# siblings -- see `events.py`'s own module docstring).
_DOWNLOAD_EXTENSION_RE: Final[re.Pattern[str]] = re.compile(
    r"\.(exe|msi|dll|bat|cmd|ps1|vbs|scr|jar|apk|zip|rar|7z|tar\.gz|tgz|tar|gz|iso)(\?|$)",
    re.IGNORECASE,
)


def _path_segment_count(url_path: str | None) -> int:
    if not url_path:
        return 0
    return len([seg for seg in url_path.split("?", 1)[0].split("/") if seg])


def _is_download_path(url_path: str | None) -> bool:
    if not url_path:
        return False
    return _DOWNLOAD_EXTENSION_RE.search(url_path) is not None


def _referer_registrable_domain(referrer: str | None) -> str | None:
    """The referer URL's own registrable domain, via the same `enrich_domain` normalization every
    other "domain" in this package already goes through (`events.py`'s own registrable-domain
    fallback-to-hostname precedent) -- so a chain comparison here and a domain comparison anywhere
    else in `features.py` never silently disagree about what "the same domain" means. `None` for
    an absent, unparseable, or netloc-less referer (a relative path, a malformed value) -- not
    every value attacker-controlled log content puts in this field is a real absolute URL, and a
    referer this module cannot resolve a host from carries no chain-linkage information.
    """
    if not isinstance(referrer, str) or not referrer:
        return None
    hostname = urlsplit(referrer).hostname
    if not hostname:
        return None
    info = enrich_domain(hostname)
    return info.registrable_domain if info else hostname


def _as_str_or_none(value: object) -> str | None:
    """Normalizes a pandas cell to `str | None`. A `DataFrame` built from a column that mixes
    Python `None` with strings (exactly what `registrable_domain`/`url_path`/`referrer` do on any
    file where some but not all proxy events carry a value -- the ordinary case) silently turns
    the `None` entries into float `nan`, not `None` (verified directly -- both the list-of-dicts
    and dict-of-lists `pd.DataFrame` constructors do this). `is None`/truthiness checks against a
    `nan` do not behave like checks against `None` (`nan is not None`, and `bool(nan)` is `True`),
    so every value this module reads off a frame goes through this first.
    """
    return value if isinstance(value, str) else None


def _hops_for_principal(
    rows: Sequence[tuple[object, pd.Timestamp, object, object, object]],
) -> list[dict[str, object]]:
    """`rows`, already time-sorted for one principal: `(index, ts, registrable_domain, url_path,
    referrer)`. Returns one dict per row, same order, carrying `_index` plus this module's five
    columns -- see module docstring, "Chain reconstruction, precisely."
    """
    chains: dict[str, tuple[int, str]] = {}
    last_ts: pd.Timestamp | None = None
    hops: list[dict[str, object]] = []

    for idx, ts, raw_domain, raw_url_path, raw_referrer in rows:
        domain = _as_str_or_none(raw_domain)
        url_path = _as_str_or_none(raw_url_path)
        referrer = _as_str_or_none(raw_referrer)

        if last_ts is not None:
            gap = (ts - last_ts).total_seconds()
            if gap > _CHAIN_IDLE_GAP_SECONDS:
                chains = {}
        last_ts = ts

        ref_domain = _referer_registrable_domain(referrer)
        is_deep = _path_segment_count(url_path) >= _DEEP_PATH_MIN_SEGMENTS
        referer_less_deep_path = is_deep and referrer is None

        if ref_domain is not None and ref_domain in chains:
            prev_depth, entry_domain = chains[ref_domain]
            navigation_depth = prev_depth + 1
            cross_domain_redirect_chain = domain is not None and domain != ref_domain
        else:
            navigation_depth = 0
            # "" rather than `None` when even this event's own domain is missing (a degenerate,
            # non-proxy-shaped row): keeps this column homogeneously `str`, so `.nunique()` in
            # `features.py` counts it as one distinct (if uninformative) entry rather than being
            # silently dropped the way a `NaN` would be.
            entry_domain = ref_domain if ref_domain is not None else (domain or "")
            cross_domain_redirect_chain = False

        download_without_navigation = navigation_depth == 0 and _is_download_path(url_path)

        if domain is not None:
            chains[domain] = (navigation_depth, entry_domain)

        hops.append(
            {
                "_index": idx,
                NAV_REFERER_LESS_DEEP_PATH: referer_less_deep_path,
                NAV_NAVIGATION_DEPTH: float(navigation_depth),
                NAV_ENTRY_DOMAIN: entry_domain,
                NAV_CROSS_DOMAIN_REDIRECT_CHAIN: cross_domain_redirect_chain,
                NAV_DOWNLOAD_WITHOUT_NAVIGATION: download_without_navigation,
            }
        )
    return hops


def annotate_navigation_hops(proxy: pd.DataFrame, *, entity_col: str) -> pd.DataFrame:
    """`proxy` is a proxy-only event frame carrying `entity_col`, `ts`, `registrable_domain`,
    `url_path`, and `referrer` -- `features.py`'s own `proxy` variable, for `entity_col=
    "principal"` only (see module docstring, "Entity scope"). Returns a same-index frame carrying
    `NAVIGATION_HOP_COLUMNS`, ready to `.join` straight back onto `proxy`.

    Grouped by `entity_col` and processed one principal at a time (`_hops_for_principal`) -- each
    principal's chain state is independent, matching every other per-principal computation in this
    package (`estimate_work_hours`, `_own_history_z`).
    """
    if proxy.empty:
        return pd.DataFrame(columns=list(NAVIGATION_HOP_COLUMNS), index=proxy.index)

    all_hops: list[dict[str, object]] = []
    for _, group in proxy.sort_values("ts").groupby(entity_col, sort=False, dropna=False):
        rows = list(
            zip(
                group.index,
                group["ts"],
                group["registrable_domain"],
                group["url_path"],
                group["referrer"],
                strict=True,
            )
        )
        all_hops.extend(_hops_for_principal(rows))

    result = pd.DataFrame(all_hops).set_index("_index")
    result.index.name = proxy.index.name
    return result.reindex(proxy.index)
