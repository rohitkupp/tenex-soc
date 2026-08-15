"""domain -> registrable domain, TLD risk tier, age in days, newly-registered flag
(docs/03-PARSERS-OCSF.md "Enrichment").

docs/03: "Newly-registered domain (age < 30 days) is a strong C2 indicator -- surface it as
a first-class enrichment flag, not buried in JSON." `age_days`/`newly_registered` below are
exactly that first-class flag.

**Domain popularity is reused, not reinvented** (per the M5 task brief: "M2 already bundles
grounding data under `backend/datagen/data/` ... reuse or extend rather than inventing
parallel datasets"). This module reads `backend/datagen/data/top_domains.txt` directly --
the same Majestic Million top-5000 list `datagen/realism.py` uses to shape the benign
corpus's domain popularity -- rather than shipping a second copy that could silently drift
out of sync with it.

**Domain age has one honest, bundled source and no other.** There is no legitimate offline
WHOIS/RDAP dataset obtainable without live network access in this environment, so
`data/enrichment/domain_age_snapshot.csv` is *not* a real registration-date crawl. It is a
deterministic snapshot recording exactly one true fact: every domain in the reused top-5000
list is long-established (true in reality -- the world's most popular sites were
overwhelmingly registered decades ago). Domains outside that list -- which, by construction
of the M2 generator, is where essentially every synthetic attacker/typosquat domain lives
(`datagen/realism.py`'s `NewlyRegisteredDomainPool` mints brand-new, never-before-seen
strings) -- get **no snapshot row**, and this module reports their age as honestly unknown
(`age_known=False`, `newly_registered=False`) rather than fabricating a plausible-looking
number for a string it has no real information about. `tld_risk_tier` is the flag that
*does* fire on that population instead (typosquat/DGA-style domains concentrate in the
`high`-tier TLDs in `data/enrichment/tld_risk.yml`, which is grounded independently in
real-world abuse statistics, not reverse-engineered from `datagen`). See the M5 report for
measured coverage on a generated corpus and the same tradeoff spelled out again there.

Public-suffix parsing uses `tldextract` in fully offline mode: `TLDExtract(suffix_list_urls=
())` forces it onto the snapshot of the public suffix list bundled with the package and
never attempts a network fetch, satisfying docs/03's "Do not make network calls at runtime."
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import lru_cache

import tldextract
import yaml

from app.enrichment.loader import DATA_ENRICHMENT_DIR, DATAGEN_DATA_DIR

DOMAIN_AGE_CSV = DATA_ENRICHMENT_DIR / "domain_age_snapshot.csv"
TLD_RISK_YML = DATA_ENRICHMENT_DIR / "tld_risk.yml"
TOP_DOMAINS_TXT = DATAGEN_DATA_DIR / "top_domains.txt"

NEWLY_REGISTERED_THRESHOLD_DAYS = 30


@dataclass(frozen=True, slots=True)
class DomainEnrichment:
    registrable_domain: str
    tld: str
    tld_risk_tier: str  # "high" | "medium" | "low" | "unknown"
    age_days: int | None
    age_known: bool
    newly_registered: bool
    popularity_rank: int | None
    is_top_site: bool


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # suffix_list_urls=() -- offline only, bundled snapshot, no network fetch, ever.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@lru_cache(maxsize=1)
def _tld_risk() -> dict[str, str]:
    if not TLD_RISK_YML.exists():
        return {}
    data = yaml.safe_load(TLD_RISK_YML.read_text(encoding="utf-8")) or {}
    out: dict[str, str] = {}
    for tier in ("high", "medium", "low"):
        for tld in data.get(tier) or []:
            out[str(tld).lower()] = tier
    return out


@lru_cache(maxsize=1)
def _age_snapshot() -> dict[str, date]:
    if not DOMAIN_AGE_CSV.exists():
        return {}
    out: dict[str, date] = {}
    with DOMAIN_AGE_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                out[row["domain"].strip().lower()] = date.fromisoformat(row["first_seen"])
            except (KeyError, ValueError):
                continue
    return out


@lru_cache(maxsize=1)
def _popularity_rank() -> dict[str, int]:
    if not TOP_DOMAINS_TXT.exists():
        return {}
    out: dict[str, int] = {}
    rank = 0
    for raw in TOP_DOMAINS_TXT.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rank += 1
        out[line.lower()] = rank
    return out


def enrich_domain(domain: str | None, *, as_of: date | None = None) -> DomainEnrichment | None:
    """`as_of` defaults to real today and only exists so tests can pin "now" instead of
    depending on wall-clock date. `domain` may be a bare hostname (as stored in
    `events.domain`, docs/02) or already-registrable; a direct-IP host (docs/04's "Direct-to-
    IP HTTP request" rule fires on exactly this) has no TLD, and is returned with the raw
    string as `registrable_domain`, `tld=""`, and tier `"unknown"` rather than dropped."""
    if not domain:
        return None
    hostname = domain.strip().lower().rstrip(".")
    if not hostname:
        return None

    result = _extractor()(hostname)
    registrable = result.top_domain_under_public_suffix or hostname
    tld = result.suffix or ""

    tier = _tld_risk().get(tld, "unknown") if tld else "unknown"

    first_seen = _age_snapshot().get(registrable)
    if first_seen is not None:
        now = as_of if as_of is not None else datetime.now(UTC).date()
        age_days = (now - first_seen).days
        age_known = True
        newly_registered = age_days < NEWLY_REGISTERED_THRESHOLD_DAYS
    else:
        age_days = None
        age_known = False
        newly_registered = False

    rank = _popularity_rank().get(registrable)

    return DomainEnrichment(
        registrable_domain=registrable,
        tld=tld,
        tld_risk_tier=tier,
        age_days=age_days,
        age_known=age_known,
        newly_registered=newly_registered,
        popularity_rank=rank,
        is_top_site=rank is not None,
    )
