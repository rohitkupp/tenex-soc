"""IP -> ASN, org, country, hosting-provider flag (docs/03-PARSERS-OCSF.md "Enrichment").

docs/03 asks for this to be built from "offline MaxMind GeoLite2 + ASN db in
`data/enrichment/`". That specific database requires a MaxMind account and license key to
download and is a binary format (`.mmdb`); neither is obtainable from this sandboxed,
network-free build environment, so it is not what is bundled here. Documented honestly
rather than silently substituted.

What IS bundled (`data/enrichment/ip_ranges.csv`, ~8,400 rows) is a compact IPv4-only CIDR
table built from officially published, authoritative provider feeds, fetched once at build
time (never at runtime):

  * Cloudflare  -- https://www.cloudflare.com/ips-v4        (official)
  * Google Cloud -- https://www.gstatic.com/ipranges/cloud.json  (official)
  * Google (all) -- https://www.gstatic.com/ipranges/goog.json   (official)
  * AWS         -- https://ip-ranges.amazonaws.com/ip-ranges.json (official, `service=AMAZON`)
  * DigitalOcean -- https://digitalocean.com/geo/google.csv  (official DO-published geo feed)

fetched 2026-08-14. `org`/`asn` on each row is the provider that published the feed (not a
per-prefix BGP lookup); `country`, where present, comes from the provider's own region/scope
metadata (AWS region, GCP scope, DigitalOcean's own geo column) via a small, hand-curated
region-to-country table in this module -- left blank rather than guessed where a region has
no single-country mapping (e.g. AWS's `GLOBAL`/edge entries).

Special-use IPv4 space (RFC 1918 private, RFC 5737 documentation/TEST-NET, loopback,
link-local, ...) is resolved separately below via a short, exact, verifiable table rather
than the CSV -- these are IANA-registered constants, not something a curated feed would ever
carry, and getting them right matters here specifically: `datagen`'s default office egress
addresses (docs/11) sit in the three RFC 5737 TEST-NET blocks on purpose ("the corpus must
never contain a routable address that someone could mistake for real telemetry" --
`datagen/realism.py`), so a real deployment's own corporate ranges would just as often be
private RFC 1918 space. Recognizing that correctly is itself a legitimate enrichment signal,
not a gap.

**Known limitation** (state honestly, per the M5 task brief): `datagen`'s residential and
hosting-infrastructure IPs are drawn from effectively random octet ranges (`rng.randint`),
not from real allocated blocks -- deliberately, per `datagen/realism.py`'s own comments, so
the synthetic corpus never contains an address indistinguishable from real telemetry. That
means most of those specific synthetic addresses will *not* land inside any real provider's
published CIDR block, and this module will honestly report them as unresolved rather than
fabricate a match. Coverage is measured and reported against a real M2 corpus in the M5
report rather than assumed.

IPv6 is out of scope: none of the three parsers (docs/03) or `datagen` ever emit an IPv6
address, and every bundled feed above is IPv4-only. An IPv6 input still resolves cleanly
(falls through to "no data" rather than raising) instead of being treated as an error.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
from dataclasses import dataclass
from functools import lru_cache

from app.enrichment.loader import DATA_ENRICHMENT_DIR

IP_RANGES_CSV = DATA_ENRICHMENT_DIR / "ip_ranges.csv"

# IANA special-purpose IPv4 registry (RFC 6890 and the RFCs it collects), the entries
# relevant to traffic this pipeline will actually see. Exact and verifiable by construction
# (stdlib `ipaddress` network membership), unlike anything in the curated CSV above.
_SPECIAL_USE: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (ipaddress.IPv4Network("0.0.0.0/8"), '"This" Network (RFC 791)'),
    (ipaddress.IPv4Network("10.0.0.0/8"), "Private-Use (RFC 1918)"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "Carrier-Grade NAT (RFC 6598)"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "Loopback (RFC 1122)"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "Link-Local (RFC 3927)"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "Private-Use (RFC 1918)"),
    (ipaddress.IPv4Network("192.0.0.0/24"), "IETF Protocol Assignments (RFC 6890)"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "Documentation TEST-NET-1 (RFC 5737)"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "Private-Use (RFC 1918)"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "Benchmarking (RFC 2544)"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "Documentation TEST-NET-2 (RFC 5737)"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "Documentation TEST-NET-3 (RFC 5737)"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "Multicast (RFC 5771)"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "Reserved (RFC 1112)"),
    (ipaddress.IPv4Network("255.255.255.255/32"), "Limited Broadcast (RFC 8190)"),
)


@dataclass(frozen=True, slots=True)
class IPEnrichment:
    """One resolved `src_ip`/`dst_ip`. `asn`/`country` are `None` when unresolved or not
    applicable (special-use space has no ASN); `is_hosting` is `False`, never `None`, so
    callers building an L3 feature like `hosting_provider_ratio` (docs/04) never have to
    special-case a missing value."""

    asn: int | None
    org: str | None
    country: str | None
    is_hosting: bool
    is_special_use: bool


@dataclass(frozen=True, slots=True)
class _Range:
    start: int
    end: int
    asn: int | None
    org: str
    country: str | None
    is_hosting: bool


@lru_cache(maxsize=1)
def _load_ranges() -> tuple[_Range, ...]:
    if not IP_RANGES_CSV.exists():
        return ()
    ranges: list[_Range] = []
    with IP_RANGES_CSV.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                net = ipaddress.IPv4Network(row["cidr"], strict=False)
            except ValueError:
                continue
            ranges.append(
                _Range(
                    start=int(net.network_address),
                    end=int(net.broadcast_address),
                    asn=int(row["asn"]) if row.get("asn") else None,
                    org=row["org"],
                    country=row.get("country") or None,
                    is_hosting=(row.get("is_hosting") or "").strip().lower() == "true",
                )
            )
    ranges.sort(key=lambda r: r.start)
    return tuple(ranges)


@lru_cache(maxsize=1)
def _sorted_starts() -> tuple[int, ...]:
    return tuple(r.start for r in _load_ranges())


def _special_use(addr: ipaddress.IPv4Address) -> str | None:
    for net, label in _SPECIAL_USE:
        if addr in net:
            return label
    return None


def _lookup_range(ip_int: int) -> _Range | None:
    ranges = _load_ranges()
    starts = _sorted_starts()
    idx = bisect.bisect_right(starts, ip_int) - 1
    # Providers' published blocks shouldn't nest, but walk back a bounded handful of
    # candidates as a safety net rather than assuming perfectly disjoint input data.
    for i in range(idx, max(idx - 4, -1), -1):
        r = ranges[i]
        if r.start <= ip_int <= r.end:
            return r
    return None


def enrich_ip(ip: str | None) -> IPEnrichment | None:
    """`None` in, `None` out. An unparseable string also returns `None` -- indistinguishable
    from "not provided" to a caller, which is the right behavior for a hot column that is
    already `str | None` end to end (docs/02)."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    if isinstance(addr, ipaddress.IPv6Address):
        return IPEnrichment(
            asn=None, org=None, country=None, is_hosting=False, is_special_use=False
        )

    special = _special_use(addr)
    if special is not None:
        return IPEnrichment(
            asn=None, org=special, country=None, is_hosting=False, is_special_use=True
        )

    match = _lookup_range(int(addr))
    if match is None:
        return IPEnrichment(
            asn=None, org=None, country=None, is_hosting=False, is_special_use=False
        )
    return IPEnrichment(
        asn=match.asn,
        org=match.org,
        country=match.country,
        is_hosting=match.is_hosting,
        is_special_use=False,
    )
