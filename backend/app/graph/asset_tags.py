"""Asset/inventory tags — Tier 2 asset-centric pivoting, deterministic, zero LLM cost.

## Why this exists, and why it is a second module rather than an extension of `app.graph.tags`

The user's own framing of the goal: *"tagging is mainly for Tier 2 analytics — executives should
be able to check all the issues related to a certain device."* `app.graph.tags.
compute_incident_tags` already established the namespaced-flat-list convention
(`technique:`/`layer:`/`detector:`/derived) this module extends — same `TEXT[]` column
(`incidents.tags`, no schema change needed for the column itself), same "compute once at correlate
time" placement. But that module's inputs are the incident's *signals* (`SignalRef`); asset tags
come from the incident's *evidence events* instead (device/department/location/app/risk are event
properties, not signal properties) — different input shape, different module, unioned into the
same tag list by the caller (`app.pipeline.stages.correlate`).

## The tag set, and why each one earns its place

* `device:<hostname>` — the literal ask: pivot every incident touching one physical/virtual
  endpoint. Keyed on `devicehostname` (`"THINKPADSMITH"`), never `devicename` (an opaque
  hash-suffixed identifier, `"PC11NLPA:5F08D97B..."`) — an executive recognizes the former, not
  the latter. `devicename` is still carried on the event (`app.ocsf.common.Device.name`) for
  citation/evidence purposes; it just isn't a pivot axis.
* `os:<type>` — `deviceostype` is a five-value enum (plus `linux`/`chromeos`/`other` from the
  useragent fallback), the textbook case for a rollup tag: "how many open incidents touch a
  Windows endpoint."
* `os_version:<major.minor>` — `deviceosversion` is high-cardinality free text
  (`"Version 10.14.2 (Build 18C54)"`); tagged raw it would explode tag cardinality and make a
  rollup meaningless (every patch level its own bucket). Normalized to `major.minor` for the tag;
  the full raw string still lives on the event (`Event.os_version`) for anyone who needs the exact
  build.
* `dept:<department>` / `location:<location>` — already-parsed fields (`docs/03`'s original 25),
  newly exposed as incident-level pivots: "which department/office has the most open incidents."
* `app:<appname>` — already-parsed (`unmapped.app_name`); "every incident touching Dropbox."
* `risk:<band>` — bucketed from the already-parsed page-risk `risk_score` (0-100) using the same
  Critical/High/Medium/Low/None bands docs/v1/zscaler-nss-web-fields.md's own `threatseverity`
  field documents Zscaler using for the identical 0-100 scale — reusing a vendor-documented
  bucketing rather than inventing a new one.
* `flow:<type>` — `flow_type` (Direct/Loopback/VPN/VPN Tunnel/ZIA/ZPA) tells you whether traffic
  was on-network; "off-network devices with open incidents" is a real Tier 2 question.
* `bypassed-client-connector` (derived, unprefixed) — traffic that bypassed the Client Connector
  is unmonitored traffic on a device that should have been monitored. Arguably the highest-value
  tag in this set: "which devices are bypassing?" is a real executive/Tier 2 question on its own,
  independent of whatever incident happened to also involve that device.
* `shared-device` (derived, unprefixed) — `deviceowner` (the asset's assigned user) diverging from
  the event's own `principal` (who was actually logged in) is itself a signal, not merely two
  redundant copies of the same fact: a borrowed or shared workstation. Not two separate tags
  (`device_owner:<x>` / `login:<y>`) because the *divergence*, not either value alone, is what is
  interesting — the owner is not itself a new pivot axis (it would just duplicate `dept:`/the
  incident's own user entity in the overwhelming common case where owner == login).

Explicitly **not** tagged, and why: `devicemodel`/`devicetype`/`deviceappversion` (catalogued in
docs/v1/zscaler-nss-web-fields.md, not parsed — see `app.parsers.zscaler`'s module docstring for
why); `app_status`/`app_risk_score` (the cloud-app-specific Sanctioned/Unsanctioned + 1-5 risk
index fields are documented but never parsed by this pipeline at all — adding them would mean
extending the canonical field list a second time in the same task for a field this task's
evidence base does not otherwise need, which is exactly the "do not add a tag just because a field
exists" CLAUDE.md warns against).

## Precedence: explicit device field beats useragent-derived fallback

`os_type`/`os_version` prefer the event's own hot column (`Event.os_type`/`Event.os_version`,
populated when the transaction carried real Client Connector device fields) and fall back to
`app.enrichment.user_agent_enrichment`'s useragent-derived guess only when the hot column is
`None` — service-account/server traffic in this pipeline's own corpus never carries a Client
Connector device (`datagen.emitters.zscaler._device_profile`'s own docstring) and is exactly the
traffic this fallback exists for.

## Real values at rest, same trust boundary as everything else in `app.graph`

Tags land in `incidents.tags`, a tenant's own table — real hostnames/usernames, not pseudonyms,
exactly like `entities.value` already stores real emails/IPs at rest (docs/06: pseudonymization
happens at the LLM/Tier 2 *boundary*, never in Postgres). Verified this feature does not create a
new cross-tenant leak: `app.tier2.signature_sync.sync_incident_to_tier2` reads
`verdict.mitre_techniques`/`incident.entity_ids`/`incident.fused_score`/`incident.embedding` — it
never reads `incident.tags` at all, so nothing this module adds reaches `tier2_signatures`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "TAG_APP_PREFIX",
    "TAG_BYPASSED_CLIENT_CONNECTOR",
    "TAG_DEPT_PREFIX",
    "TAG_DEVICE_PREFIX",
    "TAG_FLOW_PREFIX",
    "TAG_LOCATION_PREFIX",
    "TAG_OS_PREFIX",
    "TAG_OS_VERSION_PREFIX",
    "TAG_RISK_PREFIX",
    "TAG_SHARED_DEVICE",
    "AssetEvent",
    "compute_asset_tags",
]

TAG_DEVICE_PREFIX: Final[str] = "device:"
TAG_OS_PREFIX: Final[str] = "os:"
TAG_OS_VERSION_PREFIX: Final[str] = "os_version:"
TAG_DEPT_PREFIX: Final[str] = "dept:"
TAG_LOCATION_PREFIX: Final[str] = "location:"
TAG_APP_PREFIX: Final[str] = "app:"
TAG_RISK_PREFIX: Final[str] = "risk:"
TAG_FLOW_PREFIX: Final[str] = "flow:"
TAG_BYPASSED_CLIENT_CONNECTOR: Final[str] = "bypassed-client-connector"
TAG_SHARED_DEVICE: Final[str] = "shared-device"

# docs/v1/zscaler-nss-web-fields.md `%s{threatseverity}`'s own bucketing of the identical 0-100
# `%d{riskscore}` scale: Critical 90-100, High 75-89, Medium 46-74, Low 1-45, None 0. Reused
# verbatim rather than inventing a new cut -- lower bound inclusive, checked high-to-low.
_RISK_BANDS: Final[tuple[tuple[int, str], ...]] = (
    (90, "critical"),
    (75, "high"),
    (46, "medium"),
    (1, "low"),
)


@dataclass(frozen=True, slots=True)
class AssetEvent:
    """The subset of one evidence event's fields asset-tag computation needs — deliberately
    narrower than `app.models.event.Event`, same "small projection dataclass" convention
    `app.graph.builder.GraphEvent` already uses for the entity graph. Built by
    `app.pipeline.stages.correlate` from a single targeted query over the incident's own
    `evidence_event_ids`."""

    principal: str | None
    hostname: str | None
    os_type: str | None
    os_version: str | None
    device_owner: str | None
    department: str | None
    location: str | None
    app_name: str | None
    risk_score: int | None
    bypassed_traffic: bool | None
    flow_type: str | None
    # Useragent-derived fallback (`app.enrichment.user_agent_enrichment`), already normalized to
    # the same `os_type` vocabulary — used only when `os_type`/`os_version` above are `None`.
    ua_os_type: str | None = None
    ua_os_version: str | None = None


def _risk_band(score: int | None) -> str | None:
    if score is None:
        return None
    for floor, band in _RISK_BANDS:
        if score >= floor:
            return band
    return None


_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"(\d+)(?:\.(\d+))?")


def _major_minor(version: str | None) -> str | None:
    """`"Version 10.14.2 (Build 18C54)"` -> `"10.14"`; `"14"` -> `"14"` (Android's bare major-only
    version, still one meaningful component); `None`/garbage -> `None`. Deterministic regex, not
    a full version-string grammar: the first `major(.minor)?` run anywhere in the string, which is
    exactly the two shapes Zscaler's own documented example and `ua_parser`'s dot-joined fallback
    (`app.enrichment.user_agent_enrichment._os_version_string`) ever produce."""
    if not version:
        return None
    match = _VERSION_RE.search(version)
    if match is None:
        return None
    major, minor = match.groups()
    return f"{major}.{minor}" if minor else major


def _slug(value: str) -> str:
    """`"VPN Tunnel"` -> `"vpn-tunnel"` — tag values are space-free by convention (every other
    tag in this codebase is, `technique:T1090`/`layer:rule`); `flow_type`'s enum is the one
    field in this module's input that can contain a space."""
    return "-".join(value.strip().lower().split())


def compute_asset_tags(events: Sequence[AssetEvent]) -> list[str]:
    """Deterministic, sorted, deduplicated — same contract as `app.graph.tags.
    compute_incident_tags`. `events` is every evidence event the incident's own signals cite
    (`Signal.evidence_event_ids`, union across the incident's signals); an incident with no
    evidence events (should not happen in practice — every signal carries at least one) produces
    no asset tags without raising."""
    tags: set[str] = set()

    for e in events:
        if e.hostname:
            tags.add(f"{TAG_DEVICE_PREFIX}{e.hostname}")

        os_type = e.os_type or e.ua_os_type
        if os_type:
            tags.add(f"{TAG_OS_PREFIX}{os_type}")

        os_version = e.os_version or e.ua_os_version
        major_minor = _major_minor(os_version)
        if major_minor:
            tags.add(f"{TAG_OS_VERSION_PREFIX}{major_minor}")

        if e.department:
            tags.add(f"{TAG_DEPT_PREFIX}{e.department}")
        if e.location:
            tags.add(f"{TAG_LOCATION_PREFIX}{e.location}")
        if e.app_name:
            tags.add(f"{TAG_APP_PREFIX}{e.app_name}")

        band = _risk_band(e.risk_score)
        if band:
            tags.add(f"{TAG_RISK_PREFIX}{band}")

        if e.flow_type:
            tags.add(f"{TAG_FLOW_PREFIX}{_slug(e.flow_type)}")

        if e.bypassed_traffic:
            tags.add(TAG_BYPASSED_CLIENT_CONNECTOR)

        if e.device_owner and e.principal:
            login_local = e.principal.split("@", 1)[0].strip().lower()
            if login_local and login_local != e.device_owner.strip().lower():
                tags.add(TAG_SHARED_DEVICE)

    return sorted(tags)
