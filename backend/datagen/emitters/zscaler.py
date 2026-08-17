"""ZScaler NSS Web proxy logs — the highest-volume source in the corpus (docs/11).

Tab-delimited NSS Web feed with a header line, carrying all 181 fields
`docs/v1/zscaler-nss-web-fields.md` documents from the NSS Web Logs feed reference — docs/03's
original 25 (still that document's own order, unchanged, first in `FIELDS`), the 27 promoted
across two later changes (device/asset + detection-relevant TLS/threat/network fields), and
~129 more added by this task's full-width widening (docs/v1/11-SYNTHETIC-DATA.md "Full width,
and the 25/52-of-181 extraction contract"). `app/parsers/zscaler.py` only ever extracts the first
52 by name; the rest are catalogued, realistic, and internally consistent, but deliberately not
parsed — see `FIELDS`'s own comment block and `_apply_wide_fields` for why and how. The header is
what makes the file sniffable and what lets the M3 parser bind columns by name rather than
position; `FIELD_INDEX` is exported so the parser never has to restate the order.

Two format decisions worth stating, because a parser written against a guess would break:

* `url` carries the **path and query only**, not the scheme and host. docs/03 maps `url` to
  `http_request.url.path` and `host` to `http_request.url.hostname`; a full URL in `url` would
  duplicate the host and put a URL where the parser expects a path.
* Absent values are the literal string `None`, which is what NSS emits for a clean transaction.
  Records only carry the fields they actually set and `serialize` fills the rest from
  `_FIELD_DEFAULTS` (the original 25) or `_apply_wide_fields`'s own per-event derivation (the
  full-width catalogue) — a benign event's `fields` dict still costs far fewer entries than
  `len(FIELDS)`, just no longer sixteen: the full-width catalogue's own defaulting happens through
  `_apply_wide_fields`, called once per event, not through a static table.

Line numbers: the header occupies physical line 1, so a driver that writes it must call
`assign_line_numbers(records, start=1 + ZScalerEmitter.header_lines)` for the line numbers in
`GroundTruth` to point at the right rows.

Volume: ~2M events. Every numeric draw is vectorised on the seeded numpy engine and records are
yielded batch by batch, so the emitter never holds more than `_BATCH` events at once. The one
thing not vectorised is `EventRecord` construction itself (and, since this task, `_apply_wide_fields`'s
per-event full-width derivation — `_mix`-based rather than `hashlib`-based specifically to keep
that unvectorised cost small at ~2M events, see that function's own section docstring).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, ClassVar, Final, TextIO

import numpy as np

from datagen.org import SaasApp, User
from datagen.realism import RealismModels, ResponseSizeModel
from datagen.rng import SeededRandom, stable_hash
from datagen.types import BenignContext, EventRecord, ScenarioContext, SourceType

__all__ = [
    "CATEGORIES",
    "EMPTY",
    "FIELDS",
    "FIELD_INDEX",
    "KINDS",
    "METHODS",
    "NAMED_CATEGORIES",
    "RISKY_COUNTRIES",
    "SECURITY_CATEGORIES",
    "STATUS_CODES",
    "UrlCategory",
    "ZScalerEmitter",
    "categorize",
    "line_numbers",
    "server_ip",
]

# docs/03 "ZScaler NSS Web -> OCSF HTTP Activity (4002)", in the order that table lists them.
FIELDS: Final[tuple[str, ...]] = (
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
    # Asset/device extension (this task, docs/v1/zscaler-nss-web-fields.md "Zscaler Client
    # Connector Device Information" + "Miscellaneous") -- `app.parsers.zscaler`'s literal NSS
    # token names, appended rather than interspersed so the original 25-field order (and every
    # existing hand-written fixture line built against it) is untouched.
    "devicehostname",
    "devicename",
    "deviceostype",
    "deviceosversion",
    "deviceowner",
    "bypassed_traffic",
    "flow_type",
    # Phase 2 detection-field extension (this task, docs/v1/zscaler-nss-web-fields.md "SSL/TLS",
    # "Server Connection", "Sandbox", "File Type Control", "Network", "Threat Protection") --
    # `app.parsers.zscaler`'s literal NSS token names, appended (not interspersed) for the same
    # reason the device extension above is.
    "ja4_str",
    "df_hostname",
    "df_hosthead",
    "ssldecrypted",
    "is_sslselfsigned",
    "is_sslexpiredca",
    "is_ssluntrustedca",
    "srvcertvalidityperiod",
    "srvocspresult",
    "sha256",
    "bamd5",
    "srcip_country",
    "dstip_country",
    "is_src_cntry_risky",
    "is_dst_cntry_risky",
    "upload_filename",
    "upload_filetype",
    "filetype",
    "unscannabletype",
    "threatseverity",
    # ------------------------------------------------------------------------------------------
    # Full-catalogue widening (this task, docs/v1/zscaler-nss-web-fields.md). The application
    # only ever *extracts* the 52 fields above (docs/03's 25 plus the 27 promoted across the two
    # changes right above this comment) -- everything below exists so the raw file this generator
    # produces is genuinely ~150-column, the width a real NSS export configured with "every
    # field" would be, and the extraction step above has 100+ unmapped columns to correctly
    # ignore rather than 0. `app/parsers/zscaler.py` is deliberately NOT changed to read any of
    # these (CLAUDE.md: "do not add a tag just because a field exists"; these fields back no tag,
    # detector, or citation today) -- they are catalogued, realistic, and internally consistent,
    # not wired.
    #
    # Every field below uses the PDF's own literal `%s{...}`/`%d{...}` token -- there is no prior
    # "friendly" name to preserve continuity with for a field this generator has never emitted
    # before (same reasoning the device-field extension above already gives for why *it* uses
    # literal tokens). Nothing here renames or duplicates a field already represented above
    # (`login`/`dept`/`cip`/`sip`/`reqmethod`/`respcode`/`reqsize`/`respsize`/`ua`/`urlcat`/
    # `urlsupercat`/`malwarecat`/`dlpeng`/`dlpdict` already live under this file's original 25
    # SIEM-normalized names -- see docs/v1/zscaler-nss-web-fields.md "Task 2 — reconciliation").
    #
    # Grouped by the field-reference doc's own section headings, in that doc's own order.
    # Date/Time -- every one of these is a different rendering of the same instant `datetime`
    # already carries; `_derive_datetime_tokens` computes all eleven from one `datetime.timestamp`
    # read so they can never drift apart from each other or from `datetime`.
    "time",
    "tz",
    "ss",
    "mm",
    "hh",
    "dd",
    "mth",
    "yyyy",
    "mon",
    "day",
    "epochtime",
    # User Information (login/dept already carried as user/department above).
    "company",
    "cloudname",
    # Bandwidth Control -- always off in this corpus (see `_apply_wide_fields`'s own note).
    "txn_delay_req",
    "txn_delay_resp",
    "throttlereqsize",
    "throttlerespsize",
    "bwthrottle",
    "bwclassname",
    "bwrulename",
    # Cloud Application (appname/appclass already carried above).
    "app_risk_score",
    "app_status",
    "activity",
    "prompt_req",
    "prompt_class",
    "inst_level1_type",
    "inst_level1_id",
    "inst_level1_name",
    "inst_level2_type",
    "inst_level2_id",
    "inst_level2_name",
    "inst_level3_type",
    "inst_level3_id",
    "inst_level3_name",
    # Data Center
    "datacenter",
    "datacentercity",
    "datacentercountry",
    # Data Loss Prevention (dlpeng/dlpdict already carried as dlpengine/dlpdictionaries above;
    # `dlpdict` here is the same dictionary set, pipe-delimited per the PDF's own literal example,
    # vs. `dlpdictionaries`'s comma delimiter -- two independent naming conventions on the same
    # underlying match, exactly like the original 25's own renaming story).
    "dlpdict",
    "dlpdicthitcount",
    "dlpidentifier",
    "exempt_dlpidentifier",
    "dlpmd5",
    "dlprulename",
    "trig_dlprulename",
    "other_dlprulenames",
    "all_dlprulenames",
    "dlp_policy_action",
    "dlp_confirm_justification_msg",
    # Extranet Application -- never populated (no extranet resource modeled); see
    # `_apply_wide_fields`'s note.
    "extranet_name",
    # File Type Control (filetype/upload_filetype/upload_filename/unscannabletype already carried
    # above).
    "ft_rulename",
    "fileclass",
    "filename",
    "filesubtype",
    "upload_fileclass",
    "upload_filesubtype",
    "upload_doctypename",
    "upload_doc_sub_type",
    # Forwarding Control
    "rdr_rulename",
    "fwd_type",
    "fwd_gw_name",
    "fwd_gw_ip",
    "zpa_app_seg_name",
    # HTTP Transaction (reqsize/respsize/reqmethod/respcode/referer/ua/host/url/df_hostname/
    # df_hosthead already carried above -- see the module-level comment on this block).
    "reqdatasize",
    "reqhdrsize",
    "respdatasize",
    "resphdrsize",
    "totalsize",
    "reqversion",
    "respversion",
    "refererhost",
    "uaclass",
    "ua_token",
    "contenttype",
    # Mobile Application -- never populated; docs/11's own documented limitation is that every
    # human principal gets a desktop device fingerprint (`Org._build_users` ->
    # `UserAgentMix.sample_desktop`), so there is no mobile traffic in this corpus to describe.
    "mobappname",
    "mobappcat",
    "mobdevtype",
    # Network (cip/sip/location/srcip_country/dstip_country/is_src_cntry_risky/
    # is_dst_cntry_risky already carried above).
    "cintip",
    "cpubip",
    "clt_sport",
    "srv_dport",
    "proto",
    "alpnprotocol",
    "trafficredirectmethod",
    "userlocationname",
    # Policy (action/reason already carried above).
    "ruletype",
    "rulelabel",
    "urlfilterrulelabel",
    "apprulelabel",
    # SSL/TLS (ssldecrypted/ja4_str already carried above).
    "ssl_rulename",
    "externalspr",
    "keyprotectiontype",
    # Client Connection
    "clientsslcipher",
    "clienttlsversion",
    "clientsslsessreuse",
    "cltsslfailreason",
    "cltsslfailcount",
    "client_tls_keyex_pqc_offers",
    "client_tls_keyex_non_pqc_offers",
    "client_tls_keyex_hybrid_offers",
    "client_tls_keyex_unknown_offers",
    "client_tls_sig_pqc_offers",
    "client_tls_sig_non_pqc_offers",
    "client_tls_sig_hybrid_offers",
    "client_tls_sig_unknown_offers",
    "client_tls_keyex_alg",
    "client_tls_sig_alg",
    # Server Connection (srvocspresult/srvcertvalidityperiod/is_ssluntrustedca/is_sslselfsigned/
    # is_sslexpiredca already carried above).
    "srvsslcipher",
    "srvtlsversion",
    "serversslsessreuse",
    "srvcertchainvalpass",
    "srvwildcardcert",
    "srvcertvalidationtype",
    "server_tls_keyex_alg",
    "server_tls_sig_alg",
    # Threat Protection (riskscore/threatseverity/threatname already carried above; `malwarecat`
    # deliberately not added here -- see the module-level comment: this file's `threatcategory` is
    # already that concept under its SIEM-normalized name, and a second literal `malwarecat`
    # column would describe the same slot twice).
    "malwareclass",
    "ai_ml_detect_src",
    # URL Categorization (urlsupercat/urlcat already carried above).
    "urlclass",
    "urlcatmethod",
    # Zscaler Client Connector Device Information -- catalogued but not wired, same as
    # `devicemodel`/`devicetype`/`deviceappversion` already are per docs/v1/
    # zscaler-nss-web-fields.md's own "What this task wired in vs. catalogued only"; computed in
    # `_device_profile` (stable per user, like the seven wired device fields already are).
    "devicemodel",
    "devicetype",
    "deviceappversion",
    # Miscellaneous (bypassed_traffic/flow_type already carried above).
    "ztunnelversion",
    "external_devid",
    "bypassed_etime",
    "recordid",
    "pcapid",
    "productversion",
    "nsssvcip",
    "eedone",
)

FIELD_INDEX: Final[dict[str, int]] = {name: i for i, name in enumerate(FIELDS)}

EMPTY: Final[str] = "None"

_FIELD_DEFAULTS: Final[dict[str, str]] = {
    "serverip": EMPTY,
    "host": EMPTY,
    "url": "/",
    "requestmethod": "GET",
    "status": "200",
    "requestsize": "0",
    "responsesize": "0",
    "useragent": EMPTY,
    "action": "Allowed",
    "urlcategory": "Miscellaneous or Unknown",
    "urlsupercategory": "Miscellaneous",
    "appname": "General Browsing",
    "appclass": "General Browsing",
    "threatname": EMPTY,
    "threatcategory": EMPTY,
    "riskscore": "0",
    "reason": EMPTY,
    "referer": EMPTY,
    "dlpengine": EMPTY,
    "dlpdictionaries": EMPTY,
    "location": EMPTY,
    "department": EMPTY,
}

_BATCH: Final[int] = 50_000

# The NSS `riskscore` field is documented 0-100.
_MAX_RISK: Final[int] = 100

# 204/304 carry headers and no body; leaving them on the log-normal curve would put phantom
# megabytes of `bytes_in` into every hourly feature vector.
_NO_BODY: Final[frozenset[int]] = frozenset({204, 304})
_NO_BODY_BYTES: Final[int] = 512
_BLOCK_PAGE_BYTES: Final[int] = 1180

# Human uploads stay below the 10 MB threshold of the L1 "large POST" rule. Real users do send
# bigger files, but the benign corpus is the training set and the labelled false-positive
# control is scenario 10 — a rule that fires a thousand times on the clean corpus is untunable.
_HUMAN_MAX_REQUEST_BYTES: Final[int] = 8_000_000
_MAX_BYTES: Final[int] = 2_000_000_000
_MIN_BYTES: Final[int] = 64


# ---------------------------------------------------------------------------- device profile
#
# Zscaler Client Connector device fields (docs/v1/zscaler-nss-web-fields.md), stable per
# principal — "one stable hostname/model per simulated user" (this task's brief), the same
# fingerprint-per-user discipline `datagen.org.DeviceFingerprint` already established for
# `user_agent`/`os_family`. Deliberately built from `user.device` and `stable_hash` alone, not a
# new field on `datagen.org.User` — `Org.fingerprint()` content-hashes the whole org
# (`Org.to_dict`), and adding a column there would change every seeded org's fingerprint for a
# property this module can derive from data the `User` already carries.

# `datagen.realism.UserAgentSpec.os_family` -> Zscaler's own `deviceostype` wire enum (this task's
# brief gives the exact five values). Real users' devices only ever carry `desktop`/`mobile`
# `os_family` values (docs/11 "human user agents are desktop-only"); `Linux` never appears on a
# human's `device.os_family` today, but is mapped here anyway for the same forward-compatibility
# reason `app.privacy.event_privacy` keeps unreachable-today allowlist entries.
_DEVICEOSTYPE_BY_OS_FAMILY: Final[dict[str, str]] = {
    "Windows": "Windows OS",
    "macOS": "MAC OS",
    "iOS": "iOS",
    "Android": "Android OS",
    "Linux": "Other OS",
}
_HOSTNAME_PREFIX_BY_OS_FAMILY: Final[dict[str, str]] = {
    "Windows": "DESKTOP",
    "macOS": "MBP",
    "iOS": "IPHONE",
    "Android": "ANDROID",
    "Linux": "LNX",
}
# Plausible, deterministic per-family OS version strings — a handful of pinned builds, same
# "a real fleet has a handful of pinned builds, not a continuous random draw" reasoning
# `datagen.realism.UserAgentMix`'s own docstring gives for fixed browser version strings.
_WINDOWS_OS_VERSIONS: Final[tuple[str, ...]] = (
    "10.0.19045",
    "10.0.22631",
    "11.0.22631",
    "11.0.26100",
)
_MACOS_OS_VERSIONS: Final[tuple[tuple[str, str], ...]] = (
    ("14.4.1", "23E224"),
    ("14.6.1", "23G93"),
    ("13.6.7", "22G720"),
    ("15.1", "24B83"),
)
_IOS_OS_VERSIONS: Final[tuple[str, ...]] = ("17.4.1", "17.6.1", "18.1")
_ANDROID_OS_VERSIONS: Final[tuple[str, ...]] = ("13", "14", "15")

# `devicemodel` pools, keyed the same way `_WINDOWS_OS_VERSIONS` etc. are — a handful of pinned,
# real-looking model identifiers, not a continuous random draw (this task, catalogued-only).
_WINDOWS_MODELS: Final[tuple[str, ...]] = ("20L8S7WC08", "21HH0028US", "8VR91EA", "5397NR6")
_MACOS_MODELS: Final[tuple[str, ...]] = ("MacBookPro18,3", "MacBookPro18,1", "MacBookAir10,1")
_IOS_MODELS: Final[tuple[str, ...]] = ("iPhone15,2", "iPhone14,5", "iPhone16,1")
_ANDROID_MODELS: Final[tuple[str, ...]] = ("SM-G998U", "Pixel 8", "SM-S928U")
_MODELS_BY_OS_FAMILY: Final[dict[str, tuple[str, ...]]] = {
    "Windows": _WINDOWS_MODELS,
    "macOS": _MACOS_MODELS,
    "iOS": _IOS_MODELS,
    "Android": _ANDROID_MODELS,
}
# Client Connector app version enrolled on the device — a small pool of pinned rollout versions,
# same "a real fleet has a handful of pinned builds" reasoning as the OS version pools above.
_CC_APP_VERSIONS: Final[tuple[str, ...]] = ("4.2.0.150", "4.3.1.88", "4.3.2.44", "4.1.0.220")
_ZTUNNEL_VERSION: Final[str] = "ZTUNNEL_2_0"
_DEVICETYPE_CLIENT_CONNECTOR: Final[str] = "Zscaler Client Connector"
# Share of managed devices actually enrolled in an external MDM (`external_devid`) — most are not,
# in this simulated org.
_EXTERNAL_DEVID_RATE_DENOM: Final[int] = 5

# A small, generic "shared account" name pool — real-world sources of owner/login divergence
# (kiosk terminals, contractor loaners, front-desk machines), not a fabricated *other employee*
# identity. Deterministic ~1-in-32 draw per user (`app.graph.asset_tags`'s `shared-device` tag
# exists to catch exactly this).
_SHARED_DEVICE_OWNER_POOL: Final[tuple[str, ...]] = (
    "contractor1",
    "labuser",
    "frontdesk",
    "kiosk01",
    "tempstaff",
)
_SHARED_DEVICE_OWNER_RATE_DENOM: Final[int] = 32

_FLOW_ZIA: Final[str] = "ZIA"
_FLOW_VPN: Final[str] = "VPN"
_FLOW_ZPA: Final[str] = "ZPA"
_FLOW_DIRECT: Final[str] = "Direct"
# ~1-in-20 remote-page requests get tagged ZPA (private app access) instead of the VPN default —
# deterministic on the existing per-event `path_seeds` draw, no new RNG stream.
_ZPA_OVERRIDE_MODULUS: Final[int] = 20
_HUMAN_BYPASS_RATE: Final[float] = 0.02


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    """`(devicehostname, devicename, deviceostype, deviceosversion, deviceowner)` for one
    principal — `None` for every field when the principal has no Client Connector device at all
    (service accounts: unmanaged/headless hosts, realistic corpus shape in its own right, and
    exactly the traffic `app.enrichment.user_agent_enrichment`'s useragent-derived OS fallback
    exists to cover, since it has no explicit device field to fall back *from* otherwise).

    `model`/`device_type`/`app_version`/`ztunnel_version`/`external_devid` (this task, docs/v1/
    zscaler-nss-web-fields.md "Zscaler Client Connector Device Information" + "Miscellaneous",
    catalogued-only) are device-*level* facts, not per-request draws — a laptop's model number
    does not change between HTTP transactions — so they are computed once here, alongside the
    five wired device fields, rather than per-event in `_apply_wide_fields`. Same all-`None`
    convention for service accounts."""

    hostname: str | None
    device_name: str | None
    os_type: str | None
    os_version: str | None
    owner: str | None
    model: str | None = None
    device_type: str | None = None
    app_version: str | None = None
    ztunnel_version: str | None = None
    external_devid: str | None = None


def _device_profile(user: User) -> DeviceProfile:
    if user.is_service_account:
        return DeviceProfile(None, None, None, None, None)

    device = user.device
    h = stable_hash(f"{user.key}|device")
    prefix = _HOSTNAME_PREFIX_BY_OS_FAMILY.get(device.os_family, "PC")
    hostname = f"{prefix}-{user.username.upper()}"
    device_name = f"{hostname}:{h:032X}"[:64]
    devicetype = _DEVICEOSTYPE_BY_OS_FAMILY.get(device.os_family, "Other OS")

    version: str | None
    if device.os_family == "Windows":
        version = f"Version {_WINDOWS_OS_VERSIONS[h % len(_WINDOWS_OS_VERSIONS)]}"
    elif device.os_family == "macOS":
        num, build = _MACOS_OS_VERSIONS[h % len(_MACOS_OS_VERSIONS)]
        version = f"Version {num} (Build {build})"
    elif device.os_family == "iOS":
        version = f"Version {_IOS_OS_VERSIONS[h % len(_IOS_OS_VERSIONS)]}"
    elif device.os_family == "Android":
        version = f"Version {_ANDROID_OS_VERSIONS[h % len(_ANDROID_OS_VERSIONS)]}"
    else:
        version = None

    owner = user.username
    if h % _SHARED_DEVICE_OWNER_RATE_DENOM == 0:
        owner = _SHARED_DEVICE_OWNER_POOL[h % len(_SHARED_DEVICE_OWNER_POOL)]

    model_pool = _MODELS_BY_OS_FAMILY.get(device.os_family)
    model = model_pool[h % len(model_pool)] if model_pool else None
    app_version = _CC_APP_VERSIONS[h % len(_CC_APP_VERSIONS)]
    external_devid = str(1000 + h % 8999) if h % _EXTERNAL_DEVID_RATE_DENOM == 0 else None

    return DeviceProfile(
        hostname,
        device_name,
        devicetype,
        version,
        owner,
        model=model,
        device_type=_DEVICETYPE_CLIENT_CONNECTOR,
        app_version=app_version,
        ztunnel_version=_ZTUNNEL_VERSION,
        external_devid=external_devid,
    )


def _apply_device_fields(fields: dict[str, Any], profile: DeviceProfile) -> None:
    """Set the device keys on `fields` only when `profile` actually has a device — an absent
    key falls back to the `"None"` sentinel through `ZScalerEmitter._default` exactly like every
    other optional field (`threatname`, `reason`, ...) already does, so a service-account record
    costs nothing extra for fields it doesn't have."""
    if profile.hostname is None:
        return
    fields["devicehostname"] = profile.hostname
    fields["devicename"] = profile.device_name
    fields["deviceostype"] = profile.os_type
    fields["deviceowner"] = profile.owner
    if profile.os_version is not None:
        fields["deviceosversion"] = profile.os_version
    # Catalogued-only device fields (this task) — same presence discipline as the five above.
    if profile.model is not None:
        fields["devicemodel"] = profile.model
    if profile.device_type is not None:
        fields["devicetype"] = profile.device_type
    if profile.app_version is not None:
        fields["deviceappversion"] = profile.app_version
    if profile.ztunnel_version is not None:
        fields["ztunnelversion"] = profile.ztunnel_version
    if profile.external_devid is not None:
        fields["external_devid"] = profile.external_devid


# ---------------------------------------------------------------------------- categories


@dataclass(frozen=True, slots=True)
class UrlCategory:
    """One `urlcategory` / `urlsupercategory` / `appclass` triple plus its baseline risk."""

    name: str
    supercategory: str
    appclass: str
    risk: int = 0
    policy_blockable: bool = False


CATEGORIES: Final[tuple[UrlCategory, ...]] = (
    UrlCategory("Professional Services", "Business and Economy", "General Browsing"),
    UrlCategory("Corporate Marketing", "Business and Economy", "General Browsing"),
    UrlCategory("Web Search", "Internet Services", "Web Search"),
    UrlCategory("Internet Services", "Internet Services", "General Browsing"),
    UrlCategory("Web Hosting", "Internet Services", "Web Hosting", 5),
    UrlCategory("Content Delivery Networks", "Internet Services", "CDN"),
    UrlCategory("Online Advertising", "Internet Services", "Advertising", 10),
    UrlCategory("News and Media", "News and Media", "General Browsing"),
    UrlCategory("Social Networking", "Social and Entertainment", "Social Networking", 15, True),
    UrlCategory("Streaming Media", "Social and Entertainment", "Streaming Media", 10, True),
    UrlCategory("Shopping and Auctions", "Shopping and Auctions", "Shopping", 5, True),
    UrlCategory("Education", "Education", "General Browsing"),
    UrlCategory("Health", "Health", "General Browsing"),
    UrlCategory("Government", "Government and Politics", "General Browsing"),
    UrlCategory("Finance", "Finance and Investment", "General Browsing"),
    UrlCategory("Travel", "Travel", "General Browsing"),
    UrlCategory("Sports", "Sports", "General Browsing", 5, True),
    UrlCategory("Reference", "Reference", "General Browsing"),
    UrlCategory("File Host", "Internet Services", "File Share", 25),
    UrlCategory("Professional Networking", "Business and Economy", "Social Networking", 5),
)

# Scenario authors reach for these by name. The L1 "malware/phishing/C2 category" rule keys on
# `urlsupercategory == "Security"`, and nothing in the benign path ever produces one.
SECURITY_CATEGORIES: Final[dict[str, UrlCategory]] = {
    "malware": UrlCategory("Malware Sites", "Security", "Malware", 95),
    "phishing": UrlCategory("Phishing", "Security", "Phishing", 95),
    "c2": UrlCategory("Botnet Callback", "Security", "Botnet", 98),
    "spyware": UrlCategory("Spyware and Adware", "Security", "Adware", 80),
    "suspicious": UrlCategory("Suspicious Destinations", "Security", "Suspicious", 70),
}

NAMED_CATEGORIES: Final[dict[str, UrlCategory]] = {
    **SECURITY_CATEGORIES,
    "newly_registered": UrlCategory(
        "Newly Registered and Revived Domains", "Miscellaneous", "General Browsing", 45
    ),
    "uncategorized": UrlCategory(
        "Miscellaneous or Unknown", "Miscellaneous", "General Browsing", 20
    ),
    "file_host": UrlCategory("File Host", "Internet Services", "File Share", 25),
    "web_hosting": UrlCategory("Web Hosting", "Internet Services", "Web Hosting", 5),
}

_SAAS_CATEGORY: Final[dict[str, UrlCategory]] = {
    "identity": UrlCategory("Professional Services", "Business and Economy", "Authentication"),
    "productivity": UrlCategory("Web-based Productivity Apps", "Business and Economy", "Office"),
    "collaboration": UrlCategory("Collaboration", "Business and Economy", "Collaboration"),
    "crm": UrlCategory("Professional Services", "Business and Economy", "CRM"),
    "hr": UrlCategory("Professional Services", "Business and Economy", "HR"),
    "engineering": UrlCategory("Professional Services", "Business and Economy", "DevOps"),
    "storage": UrlCategory("File Host", "Internet Services", "File Share", 10),
    "cloud": UrlCategory("Professional Services", "Business and Economy", "IaaS"),
    "data": UrlCategory("Professional Services", "Business and Economy", "Analytics"),
    "observability": UrlCategory("Professional Services", "Business and Economy", "Monitoring"),
}


@lru_cache(maxsize=16384)
def categorize(domain: str) -> UrlCategory:
    """Stable category for a domain.

    Keyed on `stable_hash` rather than drawn: a domain that changed category between requests
    would turn `urlcategory` into noise and cost the category-based rules their meaning.
    """
    return CATEGORIES[stable_hash(domain) % len(CATEGORIES)]


# Client addresses stay in the documentation ranges (see org.py). Destination addresses have to
# look like real CDN space, or the hosting-provider enrichment flag would separate benign from
# attack traffic for free.
_SERVER_ANCHORS: Final[tuple[str, ...]] = (
    "23.35",
    "23.53",
    "104.16",
    "104.18",
    "151.101",
    "142.250",
    "172.217",
    "13.107",
    "20.190",
    "52.84",
    "99.86",
    "18.66",
)


@lru_cache(maxsize=16384)
def server_ip(domain: str) -> str:
    """Deterministic `serverip` for a hostname.

    Derived, not drawn: the graph layer treats `dst_ip` as an entity, and a domain that resolved
    somewhere new on every request would destroy `shared_infra_overlap`.
    """
    h = stable_hash(domain)
    anchor = _SERVER_ANCHORS[h % len(_SERVER_ANCHORS)]
    return f"{anchor}.{(h >> 8) % 256}.{1 + (h >> 16) % 254}"


# ---------------------------------------------------------------------------- request shapes

KINDS: Final[tuple[str, ...]] = ("html", "script", "image", "api", "video", "download")
METHODS: Final[tuple[str, ...]] = ("GET", "POST", "HEAD", "PUT", "CONNECT")
_KIND_API: Final[int] = KINDS.index("api")
_KIND_DOWNLOAD: Final[int] = KINDS.index("download")

# 403 deliberately excluded (this task, bug fix): `_human_batch` below already produces every
# 403 through the `is_blocked` branch, paired with `action="Blocked"` by construction. Before this
# fix, 403 was *also* reachable through this "ordinary" pool at 0.5% weight with no such pairing,
# so an unblocked, `action="Allowed"` request could carry `status=403` — exactly the
# `respcode`/`action` contradiction this task's own brief calls out ("respcode 403 must co-occur
# with action=Blocked"). The 0.005 that 403 carried is folded into 404, the nearest "ordinary
# client error" code.
STATUS_CODES: Final[tuple[int, ...]] = (
    200,
    204,
    206,
    301,
    302,
    304,
    400,
    401,
    404,
    429,
    500,
    502,
    503,
)
_STATUS_WEIGHTS: Final[tuple[float, ...]] = (
    0.845,
    0.028,
    0.010,
    0.012,
    0.023,
    0.040,
    0.005,
    0.004,
    0.019,
    0.001,
    0.006,
    0.004,
    0.003,
)

# First request of a page load versus the sub-resources it pulls in, over KINDS.
_PAGE_KIND_WEIGHTS: Final[tuple[float, ...]] = (0.930, 0.0, 0.0, 0.015, 0.040, 0.015)
_SUB_KIND_WEIGHTS: Final[tuple[float, ...]] = (0.010, 0.460, 0.400, 0.130, 0.0, 0.0)

# Rows are KINDS, columns METHODS. The API row is what gives `post_ratio` a non-trivial baseline.
_METHOD_WEIGHTS: Final[tuple[tuple[float, ...], ...]] = (
    (0.965, 0.025, 0.005, 0.000, 0.005),
    (0.990, 0.000, 0.010, 0.000, 0.000),
    (0.990, 0.000, 0.010, 0.000, 0.000),
    (0.550, 0.380, 0.010, 0.050, 0.010),
    (0.980, 0.000, 0.020, 0.000, 0.000),
    (0.970, 0.000, 0.030, 0.000, 0.000),
)

_SERVICE_METHOD_WEIGHTS: Final[tuple[float, ...]] = (0.620, 0.330, 0.030, 0.020, 0.000)
_SERVICE_UPLOAD_METHOD_WEIGHTS: Final[tuple[float, ...]] = (0.220, 0.200, 0.030, 0.550, 0.000)
_SERVICE_OK_CODES: Final[tuple[int, ...]] = (200, 201, 204, 206)
_SERVICE_OK_WEIGHTS: Final[tuple[float, ...]] = (0.90, 0.05, 0.04, 0.01)
_SERVICE_ERROR_CODES: Final[tuple[int, ...]] = (400, 401, 429, 500, 503)
_SERVICE_ERROR_WEIGHTS: Final[tuple[float, ...]] = (0.15, 0.20, 0.25, 0.25, 0.15)

# (prefix, suffix) around an integer, per kind. Concatenation beats `str.format` by enough to
# matter at two million rows.
_PATHS: Final[tuple[tuple[tuple[str, str], ...], ...]] = (
    (("/", ""), ("/index.html", ""), ("/home", ""), ("/products/", ""), ("/articles/", "")),
    (("/static/js/app.", ".js"), ("/assets/bundle.", ".js"), ("/cdn/lib/", ".min.js")),
    (("/img/", ".png"), ("/assets/img/", ".jpg"), ("/static/media/", ".webp")),
    (("/api/v1/items?id=", ""), ("/api/v2/sync?cursor=", ""), ("/graphql?op=", ""), ("/v1/e/", "")),
    (("/watch?v=", ""), ("/media/stream/", ".m3u8")),
    (("/files/", ".zip"), ("/download/", ".pkg"), ("/releases/", ".tar.gz")),
)
_SERVICE_PATHS: Final[tuple[tuple[str, str], ...]] = (
    ("/api/v1/objects/", ""),
    ("/api/v2/batch?page=", ""),
    ("/v1/metrics/", ""),
    ("/v1/logs?offset=", ""),
    ("/buckets/data/", ".json"),
    ("/sync/records/", ""),
)

# Human principals who legitimately shell out to curl. Deliberately small: the L1 non-browser-UA
# rule has to stay usable, and near-miss behaviour belongs in scenario 10.
_AUTOMATION_DEPARTMENTS: Final[frozenset[str]] = frozenset({"Engineering", "IT"})
_UPLOAD_UA_FAMILIES: Final[frozenset[str]] = frozenset({"rclone", "aws-cli"})

# Zipf exponent over a user's own affinity list: they revisit a handful of sites constantly and
# the rest occasionally, the same shape as org-wide domain popularity but at personal scale.
_AFFINITY_EXPONENT: Final[float] = 0.7


def _cdf(weights: Sequence[float]) -> np.ndarray:
    arr = np.cumsum(np.asarray(weights, dtype=np.float64))
    arr /= arr[-1]
    arr[-1] = 1.0
    return arr


_STATUS_CDF: Final[np.ndarray] = _cdf(_STATUS_WEIGHTS)
_PAGE_KIND_CDF: Final[np.ndarray] = _cdf(_PAGE_KIND_WEIGHTS)
_SUB_KIND_CDF: Final[np.ndarray] = _cdf(_SUB_KIND_WEIGHTS)
_METHOD_CDF: Final[np.ndarray] = np.vstack([_cdf(row) for row in _METHOD_WEIGHTS])
_SERVICE_METHOD_CDF: Final[np.ndarray] = _cdf(_SERVICE_METHOD_WEIGHTS)
_SERVICE_UPLOAD_METHOD_CDF: Final[np.ndarray] = _cdf(_SERVICE_UPLOAD_METHOD_WEIGHTS)
_SERVICE_OK_CDF: Final[np.ndarray] = _cdf(_SERVICE_OK_WEIGHTS)
_SERVICE_ERROR_CDF: Final[np.ndarray] = _cdf(_SERVICE_ERROR_WEIGHTS)

# Vectorised views of the parameters `ResponseSizeModel` publishes. The scalar API would cost
# two million Python calls; reading its own tables keeps one definition of the distribution.
_RESP_MU: Final[np.ndarray] = np.array(
    [ResponseSizeModel.RESPONSE_PARAMS[k][0] for k in KINDS], dtype=np.float64
)
_RESP_SIGMA: Final[np.ndarray] = np.array(
    [ResponseSizeModel.RESPONSE_PARAMS[k][1] for k in KINDS], dtype=np.float64
)
_REQ_MU: Final[np.ndarray] = np.array(
    [ResponseSizeModel.REQUEST_PARAMS[m][0] for m in METHODS], dtype=np.float64
)
_REQ_SIGMA: Final[np.ndarray] = np.array(
    [ResponseSizeModel.REQUEST_PARAMS[m][1] for m in METHODS], dtype=np.float64
)


def _pick(u: np.ndarray, cdf: np.ndarray) -> np.ndarray:
    return np.searchsorted(cdf, u)


def _pick_rows(u: np.ndarray, cdfs: np.ndarray, rows: np.ndarray) -> np.ndarray:
    """Inverse-CDF pick where each element uses the row selected by `rows`."""
    return (u[:, None] > cdfs[rows]).sum(axis=1)


def _apportion(weights: Sequence[float], total: int) -> list[int]:
    """Largest-remainder split of `total` across `weights`. Integer-exact, no RNG, no drift."""
    mass = float(sum(weights))
    if mass <= 0 or total <= 0:
        return [0] * len(weights)
    exact = [total * (w / mass) for w in weights]
    counts = [int(x) for x in exact]
    remainder = total - sum(counts)
    if remainder:
        order = sorted(range(len(weights)), key=lambda i: (-(exact[i] - counts[i]), i))
        for i in order[:remainder]:
            counts[i] += 1
    return counts


# ---------------------------------------------------------------------------- phase 2 detection
# fields (this task, docs/v1/zscaler-nss-web-fields.md "SSL/TLS", "Server Connection", "Sandbox",
# "Network", "Threat Protection"). Mostly-benign defaults live here; the malicious profile
# (stable JA4 across rotating domains, self-signed short-validity cert, a reused malware hash) is
# injected by the scenario modules that need it via `extra={...}` on `build_event`/`inject`, not
# here -- see `s01_c2_beaconing.py`/`s09_multi_domain_c2_failover.py`.

# ISO 3166-1 alpha-2 -> full country name, for the office countries `OFFICE_CATALOG`
# (`datagen.realism`) actually uses -- `srcip_country`/`dstip_country`'s own documented examples
# ("Afghanistan", "Portugal") are full names, not codes.
_COUNTRY_NAME_BY_ISO2: Final[dict[str, str]] = {
    "US": "United States",
    "IE": "Ireland",
    "GB": "United Kingdom",
    "DE": "Germany",
    "SG": "Singapore",
    "IN": "India",
    "AU": "Australia",
    "JP": "Japan",
    "CA": "Canada",
}

# Countries the benign path never routes through. Exported (this task) so
# `s09_multi_domain_c2_failover.py` can give its C2 infrastructure a risky-jurisdiction
# destination -- `is_dst_cntry_risky = Yes` is otherwise never produced anywhere in this corpus,
# benign or malicious, which would make it an untestable field.
RISKY_COUNTRIES: Final[tuple[str, ...]] = ("Russia", "North Korea", "Iran")

# Most enterprise TLS-inspecting proxies inspect the large majority of HTTPS traffic; the
# uninspected minority is real (M365/UCaaS bypass categories, `docs/v1/zscaler-nss-web-fields.md`
# `%s{externalspr}`'s own examples), not a generator artifact.
_SSL_NOT_INSPECTED_RATE: Final[float] = 0.05
_CERT_VALIDITY_PERIODS: Final[tuple[str, ...]] = (
    "Short (0-3 months)",
    "Medium (3-12 months)",
    "Long (More than 12 months)",
)
# Legit, long-lived sites skew long/medium-validity; a short-validity cert on otherwise-normal
# traffic is rare (Let's Encrypt 90-day certs on smaller sites) but not zero.
_CERT_VALIDITY_WEIGHTS: Final[tuple[float, ...]] = (0.05, 0.35, 0.60)
_CERT_VALIDITY_CDF: Final[np.ndarray] = _cdf(_CERT_VALIDITY_WEIGHTS)

_FILETYPES: Final[tuple[str, ...]] = ("PDF Documents", "Office Documents", "Images", "Archive")
_FILETYPE_WEIGHTS: Final[tuple[float, ...]] = (0.35, 0.30, 0.25, 0.10)
_FILETYPE_CDF: Final[np.ndarray] = _cdf(_FILETYPE_WEIGHTS)
# Share of "download"-kind requests that populate `filetype` at all -- most download-shaped
# requests in the benign corpus are images/scripts pulled as page sub-resources, not the small
# minority that are genuinely a document/archive download File Type Control would classify.
_FILETYPE_POPULATED_RATE: Final[float] = 0.35
# Of those, an even smaller share get a `sha256`/`bamd5` pair -- Sandbox only hashes files it
# actually submitted for analysis, not every download.
_FILE_HASH_RATE: Final[float] = 0.08


def _country_for_office(office_country_iso2: str) -> str:
    return _COUNTRY_NAME_BY_ISO2.get(office_country_iso2, office_country_iso2)


@lru_cache(maxsize=16384)
def _dst_country_for(domain: str) -> str:
    """Stable per destination domain, same `stable_hash`-keyed-cache discipline as
    `categorize`/`server_ip` above -- a real site's hosting country does not change request to
    request. Weighted toward the USA (where most of `_SERVER_ANCHORS`' real-world CDN/cloud
    ranges actually sit) with a long tail of other major hosting markets, so `n_unique_countries`
    (docs/04 L3 "Device" family) has real variance to measure in the benign corpus."""
    pool = ("United States",) * 6 + ("Ireland", "Germany", "Singapore", "Japan", "United Kingdom")
    return pool[stable_hash(f"{domain}|dst-country") % len(pool)]


@lru_cache(maxsize=16384)
def _cert_posture(domain: str) -> tuple[str, str]:
    """`(srvcertvalidityperiod, srvocspresult)` for one domain, stable per domain -- a real site's
    certificate doesn't change validity bucket or OCSP status request to request. `srvocspresult`
    is `Good` for the entire benign path; `Revoked` is reserved for a scenario that wants it,
    never produced here (a revoked-but-still-served certificate is itself an attack/
    misconfiguration signal, not benign background noise)."""
    idx = int(
        np.searchsorted(_CERT_VALIDITY_CDF, (stable_hash(f"{domain}|cert") % 10_000) / 10_000)
    )
    return _CERT_VALIDITY_PERIODS[idx], "Good"


def _ja4_fingerprint(cohort_key: str) -> str:
    """A deterministic, JA4-shaped fingerprint (`t13d190900_<12 hex>_<12 hex>`, matching the
    PDF's own example format) for a given cohort key. Real JA4 hashes a client's actual TLS
    ClientHello (protocol version, cipher list order, extension list, ALPN); this generator has no
    real TLS handshake to hash, so it derives a stable fingerprint per cohort from `stable_hash`
    instead -- the same cohort (e.g. `"Chrome|Windows"`, or one implant's own identity string)
    always produces the same fingerprint, because a real browser+OS combination's TLS stack -- or
    a real implant's TLS library -- does not change request to request; different cohorts produce
    different fingerprints with overwhelming probability. This one primitive is what makes both
    "many users on the same browser/OS share one JA4" (benign clustering, realistic: a JA4 is a
    function of the TLS library, not the individual) and "one C2 implant keeps one stable JA4
    across its whole rotating-domain campaign" (the cross-tenant detection signal this task's
    Phase 2 design note calls out for `ja4_str`) fall out of the same code path."""
    a = stable_hash(cohort_key) & 0xFFFFFFFFFFFF
    b = stable_hash(f"{cohort_key}|ja4b") & 0xFFFFFFFFFFFF
    return f"t13d190900_{a:012x}_{b:012x}"


def _threat_severity(riskscore: int) -> str:
    """docs/v1/zscaler-nss-web-fields.md `%s{threatseverity}`'s own documented bucketing of
    `%d{riskscore}`: Critical 90-100, High 75-89, Medium 46-74, Low 1-45, None 0. Computed
    directly from the same `riskscore` this emitter already assigns per event -- unlike the
    sparse fields above, every real transaction gets *some* threatseverity value, so this is not
    gated on any other field the way `filetype`/file hashes are."""
    if riskscore <= 0:
        return "None"
    if riskscore >= 90:
        return "Critical"
    if riskscore >= 75:
        return "High"
    if riskscore >= 46:
        return "Medium"
    return "Low"


def _fake_hash(seed: str, length: int) -> str:
    """A stable, hex-digit-shaped placeholder hash of the requested length -- not a real SHA-256/
    MD5 of any actual file content (there is no real file here to hash), same "shaped like the
    real thing, not computed from it" discipline `_device_profile`'s `device_name` already uses
    for its own hash-suffixed identifier."""
    digits = f"{stable_hash(seed):x}" * 8
    return digits[:length]


# ---------------------------------------------------------------------------- full-width catalogue
#
# The rest of docs/v1/zscaler-nss-web-fields.md (this task) — ~130 more fields, catalogued but not
# parsed (module docstring, `FIELDS`'s own comment block). Every value below is *derived* from a
# field already set on `fields` (or from `ts`/`client_ip`/`company`/`cloudname`/`device_profile`/
# `seed`, the only extra inputs `_apply_wide_fields` takes) rather than drawn independently — the
# whole point of this section is that a reviewer who greps two of these columns finds them
# agreeing, not contradicting each other. `seed` is *reused* per-event entropy the caller already
# has (`path_seeds[i]`/`seed_l[i]` in the two benign batch loops, a `stable_hash` of the event's
# own timestamp+host+url in `inject`), not a fresh draw — `_mix` below decorrelates *across
# fields* from that one integer via cheap arithmetic (no `hashlib` call per field), which matters
# at ~2M benign events.
#
# Every assignment goes through `fields.setdefault`: a scenario's `extra={...}` (e.g. the C2
# implant's `is_sslselfsigned`/`srvcertvalidityperiod` block) always wins over this function's
# generic default, exactly like the wired Phase-2 fields already behave.


def _mix(seed: int, salt: int) -> int:
    """Cheap, deterministic decorrelation of one per-event `seed` across many field draws —
    splitmix64-style integer mixing, no hashing. `seed` alone would make every field in this
    section move in lockstep (e.g. `alpnprotocol` and `srvwildcardcert` would flip together on
    the same events); a distinct integer `salt` per field call site breaks that correlation for
    the cost of a few multiplications instead of a `hashlib.blake2b` call."""
    x = (seed ^ (salt * 0x9E3779B97F4A7C15)) & 0xFFFFFFFFFFFFFFFF
    x = (x ^ (x >> 33)) * 0xFF51AFD7ED558CCD & 0xFFFFFFFFFFFFFFFF
    x = (x ^ (x >> 29)) * 0xC4CEB9FE1A85EC53 & 0xFFFFFFFFFFFFFFFF
    return x ^ (x >> 32)


def _frac(seed: int, salt: int) -> float:
    """`[0, 1)` from `_mix`, for weighted-draw thresholds below."""
    return (_mix(seed, salt) % 1_000_000) / 1_000_000.0


def _cdf_tuple(weights: Sequence[float]) -> tuple[float, ...]:
    """Plain-Python cumulative distribution, no numpy array allocation — `_band` below is called
    several times per event over pools of 2-4 items, where numpy's fixed per-call overhead costs
    more than it saves at that size (unlike the vectorised `_STATUS_CDF`-style tables above, which
    apply to whole-batch arrays)."""
    total = sum(weights)
    cum: list[float] = []
    running = 0.0
    for w in weights:
        running += w
        cum.append(running / total)
    cum[-1] = 1.0
    return tuple(cum)


def _band(seed: int, salt: int, pool: Sequence[str], cdf: Sequence[float]) -> str:
    u = _frac(seed, salt)
    for i, edge in enumerate(cdf):
        if u < edge:
            return pool[i]
    return pool[-1]


# Day-of-week / month-name tables — hand-rolled, not `strftime`, same locale-independence
# discipline `_format_ts` already uses for the ISO `datetime` field.
_WEEKDAY_NAMES: Final[tuple[str, ...]] = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTH_NAMES: Final[tuple[str, ...]] = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)  # fmt: skip


def _derive_datetime_tokens(ts: datetime) -> dict[str, str]:
    """The eleven Date/Time catalogue fields, all read off one `datetime.timestamp` -- so `time`/
    `ss`/`mm`/`hh`/`dd`/`mth`/`yyyy`/`mon`/`day`/`epochtime` can never disagree with each other or
    with the `datetime` field they all derive from the same way. `tz` is the constant "GMT"
    (docs/v1/zscaler-nss-web-fields.md's own example) -- the NSS feed's configured display zone,
    not a per-event value; this generator's own clock is UTC throughout (`_format_ts`)."""
    if ts.tzinfo is not UTC:
        ts = ts.astimezone(UTC)
    weekday, month = _WEEKDAY_NAMES[ts.weekday()], _MONTH_NAMES[ts.month - 1]
    return {
        "time": f"{weekday} {month} {ts.day:02d} {ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} "
        f"{ts.year:04d}",
        "tz": "GMT",
        "ss": f"{ts.second:02d}",
        "mm": f"{ts.minute:02d}",
        "hh": f"{ts.hour:02d}",
        "dd": f"{ts.day:02d}",
        "mth": f"{ts.month:02d}",
        "yyyy": f"{ts.year:04d}",
        "mon": month,
        "day": weekday,
        "epochtime": str(int(ts.timestamp())),
    }


# Data Center: one plausible ZScaler Public Service Edge per office country — a deployment fact
# (which PoP serves this office), not a per-event draw. Keyed off `srcip_country`'s own full-name
# vocabulary (`_COUNTRY_NAME_BY_ISO2`) so it is always consistent with the country that field
# already reports.
_DATA_CENTER_BY_COUNTRY: Final[dict[str, tuple[str, str, str]]] = {
    "United States": ("US Client Node DC", "San Jose", "United States"),
    "Ireland": ("EU Client Node DC", "Dublin", "Ireland"),
    "United Kingdom": ("UK Client Node DC", "London", "United Kingdom"),
    "Germany": ("EU Client Node DC", "Frankfurt", "Germany"),
    "Singapore": ("APAC Client Node DC", "Singapore", "Singapore"),
    "Japan": ("APAC Client Node DC", "Tokyo", "Japan"),
}
_DEFAULT_DATA_CENTER: Final[tuple[str, str, str]] = _DATA_CENTER_BY_COUNTRY["United States"]

_FT_CLASS_BY_TYPE: Final[dict[str, tuple[str, str]]] = {
    "PDF Documents": ("Productivity Files", "pdf"),
    "Office Documents": ("Productivity Files", "docx"),
    "Images": ("Multimedia Files", "jpg"),
    "Archive": ("Archive Files", "zip"),
    "Archive Files": ("Archive Files", "7z"),
    "Windows Executables": ("Executables", "exe"),
}

_TLS_VERSIONS: Final[tuple[str, ...]] = ("TLS1_1", "TLS1_2", "TLS1_3")
_TLS_VERSION_CDF: Final[tuple[float, ...]] = _cdf_tuple((0.01, 0.34, 0.65))
_TLS13_CIPHERS: Final[tuple[str, ...]] = (
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
)  # fmt: skip
_TLS12_CIPHERS: Final[tuple[str, ...]] = (
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
)  # fmt: skip
_SESS_REUSE_VALUES: Final[tuple[str, ...]] = ("Yes", "No", "Unknown")
_SESS_REUSE_CDF: Final[tuple[float, ...]] = _cdf_tuple((0.60, 0.35, 0.05))
_KEYEX_ALGS: Final[tuple[str, ...]] = ("X25519", "secp256r1")
_SIG_ALGS: Final[tuple[str, ...]] = ("rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256")
_CERT_VALIDATION_TYPES: Final[tuple[str, ...]] = ("DV", "OV", "EV")
_CERT_VALIDATION_CDF: Final[tuple[float, ...]] = _cdf_tuple((0.85, 0.12, 0.03))
_NOT_INSPECTED_REASONS: Final[tuple[str, ...]] = (
    "Not inspected because of client non-browser traffic",
    "Not inspected because of trusted cert-pinned application",
    "Not inspected because of exempted URL category",
)
_URLCLASS_BY_SUPERCATEGORY: Final[dict[str, str]] = {
    "Security": "Privacy Risk",
    "Social and Entertainment": "Bandwidth Loss",
    "Shopping and Auctions": "Bandwidth Loss",
}
_CONTENT_TYPE_BY_EXT: Final[dict[str, str]] = {
    "js": "application/javascript",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
    "zip": "application/zip",
    "pkg": "application/octet-stream",
    "gz": "application/gzip",
    "m3u8": "application/vnd.apple.mpegurl",
    "json": "application/json",
    "html": "text/html",
}
# Consumer-facing cloud/policy category names a security-relevant Sanctioned/Unsanctioned verdict
# actually applies to — matches the same `policy_blockable` categories `_policy_blocked` already
# treats as "the kind of destination URL filtering has an opinion about" (module docstring).
_UNSANCTIONED_SUPERCATEGORIES: Final[frozenset[str]] = frozenset(
    {"Social and Entertainment", "Shopping and Auctions", "Sports"}
)


def _uaclass_and_token(ua: str) -> tuple[str, str]:
    """`(uaclass, ua_token)` from the already-generated `useragent` string -- no new parameter,
    since the family is recoverable from the UA itself the same way a real NSS feed's own
    classifier would read it. Order matters: a Chrome-derived UA (Edge, and Chrome itself) also
    contains the literal substring `Safari/`, so `Safari` must be checked last."""
    if "Edg/" in ua:
        return "Edge", "Microsoft Edge (0.x)"
    if "Chrome/" in ua and "Chromium" not in ua:
        return "Chrome", "Google Chrome (0.x)"
    if "Firefox/" in ua:
        return "Firefox", "Firefox (0.x)"
    if "Safari/" in ua:
        return "Safari", "Safari (0.x)"
    token = ua.split("/", 1)[0].strip() or "Other"
    return "Other", f"{token} (0.x)"


def _hostname_from(url_like: str | None) -> str | None:
    if not url_like:
        return None
    return url_like.split("://", 1)[-1].split("/", 1)[0] or None


def _content_type_for(url: str) -> str:
    path = url.split("?", 1)[0]
    tail = path.rsplit("/", 1)[-1]
    if "." in tail:
        ext = tail.rsplit(".", 1)[-1].lower()
        if ext in _CONTENT_TYPE_BY_EXT:
            return _CONTENT_TYPE_BY_EXT[ext]
    if "api" in path or "graphql" in path:
        return "application/json"
    return "text/html"


def _org_company_name(org_name: str) -> str:
    """`%s{company}` from `Org.name` — the labeled-corpus splits name their orgs in lowercase
    (`"northwind"`, `"contoso"`, `"fabrikam"`, docs/11), which reads oddly as a company name on
    the wire; title-case only kicks in when the name has no uppercase of its own, so the default
    `Org(name="Northwind Trading")` passes through unchanged."""
    return org_name if any(c.isupper() for c in org_name) else org_name.title()


def _org_cloudname(email_domain: str) -> str:
    """`%s{cloudname}` — a per-tenant Zscaler cloud name, derived from the org's own email domain
    (`"northwind.example"` -> `"northwind.zscaler.net"`) rather than a shared literal constant, so
    it stays internally consistent with `login`/`user`'s own domain instead of contradicting it."""
    return f"{email_domain.split('.', 1)[0]}.zscaler.net"


def _apply_wide_fields(
    fields: dict[str, Any],
    *,
    ts: datetime,
    client_ip: str | None,
    company: str,
    cloudname: str,
    device_profile: DeviceProfile,
    seed: int,
) -> None:
    """Fill every full-width catalogue field onto `fields`, via `setdefault` throughout so a
    scenario's own `extra={...}` always wins (see the section docstring above)."""
    for key, value in _derive_datetime_tokens(ts).items():
        fields.setdefault(key, value)

    fields.setdefault("company", company)
    fields.setdefault("cloudname", cloudname)

    # Network: `cip`/`cintip`/`cpubip` are documented as "same address unless an additional
    # internal-NAT hop is visible" -- this generator models exactly one client-visible address per
    # event (`client_ip`, already either an office egress or a home broadband IP, both already
    # "public-looking" per `org.py`/`realism.py`'s own TEST-NET/consumer-ISP addressing), so there
    # is no second, more-internal hop for `cintip` to reveal and no separate NAT layer for
    # `cpubip` to differ across -- all three are the same value here, which is the documented
    # degenerate case, not an omission.
    fields.setdefault("cintip", client_ip)
    fields.setdefault("cpubip", client_ip)
    fields.setdefault("clt_sport", str(1024 + _mix(seed, 1) % 64511))
    fields.setdefault("srv_dport", "443")
    fields.setdefault("proto", "HTTP")
    fields.setdefault("alpnprotocol", "h2" if _frac(seed, 2) < 0.70 else "http/1.1")
    device_present = device_profile.hostname is not None
    fields.setdefault(
        "trafficredirectmethod", "Zscaler Client Connector" if device_present else "PAC"
    )
    # `userlocationname`: Zero Trust Browser origination point -- this org never routes through
    # one, so always `None` (this task's own explicit requirement: "None unless Zero Trust
    # Browser").
    fields.setdefault("userlocationname", None)

    # Bandwidth Control: never throttled in this corpus -- a deliberate simplification (like
    # `srvocspresult`'s "always Good in benign" above), not a per-tenant policy this generator
    # models. `bwthrottle == "No"` and both throttled-size fields at `0` is the only internally
    # consistent combination, so this can never contradict itself.
    fields.setdefault("bwthrottle", "No")
    fields.setdefault("throttlereqsize", "0")
    fields.setdefault("throttlerespsize", "0")
    fields.setdefault("txn_delay_req", str(5 + _mix(seed, 3) % 30))
    fields.setdefault("txn_delay_resp", str(8 + _mix(seed, 4) % 40))

    # Cloud Application
    appname = fields.get("appname")
    is_cloud_app = appname not in (None, "General Browsing")
    riskscore = int(fields.get("riskscore") or 0)
    urlsupercategory = fields.get("urlsupercategory")
    if is_cloud_app:
        fields.setdefault("app_risk_score", str(max(1, min(5, 1 + riskscore // 25))))
        method = fields.get("requestmethod")
        url = str(fields.get("url") or "")
        download_ext = url.split("?", 1)[0].rsplit(".", 1)[-1].lower()
        if method == "POST":
            fields.setdefault("activity", "Upload")
        elif download_ext in {"zip", "pkg", "gz", "exe"}:
            fields.setdefault("activity", "Download")
        else:
            fields.setdefault("activity", "View")
        fields.setdefault("app_status", "Sanctioned")
    else:
        fields.setdefault(
            "app_status",
            "Unsanctioned" if urlsupercategory in _UNSANCTIONED_SUPERCATEGORIES else "N/A",
        )
    # `inst_level*` (cloud-console org/project/resource identity): only meaningful for an actual
    # console session, and only a minority of even those calls carry it — most AWS Console
    # traffic in this corpus is ordinary page/API traffic, not a resource-scoped console action.
    if fields.get("host") == "amazonaws.com" and _frac(seed, 5) < 0.20:
        acct = 100_000_000_000 + _mix(seed, 6) % 900_000_000_000
        fields.setdefault("inst_level1_type", "ORG")
        fields.setdefault("inst_level1_id", f"o-{_mix(seed, 7) % 10**10:010d}")
        fields.setdefault("inst_level1_name", f"{company.lower()}-org")
        fields.setdefault("inst_level2_type", "ACCOUNT")
        fields.setdefault("inst_level2_id", str(acct))
        fields.setdefault("inst_level2_name", f"{company.lower()}-prod")
        fields.setdefault("inst_level3_type", "RESOURCE_TYPE")
        fields.setdefault("inst_level3_id", "S3")
    # `prompt_req`/`prompt_class` never populated: no generative-AI SaaS app is in `org.py`'s
    # `DEFAULT_SAAS_APPS` catalogue, so there is no traffic this field could honestly describe —
    # and log content is untrusted, attacker-controllable input (CLAUDE.md rule 3); fabricating a
    # plausible-looking prompt string here would be inventing exactly the kind of data that
    # shouldn't be synthesized without a real source behind it.

    # Data Center
    dc = _DATA_CENTER_BY_COUNTRY.get(str(fields.get("srcip_country")), _DEFAULT_DATA_CENTER)
    fields.setdefault("datacenter", dc[0])
    fields.setdefault("datacentercity", dc[1])
    fields.setdefault("datacentercountry", dc[2])

    # Data Loss Prevention
    dlpdictionaries = fields.get("dlpdictionaries")
    if dlpdictionaries:
        names = [n.strip() for n in str(dlpdictionaries).split(",") if n.strip()]
        fields.setdefault("dlpdict", "|".join(names))
        fields.setdefault(
            "dlpdicthitcount",
            "|".join(str(1 + _mix(seed, 8 + i) % 9) for i in range(len(names))),
        )
        fields.setdefault("dlpmd5", _fake_hash(f"{seed}|dlpmd5", 32))
        # `dlpidentifier` XOR `exempt_dlpidentifier` — the doc is explicit these never co-occur
        # (one is "not populated if the other is").
        dlp_id = str(6_000_000_000_000_000_000 + _mix(seed, 9) % 900_000_000_000_000_000)
        if _frac(seed, 10) < 0.10:
            fields.setdefault("exempt_dlpidentifier", dlp_id)
        else:
            fields.setdefault("dlpidentifier", dlp_id)
        fields.setdefault("trig_dlprulename", "DLP_Rule_1")
        if fields.get("action") == "Allowed":
            fields.setdefault("dlprulename", "DLP_Rule_1")
        fields.setdefault("all_dlprulenames", "[DLP_Rule_1]")
        fields.setdefault("other_dlprulenames", "[]")
        fields.setdefault("dlp_policy_action", "Incident Reported")
    # `extranet_name`/`dlp_confirm_justification_msg` never populated: no extranet resource and no
    # Confirm-action DLP rule is modeled in this corpus.

    # File Type Control
    filetype = fields.get("filetype")
    if filetype:
        fileclass, ext = _FT_CLASS_BY_TYPE.get(filetype, ("Uncategorized", "bin"))
        fields.setdefault("fileclass", fileclass)
        fields.setdefault("filename", f"download_{seed}.{ext}")
        fields.setdefault("filesubtype", ext)
        fields.setdefault("ft_rulename", "File_Type_1")
    upload_filetype = fields.get("upload_filetype")
    if upload_filetype:
        upload_fileclass, uext = _FT_CLASS_BY_TYPE.get(upload_filetype, ("Uncategorized", "bin"))
        fields.setdefault("upload_fileclass", upload_fileclass)
        fields.setdefault("upload_filesubtype", uext)
        fields.setdefault("ft_rulename", "File_Type_1")
        if upload_fileclass == "Productivity Files":
            fields.setdefault("upload_doctypename", "Corporate Finance")
            fields.setdefault("upload_doc_sub_type", "Reports")

    # Forwarding Control
    is_zpa = fields.get("flow_type") == _FLOW_ZPA
    fields.setdefault("fwd_type", "ZPA" if is_zpa else "Direct")
    if is_zpa:
        seg = str(appname or "app").replace(" ", "_")
        fields.setdefault("zpa_app_seg_name", f"ZPA_{seg}_segment")
    # `rdr_rulename`/`fwd_gw_name`/`fwd_gw_ip` never populated: no forwarding-gateway chaining is
    # modeled (this corpus's traffic goes `Direct` or `ZPA`, never `Proxy Chaining`/`Drop`).

    # Policy — "Block rules only" fields (doc's own words), so `None` on anything Allowed.
    is_blocked = fields.get("action") == "Blocked"
    if is_blocked:
        is_dlp_block = bool(fields.get("dlpengine"))
        fields.setdefault("ruletype", "Data Loss Prevention" if is_dlp_block else "URL Filtering")
        rulelabel = "DLP_Block_1" if is_dlp_block else "URL_Filtering_1"
        fields.setdefault("rulelabel", rulelabel)
        if not is_dlp_block:
            fields.setdefault("urlfilterrulelabel", rulelabel)
    # `apprulelabel` never populated: no cloud-app-specific block rule is modeled.

    # SSL/TLS + Client/Server Connection — the client<->Zscaler and Zscaler<->server TLS legs both
    # only exist when the transaction is actually Client-Connector-proxied; `bypassed_traffic == 1`
    # traffic goes direct and never terminates on Zscaler's TLS stack at all.
    bypassed = int(fields.get("bypassed_traffic") or 0) == 1
    ssldecrypted = fields.get("ssldecrypted")
    if not bypassed:
        tlsver = _band(seed, 11, _TLS_VERSIONS, _TLS_VERSION_CDF)
        fields.setdefault("clienttlsversion", tlsver)
        fields.setdefault("srvtlsversion", tlsver)
        ciphers = _TLS13_CIPHERS if tlsver == "TLS1_3" else _TLS12_CIPHERS
        fields.setdefault("clientsslcipher", ciphers[_mix(seed, 12) % len(ciphers)])
        fields.setdefault("srvsslcipher", ciphers[_mix(seed, 13) % len(ciphers)])
        fields.setdefault(
            "clientsslsessreuse", _band(seed, 14, _SESS_REUSE_VALUES, _SESS_REUSE_CDF)
        )
        fields.setdefault(
            "serversslsessreuse", _band(seed, 15, _SESS_REUSE_VALUES, _SESS_REUSE_CDF)
        )
        fields.setdefault("cltsslfailcount", "0")
        hybrid = 1 if _frac(seed, 16) < 0.30 else 0
        fields.setdefault("client_tls_keyex_pqc_offers", "0")
        fields.setdefault("client_tls_keyex_non_pqc_offers", "1")
        fields.setdefault("client_tls_keyex_hybrid_offers", str(hybrid))
        fields.setdefault("client_tls_keyex_unknown_offers", "0")
        fields.setdefault("client_tls_sig_pqc_offers", "0")
        fields.setdefault("client_tls_sig_non_pqc_offers", "1")
        fields.setdefault("client_tls_sig_hybrid_offers", "0")
        fields.setdefault("client_tls_sig_unknown_offers", "0")
        keyex = "X25519MLKEM768" if hybrid else _KEYEX_ALGS[_mix(seed, 17) % len(_KEYEX_ALGS)]
        fields.setdefault("client_tls_keyex_alg", keyex)
        fields.setdefault("server_tls_keyex_alg", _KEYEX_ALGS[_mix(seed, 18) % len(_KEYEX_ALGS)])
        fields.setdefault("client_tls_sig_alg", _SIG_ALGS[_mix(seed, 19) % len(_SIG_ALGS)])
        fields.setdefault("server_tls_sig_alg", _SIG_ALGS[_mix(seed, 20) % len(_SIG_ALGS)])

        chain_fails = (
            fields.get("is_sslselfsigned") == "Yes" or fields.get("is_ssluntrustedca") == "Fail"
        )
        fields.setdefault("srvcertchainvalpass", "Fail" if chain_fails else "Pass")
        fields.setdefault("srvwildcardcert", "Yes" if _frac(seed, 21) < 0.15 else "No")
        fields.setdefault(
            "srvcertvalidationtype",
            _band(seed, 22, _CERT_VALIDATION_TYPES, _CERT_VALIDATION_CDF),
        )

        if ssldecrypted == "Yes":
            fields.setdefault("ssl_rulename", "SSL_Inspection_1")
            blocked_security = is_blocked and urlsupercategory == "Security"
            fields.setdefault("externalspr", "Blocked" if blocked_security else "Inspected")
            fields.setdefault("keyprotectiontype", "Software Protection")
        elif ssldecrypted == "No":
            fields.setdefault("ssl_rulename", "SSL_Bypass_1")
            fields.setdefault(
                "externalspr", _NOT_INSPECTED_REASONS[_mix(seed, 23) % len(_NOT_INSPECTED_REASONS)]
            )
    # `cltsslfailreason` never populated: no client handshake failures are modeled (benign path
    # always completes its TLS handshake).

    # Threat Protection
    threatcategory = fields.get("threatcategory")
    if threatcategory == "Botnet":
        fields.setdefault("malwareclass", "Botnet")
    elif fields.get("threatname"):
        fields.setdefault("malwareclass", "Malware")
    if fields.get("urlcategory") == "Phishing":
        fields.setdefault("ai_ml_detect_src", "AI/ML - ATP - Phishing")

    # URL Categorization
    fields.setdefault(
        "urlclass", _URLCLASS_BY_SUPERCATEGORY.get(urlsupercategory, "General Surfing")
    )
    urlcategory = fields.get("urlcategory")
    if urlcategory in ("Newly Registered and Revived Domains", "Miscellaneous or Unknown"):
        fields.setdefault("urlcatmethod", "AI/ML-based content categorization")
    else:
        fields.setdefault("urlcatmethod", "Database A" if _mix(seed, 24) % 2 == 0 else "Database B")

    # HTTP Transaction
    reqsize = int(fields.get("requestsize") or 0)
    respsize = int(fields.get("responsesize") or 0)
    reqhdrsize = min(reqsize, 150 + _mix(seed, 25) % 450)
    resphdrsize = min(respsize, 150 + _mix(seed, 26) % 750)
    fields.setdefault("reqhdrsize", str(reqhdrsize))
    fields.setdefault("reqdatasize", str(reqsize - reqhdrsize))
    fields.setdefault("resphdrsize", str(resphdrsize))
    fields.setdefault("respdatasize", str(respsize - resphdrsize))
    # `%d{totalsize}` = reqsize + respsize (this task's own explicit invariant); exact integer
    # arithmetic on the same two fields the emitter already agreed on `status`/`action` from, so
    # this can never drift out of consistency with them.
    fields.setdefault("totalsize", str(reqsize + respsize))
    fields.setdefault("reqversion", "1.1")
    fields.setdefault("respversion", "1.1")
    fields.setdefault("refererhost", _hostname_from(fields.get("referer")))
    ua = str(fields.get("useragent") or "")
    uaclass, ua_token = _uaclass_and_token(ua)
    fields.setdefault("uaclass", uaclass)
    fields.setdefault("ua_token", ua_token)
    fields.setdefault("contenttype", _content_type_for(str(fields.get("url") or "/")))

    # Miscellaneous
    fields.setdefault("recordid", str(_mix(seed, 27) % 10**12))
    fields.setdefault("productversion", "6.1.245.10021_01")
    fields.setdefault("nsssvcip", "10.10.102.30")
    fields.setdefault("eedone", "No")
    if int(fields.get("bypassed_traffic") or 0) == 1:
        fields.setdefault(
            "bypassed_etime", fields.get("time") or _derive_datetime_tokens(ts)["time"]
        )
    if fields.get("threatname"):
        fields.setdefault("pcapid", f"{_mix(seed, 28) % 90_000_000:08d}/web/{seed:016x}.pcap")


# ---------------------------------------------------------------------------- serialization


def _scrub(value: Any) -> str:
    if value is None:
        return EMPTY
    text = value if isinstance(value, str) else str(value)
    if not text:
        return EMPTY
    if "\t" in text or "\n" in text or "\r" in text:
        text = text.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text


def _format_ts(ts: datetime) -> str:
    if ts.tzinfo is not UTC:
        ts = ts.astimezone(UTC)
    return (
        f"{ts.year:04d}-{ts.month:02d}-{ts.day:02d}T{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}Z"
    )


def line_numbers(records: Iterable[EventRecord]) -> list[int]:
    """File line numbers of `records`, sorted ascending.

    Meaningful only after `assign_line_numbers`; before that every `line_no` is `None` and the
    result is empty. A scenario keeps the records `ScenarioContext.add` handed back and calls
    this to report where its injected events actually landed.
    """
    return sorted(r.line_no for r in records if r.line_no is not None)


# ---------------------------------------------------------------------------- emitter


@dataclass(slots=True)
class _Catalog:
    """Per-run org-derived lookups. Held here, not on the emitter, to keep the emitter reentrant."""

    app_by_domain: dict[str, SaasApp]
    category_by_domain: dict[str, UrlCategory]

    def category(self, domain: str) -> UrlCategory:
        cat = self.category_by_domain.get(domain)
        if cat is None:
            cat = categorize(domain)
            self.category_by_domain[domain] = cat
        return cat

    def appname(self, domain: str) -> str:
        app = self.app_by_domain.get(domain)
        return app.name if app else "General Browsing"


class ZScalerEmitter:
    """`LogEmitter` for the ZScaler NSS Web feed.

    The corpus-shaping rates are constructor keywords so a driver can vary them, but the defaults
    encode one deliberate position: **the benign corpus contains nothing that should trip an L1
    proxy rule.** No security categories, no direct-to-IP requests, no threat names, no uploads
    over the large-POST threshold. Policy blocks (streaming, social, shopping) are the exception —
    they are the dominant real-world source of `blocked_ratio` and none of them is a security
    verdict. `blocked_rate` is the share of policy-blockable *hosts* a principal is blocked from,
    not a per-request coin flip: URL filtering is a deterministic policy decision, and a host that
    flipped verdict between requests would make the "blocked then allowed to the same host within
    5m" rule fire on nearly every user in the clean corpus.
    """

    source: ClassVar[SourceType] = SourceType.ZSCALER
    file_suffix: ClassVar[str] = ".log"
    header_lines: ClassVar[int] = 1

    def __init__(
        self,
        *,
        blocked_rate: float = 0.12,
        automation_ua_rate: float = 0.002,
        novel_domain_rate: float = 0.08,
        rare_domain_rate: float = 0.02,
        mean_burst: float = 2.2,
        referer_rate: float = 0.55,
        service_error_rate: float = 0.015,
        service_download_rate: float = 0.15,
        interval_jitter_pct: float = 0.012,
    ) -> None:
        self.blocked_rate = blocked_rate
        self.automation_ua_rate = automation_ua_rate
        self.novel_domain_rate = novel_domain_rate
        self.rare_domain_rate = rare_domain_rate
        self.mean_burst = max(mean_burst, 1.0)
        self.referer_rate = referer_rate
        self.service_error_rate = service_error_rate
        self.service_download_rate = service_download_rate
        self.interval_jitter_pct = interval_jitter_pct

    # ------------------------------------------------------------------ format

    def header(self) -> str | None:
        return "\t".join(FIELDS)

    def serialize(self, record: EventRecord) -> str:
        fields = record.fields
        out: list[str] = []
        for name in FIELDS:
            value = fields.get(name)
            if value is None:
                value = self._default(name, record)
            out.append(_scrub(value))
        return "\t".join(out)

    def _default(self, name: str, record: EventRecord) -> Any:
        if name == "datetime":
            return _format_ts(record.ts)
        if name == "user":
            return record.principal
        if name == "clientip":
            return record.src_ip
        return _FIELD_DEFAULTS.get(name, EMPTY)

    def write_stream(self, records: Iterable[EventRecord], handle: TextIO) -> int:
        """Header plus one line per record. Returns physical lines written."""
        written = 0
        head = self.header()
        if head is not None:
            handle.write(head)
            handle.write("\n")
            written += 1
        for record in records:
            handle.write(self.serialize(record))
            handle.write("\n")
            written += 1
        return written

    # ------------------------------------------------------------------ scenario API

    def build_event(
        self,
        *,
        ts: datetime,
        principal: str,
        host: str,
        src_ip: str | None = None,
        url: str = "/",
        method: str = "GET",
        status: int = 200,
        bytes_out: int = 0,
        bytes_in: int = 0,
        user_agent: str | None = None,
        action: str | None = None,
        category: UrlCategory | str | None = None,
        appname: str | None = None,
        threatname: str | None = None,
        threatcategory: str | None = None,
        riskscore: int | None = None,
        reason: str | None = None,
        referer: str | None = None,
        dlpengine: str | None = None,
        dlpdictionaries: str | None = None,
        dst_ip: str | None = None,
        location: str | None = None,
        department: str | None = None,
        devicehostname: str | None = None,
        devicename: str | None = None,
        deviceostype: str | None = None,
        deviceosversion: str | None = None,
        deviceowner: str | None = None,
        bypassed_traffic: int | None = None,
        flow_type: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> EventRecord:
        """A crafted, fully-formed ZScaler record. Unlabelled — pass it to `ScenarioContext.add`.

        `category` accepts a `UrlCategory` or a key of `NAMED_CATEGORIES` (`"c2"`, `"malware"`,
        `"newly_registered"`, ...), so a scenario states the verdict it wants instead of
        hand-assembling three columns that have to agree.
        """
        cat = self._resolve_category(category, host)
        fields: dict[str, Any] = {
            "serverip": dst_ip or server_ip(host),
            "host": host,
            "url": url,
            "requestmethod": method,
            "status": status,
            "requestsize": int(bytes_out),
            "responsesize": int(bytes_in),
            "useragent": user_agent,
            "action": action or ("Blocked" if status == 403 else "Allowed"),
            "urlcategory": cat.name,
            "urlsupercategory": cat.supercategory,
            "appname": appname or "General Browsing",
            "appclass": cat.appclass,
            "riskscore": min(cat.risk if riskscore is None else int(riskscore), _MAX_RISK),
            "location": location,
            "department": department,
        }
        # Bug fix (this task): every other event-construction path in this module sets
        # `threatseverity` from the same `riskscore` it just assigned (`_threat_severity`,
        # docs/v1/zscaler-nss-web-fields.md's documented riskscore bands) — this one, the only
        # path every scenario-crafted event goes through (`inject` -> `build_event`), never did,
        # so a non-blended scenario setting `riskscore=98` (e.g. `s01_c2_beaconing`'s `_C2_THREAT`)
        # silently shipped `threatseverity=None` next to it. A reviewer grepping those two columns
        # on exactly that traffic would have found them contradicting each other.
        fields["threatseverity"] = _threat_severity(int(fields["riskscore"]))
        for key, value in (
            ("threatname", threatname),
            ("threatcategory", threatcategory),
            ("reason", reason),
            ("referer", referer),
            ("dlpengine", dlpengine),
            ("dlpdictionaries", dlpdictionaries),
            ("devicehostname", devicehostname),
            ("devicename", devicename),
            ("deviceostype", deviceostype),
            ("deviceosversion", deviceosversion),
            ("deviceowner", deviceowner),
            ("bypassed_traffic", bypassed_traffic),
            ("flow_type", flow_type),
        ):
            if value is not None:
                fields[key] = value
        if extra:
            fields.update(extra)
        return EventRecord(
            ts=ts, source=self.source, principal=principal, fields=fields, src_ip=src_ip
        )

    def inject(
        self,
        ctx: ScenarioContext,
        *,
        user: User,
        ts: datetime,
        host: str,
        src_ip: str | None = None,
        user_agent: str | None = None,
        malicious: bool = True,
        **kwargs: Any,
    ) -> EventRecord:
        """Build a crafted event for `user` and append it to the scenario's stream.

        Fills the principal-derived columns from the org so an injected event is
        indistinguishable from a benign one on every field the scenario is not deliberately
        manipulating — the alternative is a scenario that is detectable because it forgot a
        column, which would make the eval measure nothing.
        """
        kwargs.setdefault("location", user.office.code)
        kwargs.setdefault("department", user.department)
        # Device fields (this task): an injected/malicious event still comes from the user's own
        # device — dropping them here would make every scenario-injected event a silent exception
        # to "indistinguishable from a benign one on every field the scenario isn't deliberately
        # manipulating" (this method's own docstring), and would starve the asset-tag bank of the
        # one thing it exists to support: tagging *incidents* (which are formed from exactly this
        # injected traffic) by device.
        profile = _device_profile(user)
        if profile.hostname is not None:
            kwargs.setdefault("devicehostname", profile.hostname)
            kwargs.setdefault("devicename", profile.device_name)
            kwargs.setdefault("deviceostype", profile.os_type)
            kwargs.setdefault("deviceowner", profile.owner)
            if profile.os_version is not None:
                kwargs.setdefault("deviceosversion", profile.os_version)
        kwargs.setdefault("flow_type", _FLOW_DIRECT if user.is_service_account else _FLOW_ZIA)
        kwargs.setdefault("bypassed_traffic", 0)
        record = self.build_event(
            ts=ts,
            principal=user.principal,
            host=host,
            src_ip=src_ip or user.office_ip,
            user_agent=user_agent or user.device.user_agent,
            **kwargs,
        )
        # Full-width catalogue fields (this task) — every scenario-injected event goes through
        # this one call site, so wiring it in here (rather than in each of the ten scenario
        # modules) is what keeps a malicious event "indistinguishable... on every field the
        # scenario is not deliberately manipulating" (this method's own docstring, above) true for
        # the ~130 catalogued-only fields too, not just the 52 the parser reads.
        _apply_wide_fields(
            record.fields,
            ts=ts,
            client_ip=record.src_ip,
            company=_org_company_name(ctx.org.name),
            cloudname=_org_cloudname(ctx.org.email_domain),
            device_profile=profile,
            seed=stable_hash(f"{ts.isoformat()}|{host}|{record.fields.get('url', '')}"),
        )
        return ctx.add(record, malicious=malicious)

    def _resolve_category(self, category: UrlCategory | str | None, host: str) -> UrlCategory:
        if isinstance(category, UrlCategory):
            return category
        if isinstance(category, str):
            named = NAMED_CATEGORIES.get(category)
            if named is None:
                raise KeyError(f"unknown category {category!r}; known: {sorted(NAMED_CATEGORIES)}")
            return named
        return categorize(host)

    # ------------------------------------------------------------------ benign corpus

    def generate_benign(self, ctx: BenignContext) -> Iterator[EventRecord]:
        catalog = self._catalog(ctx)
        principals = ctx.org.principals
        counts = _apportion([float(u.events_per_day) for u in principals], ctx.n_events)
        for user, count in zip(principals, counts, strict=True):
            if count <= 0:
                continue
            rng = ctx.user_rng(user)
            if user.is_service_account:
                yield from self._service_traffic(ctx, catalog, user, rng, count)
            else:
                yield from self._human_traffic(ctx, catalog, user, rng, count)

    def _catalog(self, ctx: BenignContext) -> _Catalog:
        return _Catalog(
            app_by_domain={app.domain: app for app in ctx.org.saas_apps},
            category_by_domain={
                app.domain: _SAAS_CATEGORY.get(app.category, categorize(app.domain))
                for app in ctx.org.saas_apps
            },
        )

    def _human_traffic(
        self, ctx: BenignContext, catalog: _Catalog, user: User, rng: SeededRandom, n: int
    ) -> Iterator[EventRecord]:
        automation_ua: str | None = None
        if self._automation_eligible(user):
            automation_ua = ctx.models.user_agents.sample_automation(
                rng.fresh("automation-ua")
            ).user_agent
        remaining = n
        while remaining > 0:
            size = min(remaining, _BATCH)
            yield from self._human_batch(ctx, catalog, user, rng, size, automation_ua)
            remaining -= size

    def _human_batch(
        self,
        ctx: BenignContext,
        catalog: _Catalog,
        user: User,
        rng: SeededRandom,
        n: int,
        automation_ua: str | None,
    ) -> Iterator[EventRecord]:
        models = ctx.models
        window = ctx.window
        np_rng = rng.np

        # A page load is one document plus its sub-resources, all to the same host within a few
        # seconds. Independent arrivals would leave `burstiness` and `iat_cv` nothing to see and
        # would hand the beaconing detector a trivially discriminative regularity score.
        # Draw with a margin, then cut at the first page whose cumulative size reaches `n`, so the
        # batch overshoots by less than one cluster instead of falling short of the requested count.
        pages = math.ceil(n / self.mean_burst * 1.15) + 16
        sizes = np.minimum(1 + np_rng.poisson(self.mean_burst - 1.0, pages), 8).astype(np.int64)
        sizes = sizes[: min(int(np.searchsorted(np.cumsum(sizes), n, side="left")) + 1, pages)]
        pages = int(sizes.size)
        total = int(sizes.sum())

        page_ts = models.diurnal.sample_epoch_seconds(
            rng, window.start, window.end, user.work_hours, pages
        )
        ts = np.repeat(page_ts, sizes) + np_rng.random(total) * 4.0
        np.clip(ts, window.start.timestamp(), window.end.timestamp() - 1e-3, out=ts)

        page_domains = self._page_domains(models, rng, user, pages)
        page_cats = [catalog.category(d) for d in page_domains]
        remote = (np_rng.random(pages) < user.remote_ratio).tolist()

        is_first = np.zeros(total, dtype=bool)
        is_first[np.cumsum(sizes) - sizes] = True
        u_kind = np_rng.random(total)
        kind_idx = np.where(is_first, _pick(u_kind, _PAGE_KIND_CDF), _pick(u_kind, _SUB_KIND_CDF))
        method_idx = _pick_rows(np_rng.random(total), _METHOD_CDF, kind_idx)
        status_idx = _pick(np_rng.random(total), _STATUS_CDF)
        resp = np.clip(
            np_rng.lognormal(_RESP_MU[kind_idx], _RESP_SIGMA[kind_idx]), _MIN_BYTES, _MAX_BYTES
        )
        req = np.clip(
            np_rng.lognormal(_REQ_MU[method_idx], _REQ_SIGMA[method_idx]),
            _MIN_BYTES,
            _HUMAN_MAX_REQUEST_BYTES,
        )
        blocked = (
            np.fromiter(
                self._policy_blocked(user, page_domains, page_cats), dtype=bool, count=pages
            )
            .repeat(sizes)
            .tolist()
        )
        wants_referer = ((~is_first) & (np_rng.random(total) < self.referer_rate)).tolist()
        path_seeds = np_rng.integers(1, 1_000_000, size=total).tolist()
        automated = (
            (np_rng.random(total) < self.automation_ua_rate).tolist()
            if automation_ua is not None
            else [False] * total
        )

        hosts: list[str] = []
        cats: list[UrlCategory] = []
        ips: list[str] = []
        remote_flags: list[bool] = []
        home_ip, office_ip = user.home_geo.ip, user.office_ip
        for page, k in enumerate(sizes.tolist()):
            hosts.extend([page_domains[page]] * k)
            cats.extend([page_cats[page]] * k)
            ips.extend([home_ip if remote[page] else office_ip] * k)
            remote_flags.extend([remote[page]] * k)

        ts_l = ts.tolist()
        kind_l = kind_idx.tolist()
        method_l = method_idx.tolist()
        status_l = status_idx.tolist()
        resp_l = resp.astype(np.int64).tolist()
        req_l = req.astype(np.int64).tolist()
        browser_ua = user.device.user_agent
        location, department, principal = user.office.code, user.department, user.principal
        device_profile = _device_profile(user)
        # Flow type (docs/v1/zscaler-nss-web-fields.md `%s{flow_type}`): VPN for a remote page,
        # ZIA (Client Connector -> the ZIA cloud) for an office one, with a small deterministic
        # ZPA (private-app-access) override — reuses `path_seeds`, no new RNG draw. `bypassed`:
        # a small minority of transactions bypass the Client Connector (design brief: "most
        # traffic not bypassed, a small minority bypassed").
        bypassed = (np_rng.random(total) < _HUMAN_BYPASS_RATE).tolist()
        # Phase 2 detection fields (this task). `browser_ja4_cohort` is per-user-device, not
        # per-user: the same browser+OS combination always produces the same JA4 (see
        # `_ja4_fingerprint`'s own docstring), which is what makes "many users share a JA4"
        # realistic clustering rather than an artifact. `ssl_inspected`/`src_country` are
        # per-batch draws/values, not per-domain, so they live here rather than inside the loop.
        ssl_inspected = (np_rng.random(total) >= _SSL_NOT_INSPECTED_RATE).tolist()
        browser_ja4_cohort = f"{user.device.browser_family}|{user.device.os_family}"
        src_country = _country_for_office(user.office.country)
        # Full-width catalogue fields (this task): org-level constants, computed once per batch
        # rather than per event.
        company = _org_company_name(ctx.org.name)
        cloudname = _org_cloudname(ctx.org.email_domain)

        for i in range(min(total, n)):
            host = hosts[i]
            cat = cats[i]
            is_blocked = blocked[i]
            status = 403 if is_blocked else STATUS_CODES[status_l[i]]
            seed = path_seeds[i]
            prefix, suffix = _PATHS[kind_l[i]][seed % len(_PATHS[kind_l[i]])]
            if is_blocked:
                body = _BLOCK_PAGE_BYTES
            elif status in _NO_BODY:
                body = _NO_BODY_BYTES
            else:
                body = resp_l[i]
            fields: dict[str, Any] = {
                "serverip": server_ip(host),
                "host": host,
                "url": f"{prefix}{seed}{suffix}",
                "requestmethod": METHODS[method_l[i]],
                "status": status,
                "requestsize": req_l[i],
                "responsesize": body,
                "useragent": automation_ua if automated[i] else browser_ua,
                "action": "Blocked" if is_blocked else "Allowed",
                "urlcategory": cat.name,
                "urlsupercategory": cat.supercategory,
                "appname": catalog.appname(host),
                "appclass": cat.appclass,
                "riskscore": min(cat.risk + (25 if is_blocked else 0), _MAX_RISK),
                "location": location,
                "department": department,
                "flow_type": _FLOW_ZPA
                if path_seeds[i] % _ZPA_OVERRIDE_MODULUS == 0
                else (_FLOW_VPN if remote_flags[i] else _FLOW_ZIA),
                "bypassed_traffic": 1 if bypassed[i] else 0,
            }
            _apply_device_fields(fields, device_profile)
            if is_blocked:
                fields["reason"] = "Blocked by URL Filtering policy"
            if wants_referer[i]:
                fields["referer"] = f"https://{host}/"

            # Phase 2 detection fields (this task) — see the module-level "phase 2 detection
            # fields" section above for the helper functions and the reasoning behind each rate.
            ja4_cohort = automation_ua if (automated[i] and automation_ua) else browser_ja4_cohort
            fields["ja4_str"] = _ja4_fingerprint(ja4_cohort)
            # Bug fix (this task): `bypassed[i]` and `ssl_inspected[i]` were drawn independently,
            # so a request could land `bypassed_traffic=1` (skips the Client Connector, and with
            # it Zscaler's TLS termination, entirely) *and* `ssldecrypted="Yes"` at the same
            # time — a transaction Zscaler never saw cannot also be one it SSL-inspected. Bypassed
            # traffic is never inspected, full stop.
            inspected = ssl_inspected[i] and not bypassed[i]
            fields["ssldecrypted"] = "Yes" if inspected else "No"
            fields["srcip_country"] = src_country
            fields["is_src_cntry_risky"] = "No"
            fields["dstip_country"] = _dst_country_for(host)
            fields["is_dst_cntry_risky"] = "No"
            fields["threatseverity"] = _threat_severity(int(fields["riskscore"]))
            if inspected:
                validity_period, ocsp_result = _cert_posture(host)
                fields["is_sslselfsigned"] = "No"
                fields["is_sslexpiredca"] = "No"
                fields["is_ssluntrustedca"] = "Pass"
                fields["srvcertvalidityperiod"] = validity_period
                fields["srvocspresult"] = ocsp_result
            if kind_l[i] == _KIND_DOWNLOAD and seed % 100 < int(_FILETYPE_POPULATED_RATE * 100):
                ftype = _FILETYPES[int(np.searchsorted(_FILETYPE_CDF, (seed % 10_000) / 10_000))]
                fields["filetype"] = ftype
                if (seed // 7) % 100 < int(_FILE_HASH_RATE * 100):
                    fields["sha256"] = _fake_hash(f"{host}|{seed}|sha256", 64)
                    fields["bamd5"] = _fake_hash(f"{host}|{seed}|md5", 32)

            event_ts = datetime.fromtimestamp(ts_l[i], tz=UTC)
            _apply_wide_fields(
                fields,
                ts=event_ts,
                client_ip=ips[i],
                company=company,
                cloudname=cloudname,
                device_profile=device_profile,
                seed=seed,
            )
            yield EventRecord(
                ts=event_ts,
                source=SourceType.ZSCALER,
                principal=principal,
                fields=fields,
                src_ip=ips[i],
            )

    def _page_domains(
        self, models: RealismModels, rng: SeededRandom, user: User, pages: int
    ) -> list[str]:
        """Mostly the user's own affinity set, with a novel slice and a long-tail slice.

        Without the novel slice `n_new_domains_for_user` would be zero in every benign hour and
        the rarity detector would have no false positives to be calibrated against.
        """
        affinity = user.domain_affinity
        weights = _cdf([(i + 1) ** -_AFFINITY_EXPONENT for i in range(len(affinity))])
        domains = [affinity[int(i)] for i in _pick(rng.np.random(pages), weights)]

        mix = rng.np.random(pages)
        novel_at = np.flatnonzero(mix < self.novel_domain_rate).tolist()
        if novel_at:
            for pos, domain in zip(
                novel_at, models.domains.sample_many(rng, len(novel_at)), strict=True
            ):
                domains[pos] = domain
        lo = self.novel_domain_rate
        for pos in np.flatnonzero((mix >= lo) & (mix < lo + self.rare_domain_rate)).tolist():
            domains[pos] = models.domains.sample_tail(rng)
        return domains

    def _policy_blocked(
        self, user: User, domains: Sequence[str], cats: Sequence[UrlCategory]
    ) -> Iterator[bool]:
        """Whether URL filtering blocks each page, decided per `(principal, host)` and derived.

        Derived rather than drawn so the verdict never changes for a pair — see the class
        docstring for why the blocked-then-allowed rule depends on that.
        """
        threshold = int(self.blocked_rate * 10_000)
        cache: dict[str, bool] = {}
        for domain, cat in zip(domains, cats, strict=True):
            if not cat.policy_blockable:
                yield False
                continue
            verdict = cache.get(domain)
            if verdict is None:
                verdict = stable_hash(f"{user.key}|{domain}") % 10_000 < threshold
                cache[domain] = verdict
            yield verdict

    def _automation_eligible(self, user: User) -> bool:
        return (
            self.automation_ua_rate > 0.0
            and user.department in _AUTOMATION_DEPARTMENTS
            and stable_hash(user.key) % 8 == 0
        )

    # ------------------------------------------------------------------ service accounts

    def _service_traffic(
        self, ctx: BenignContext, catalog: _Catalog, user: User, rng: SeededRandom, n: int
    ) -> Iterator[EventRecord]:
        """Machine-regular traffic on the account's own period.

        The near-zero inter-arrival CV is the point, not an artefact: these accounts are what the
        beaconing detector and the autoencoder have to learn as normal before scenario 1 can be
        scored honestly.
        """
        window = ctx.window
        interval = float(user.interval_s or 300)
        ticks = max(1, int(window.duration_s // interval))

        # Bresenham apportionment across ticks: spreads the remainder evenly instead of piling it
        # onto the first ticks, which would put a fake volume ramp at the start of every window.
        edges = (np.arange(ticks + 1, dtype=np.int64) * n) // ticks
        counts = np.diff(edges)
        active = np.flatnonzero(counts > 0)
        if active.size == 0:
            return
        counts = counts[active]

        phase = rng.fresh("phase").uniform(0.0, interval)
        start = 0
        while start < active.size:
            stop = start + 1
            taken = int(counts[start])
            while stop < active.size and taken + int(counts[stop]) <= _BATCH:
                taken += int(counts[stop])
                stop += 1
            yield from self._service_batch(
                ctx, catalog, user, rng, active[start:stop], counts[start:stop], interval, phase
            )
            start = stop

    def _service_batch(
        self,
        ctx: BenignContext,
        catalog: _Catalog,
        user: User,
        rng: SeededRandom,
        tick_idx: np.ndarray,
        tick_counts: np.ndarray,
        interval: float,
        phase: float,
    ) -> Iterator[EventRecord]:
        window = ctx.window
        np_rng = rng.np
        total = int(tick_counts.sum())

        tick_ts = window.start.timestamp() + phase + tick_idx.astype(np.float64) * interval
        tick_ts += np_rng.normal(0.0, interval * self.interval_jitter_pct, size=tick_idx.size)
        spread = min(interval * 0.2, 30.0)
        ts = np.repeat(tick_ts, tick_counts) + np_rng.random(total) * spread
        np.clip(ts, window.start.timestamp(), window.end.timestamp() - 1e-3, out=ts)

        upload_heavy = user.device.browser_family in _UPLOAD_UA_FAMILIES
        method_idx = _pick(
            np_rng.random(total),
            _SERVICE_UPLOAD_METHOD_CDF if upload_heavy else _SERVICE_METHOD_CDF,
        )
        kind_idx = np.where(
            (method_idx == 0) & (np_rng.random(total) < self.service_download_rate),
            _KIND_DOWNLOAD,
            _KIND_API,
        )
        errored = np_rng.random(total) < self.service_error_rate
        status = np.where(
            errored,
            np.asarray(_SERVICE_ERROR_CODES)[_pick(np_rng.random(total), _SERVICE_ERROR_CDF)],
            np.asarray(_SERVICE_OK_CODES)[_pick(np_rng.random(total), _SERVICE_OK_CDF)],
        )
        resp = np.clip(
            np_rng.lognormal(_RESP_MU[kind_idx], _RESP_SIGMA[kind_idx]), _MIN_BYTES, _MAX_BYTES
        )
        req = np.clip(
            np_rng.lognormal(_REQ_MU[method_idx], _REQ_SIGMA[method_idx]), _MIN_BYTES, _MAX_BYTES
        )
        domains = user.domain_affinity or ("amazonaws.com",)
        host_l = np_rng.integers(0, len(domains), size=total).tolist()
        seed_l = np_rng.integers(1, 1_000_000, size=total).tolist()

        ts_l = ts.tolist()
        method_l = method_idx.tolist()
        status_l = status.tolist()
        resp_l = resp.astype(np.int64).tolist()
        req_l = req.astype(np.int64).tolist()

        ua = user.device.user_agent
        location, department = user.office.code, user.department
        principal, client_ip = user.principal, user.office_ip
        # Service accounts run on unmanaged/headless hosts — no Client Connector device, so
        # `_device_profile` returns all-`None` and `_apply_device_fields` below is a no-op (the
        # realistic "these fields genuinely don't exist for this traffic" case, see
        # `DeviceProfile`'s docstring). `flow_type`/`bypassed_traffic` still apply independent of
        # Client Connector enrollment: unmanaged servers forward `Direct`, and — never having a
        # Client Connector to bypass in the first place — never trip the bypass flag.
        device_profile = _device_profile(user)
        # Phase 2 detection fields (this task). One JA4 cohort per service account's own
        # automation client (`browser_family` holds tool names like `curl`/`aws-cli`/`rclone` for
        # service accounts, `datagen.org`) — a stable per-account fingerprint, same reasoning as
        # the human path's per-browser one. `ssl_inspected`/`src_country` are per-batch, like the
        # human path.
        ssl_inspected = (np_rng.random(total) >= _SSL_NOT_INSPECTED_RATE).tolist()
        ja4_cohort = user.device.browser_family
        src_country = _country_for_office(user.office.country)
        # Full-width catalogue fields (this task): org-level constants, computed once per batch.
        company = _org_company_name(ctx.org.name)
        cloudname = _org_cloudname(ctx.org.email_domain)
        for i in range(total):
            host = domains[host_l[i]]
            cat = catalog.category(host)
            code = status_l[i]
            seed = seed_l[i]
            prefix, suffix = _SERVICE_PATHS[seed % len(_SERVICE_PATHS)]
            fields: dict[str, Any] = {
                "serverip": server_ip(host),
                "host": host,
                "url": f"{prefix}{seed}{suffix}",
                "requestmethod": METHODS[method_l[i]],
                "status": code,
                "requestsize": req_l[i],
                "responsesize": _NO_BODY_BYTES if code in _NO_BODY else resp_l[i],
                "useragent": ua,
                "action": "Allowed",
                "urlcategory": cat.name,
                "urlsupercategory": cat.supercategory,
                "appname": catalog.appname(host),
                "appclass": cat.appclass,
                "riskscore": cat.risk,
                "location": location,
                "department": department,
                "flow_type": _FLOW_DIRECT,
                "bypassed_traffic": 0,
            }
            _apply_device_fields(fields, device_profile)

            # Phase 2 detection fields (this task) — see `_human_batch` for the same wiring and
            # the helper functions' own docstrings.
            fields["ja4_str"] = _ja4_fingerprint(ja4_cohort)
            inspected = ssl_inspected[i]
            fields["ssldecrypted"] = "Yes" if inspected else "No"
            fields["srcip_country"] = src_country
            fields["is_src_cntry_risky"] = "No"
            fields["dstip_country"] = _dst_country_for(host)
            fields["is_dst_cntry_risky"] = "No"
            fields["threatseverity"] = _threat_severity(int(fields["riskscore"]))
            if inspected:
                validity_period, ocsp_result = _cert_posture(host)
                fields["is_sslselfsigned"] = "No"
                fields["is_sslexpiredca"] = "No"
                fields["is_ssluntrustedca"] = "Pass"
                fields["srvcertvalidityperiod"] = validity_period
                fields["srvocspresult"] = ocsp_result
            if kind_idx[i] == _KIND_DOWNLOAD and seed % 100 < int(_FILETYPE_POPULATED_RATE * 100):
                ftype = _FILETYPES[int(np.searchsorted(_FILETYPE_CDF, (seed % 10_000) / 10_000))]
                fields["filetype"] = ftype
                if (seed // 7) % 100 < int(_FILE_HASH_RATE * 100):
                    fields["sha256"] = _fake_hash(f"{host}|{seed}|sha256", 64)
                    fields["bamd5"] = _fake_hash(f"{host}|{seed}|md5", 32)

            event_ts = datetime.fromtimestamp(ts_l[i], tz=UTC)
            _apply_wide_fields(
                fields,
                ts=event_ts,
                client_ip=client_ip,
                company=company,
                cloudname=cloudname,
                device_profile=device_profile,
                seed=seed,
            )
            yield EventRecord(
                ts=event_ts,
                source=SourceType.ZSCALER,
                principal=principal,
                fields=fields,
                src_ip=client_ip,
            )
