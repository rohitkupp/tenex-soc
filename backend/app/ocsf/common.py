"""Shared OCSF building blocks used by all three event classes (docs/03).

These are the nested objects the docs/03 mapping tables point into — `actor.user.email_addr`,
`src_endpoint.location.country`, `http_request.url.path`, and so on. Every class here is a plain
Pydantic v2 model with every field optional, because a single source only ever populates a subset
(ZScaler never touches `api.*`; CloudTrail never touches `http_response.*`) and the parser must be
free to leave the rest at their defaults rather than inventing values.

Two deliberate simplifications versus the full OCSF taxonomy, both because a byte-for-byte OCSF
implementation needs lookup tables this project does not ship:

* `Url.category_ids` holds the vendor's own category *name* (ZScaler's `urlcategory`), not a real
  OCSF URL Category enum id — there is no bundled category-name -> OCSF-id mapping table. Kept as
  `list[str]` rather than `list[int]` so the value stays honest about what it actually is.
* `Malware.classification_ids` holds ZScaler's own `threatcategory` string, for the same reason.

Both are still exactly what docs/03's tables ask for ("urlcategory -> http_request.url.category_ids",
"threatcategory -> malware[].classification_ids") — just carrying the source's native identifier
instead of a taxonomy id nobody supplied.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class User(BaseModel):
    """`actor.user` — docs/03 populates a different subset of this per source.

    ZScaler/Okta identify a principal by email (`email_addr`); CloudTrail identifies one by ARN
    (`uid`) instead — docs/03's CloudTrail table maps `userIdentity.arn -> actor.user.uid`, not
    `email_addr`. Both fields exist here so each parser sets the one its source actually has.
    """

    model_config = ConfigDict(extra="forbid")

    email_addr: str | None = None
    name: str | None = None
    uid: str | None = None
    type: str | None = None
    groups: list[str] = Field(default_factory=list)


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: User = Field(default_factory=User)


class GeoCoordinates(BaseModel):
    """`src_endpoint.location.coordinates` — from Okta's `geographicalContext.geolocation`."""

    model_config = ConfigDict(extra="forbid")

    lat: float | None = None
    lon: float | None = None


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    country: str | None = None
    city: str | None = None
    coordinates: GeoCoordinates | None = None
    # ZScaler `srcip_country`/`dstip_country` + `is_src_cntry_risky`/`is_dst_cntry_risky`
    # (docs/v1/zscaler-nss-web-fields.md "Network"; this task's Phase 2). Vendor-reported, not
    # derived from the offline MaxMind enrichment pass (`docs/03` "Enrichment") that separately
    # populates `events.enrichment` from `src_ip`/`dst_ip` — a genuinely different data source
    # (ZScaler's own geo-IP classification vs. our bundled GeoLite2 snapshot) that can legitimately
    # disagree with it; reconciling the two is out of this task's scope (parse -> OCSF -> events,
    # not a new detector or enrichment merge).
    is_risky: bool | None = None


class AutonomousSystem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: int | None = None


class NetworkEndpoint(BaseModel):
    """`src_endpoint` / `dst_endpoint`."""

    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    location: Location | None = None
    autonomous_system: AutonomousSystem | None = None


class Url(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    path: str | None = None
    category_ids: list[str] = Field(default_factory=list)


class HttpRequest(BaseModel):
    """`http_request` — every source that carries a user agent uses this, not just ZScaler."""

    model_config = ConfigDict(extra="forbid")

    url: Url | None = None
    http_method: str | None = None
    user_agent: str | None = None
    referrer: str | None = None


class HttpResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: int | None = None


class Traffic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bytes_out: int | None = None
    bytes_in: int | None = None


class Malware(BaseModel):
    """One entry of `malware[]` — ZScaler's `threatname` / `threatcategory` pair."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    classification_ids: list[str] = Field(default_factory=list)


class Resource(BaseModel):
    """One entry of `resources[]` — Okta's `target[]`."""

    model_config = ConfigDict(extra="forbid")

    type: str | None = None
    uid: str | None = None
    name: str | None = None


class ApiService(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None


class Api(BaseModel):
    """`api.*` — CloudTrail's `eventName` / `eventSource` / request & response bodies."""

    model_config = ConfigDict(extra="forbid")

    operation: str | None = None
    service: ApiService | None = None
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None


class Cloud(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: str | None = None


# ZScaler NSS Web's "Zscaler Client Connector Device Information" section
# (docs/v1/zscaler-nss-web-fields.md) -> OCSF `device` (docs/03's extension of the HTTP Activity
# mapping table, "device asset fields"). Only three of the eight documented device tokens are
# wired into a hot column / tag today (`devicehostname`, `deviceostype`, `deviceosversion`); see
# `app.parsers.zscaler`'s module docstring for which are parsed and why the rest (`devicemodel`,
# `devicetype`, `deviceappversion`) are catalogued but not (yet) parsed.
_OS_TYPE_ALIASES: dict[str, str] = {
    # Zscaler NSS `deviceostype`'s own 5-value enum (docs/v1/zscaler-nss-web-fields.md), lowercased.
    "windows os": "windows",
    "mac os": "macos",
    "ios": "ios",
    "android os": "android",
    "other os": "other",
    # `ua_parser.parse_os(...).family` values (the useragent-derived fallback,
    # `app.enrichment.user_agent_enrichment` — docs/11 "derive OS family/version from useragent"),
    # lowercased. A superset of Zscaler's own enum: UA parsing can distinguish Linux, which the
    # Client Connector's device-type enum cannot (it has no Linux client), so `linux` is a real,
    # additional bucket rather than folded into "other".
    "windows": "windows",
    "mac os x": "macos",
    "macos": "macos",
    "android": "android",
    "linux": "linux",
    "ubuntu": "linux",
    "fedora": "linux",
    "chrome os": "chromeos",
}


def normalize_os_type(raw: str | None) -> str | None:
    """Collapse a raw OS string (Zscaler's own `deviceostype` value, or `ua_parser.parse_os`'s
    `family`) into one small, tag-friendly vocabulary. `None` in, `None` out; any non-empty,
    unrecognized string maps to `"other"` (a real Zscaler enum value, not a failure mode) rather
    than raising — a normalizer that rejects unknown input would make one weird UA string in a
    2M-event corpus fail the whole ingest, which CLAUDE.md rule 1's spirit ("reduce volume, don't
    choke on it") argues against."""
    if not raw or not raw.strip():
        return None
    return _OS_TYPE_ALIASES.get(raw.strip().lower(), "other")


class OS(BaseModel):
    """`device.os` — normalized type plus the vendor's own raw version string (docs/v1/
    zscaler-nss-web-fields.md `%s{deviceosversion}`, e.g. `"Version 10.14.2 (Build 18C54)"`).
    `type` is always run through `normalize_os_type` before landing here; `version` is kept raw
    and verbatim — normalizing *that* (major.minor) is a tag-rendering concern
    (`app.graph.asset_tags`), not an OCSF-mapping one, so the full string survives on the event."""

    model_config = ConfigDict(extra="forbid")

    type: str | None = None
    version: str | None = None


class Device(BaseModel):
    """`device` — a ZScaler Client Connector endpoint (docs/v1/zscaler-nss-web-fields.md
    "Zscaler Client Connector Device Information"). Absent entirely (not just empty) for
    transactions with no Client Connector device attached to them, which is real and common in
    this pipeline's own corpus: service-account/server traffic never carries a Client Connector
    device (`datagen.emitters.zscaler._device_profile`'s own docstring), and `app.enrichment.
    user_agent_enrichment`'s useragent-derived OS is exactly the deterministic fallback for that
    case (docs/11), not a device object.

    `owner` is the NSS `deviceowner` field — the asset's assigned user, which is not always the
    same principal as `actor.user` (the account that was actually active in this transaction).
    When they diverge, that is a shared/borrowed-device signal in its own right
    (`app.graph.asset_tags`'s `shared-device` tag), not merely two redundant copies of the same
    fact — kept as two separate fields for exactly that reason."""

    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    name: str | None = None
    owner: str | None = None
    os: OS | None = None


# ---------------------------------------------------------------------------- Phase 2 detection
# fields (docs/v1/zscaler-nss-web-fields.md "SSL/TLS", "Server Connection", "Sandbox",
# "Threat Protection", "File Type Control"). Each exists because it enables a specific detection
# this pipeline cannot currently do — see this task's report for the per-field design note.
# CLAUDE.md: no detector ships in this change; this is the data plumbing (parse -> OCSF -> events
# -> generator) that detector work would build on.


class Certificate(BaseModel):
    """`tls.certificate` — the server certificate's posture on this connection
    (docs/v1/zscaler-nss-web-fields.md "Server Connection"). All four fields are only ever
    populated when `%s{ssldecrypted}` is `Yes` (TLS Inspection has to run for ZScaler to see the
    certificate at all) — `None` on every plaintext or non-inspected HTTPS transaction, not a
    missing-data gap.

    `is_untrusted_ca` inverts the NSS wire polarity on purpose: `%s{is_ssluntrustedca}`'s own
    documented values are `Fail`/`Pass`/`None` ("Indicates whether the server certificate is
    signed by a Zscaler-trusted certificate authority or not") — `Fail` means the trust check
    failed, i.e. the CA *is* untrusted. Decoding straight to `Fail -> True` would silently invert
    the field's own name; `_to_untrusted_ca_bool` (parser) maps `Fail -> True` ("is untrusted"),
    `Pass -> False`, matching every other boolean here where `True` means "the concerning
    condition is present."
    """

    model_config = ConfigDict(extra="forbid")

    is_self_signed: bool | None = None
    is_expired: bool | None = None
    is_untrusted_ca: bool | None = None
    validity_period: str | None = None
    ocsp_status: str | None = None


class Tls(BaseModel):
    """`tls` — the TLS connection this transaction rode on
    (docs/v1/zscaler-nss-web-fields.md "SSL/TLS"). `ja4_hash` is the JA4 client fingerprint
    (`%s{ja4_str}`) — a hash of the client's own TLS stack behavior (extension order, cipher
    list, ...), not of anything server- or domain-specific, which is what makes it a strong C2
    indicator: malware rotates domains and IPs constantly but rarely its TLS library, so the same
    JA4 recurring across unrelated domains from one source is a stronger, more durable signal than
    any single domain (see this task's report for the full design note)."""

    model_config = ConfigDict(extra="forbid")

    ja4_hash: str | None = None
    decrypted: bool | None = None
    certificate: Certificate | None = None


class File(BaseModel):
    """`file` — the file (if any) this transaction transferred
    (docs/v1/zscaler-nss-web-fields.md "File Type Control", "Sandbox"). `name`/`upload_type` come
    from the upload-direction NSS fields (`%s{upload_filename}`/`%s{upload_filetype}`);
    `download_type` from the plain `%s{filetype}` (download direction) — ZScaler tracks upload and
    download file metadata as genuinely separate field families (docs/v1/zscaler-nss-web-fields.md
    "File Type Control"), so this model keeps them as separate attributes rather than collapsing
    upload/download into one ambiguous `type`. `hash_sha256`/`hash_md5` (`%s{sha256}`/`%s{bamd5}`)
    are populated independent of direction — the PDF's own Sandbox section describes `bamd5` as
    "the MD5 hash of the malware file that was detected... or the file that was sent for analysis",
    not tied to upload vs. download."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    upload_type: str | None = None
    download_type: str | None = None
    unscannable_type: str | None = None
    hash_sha256: str | None = None
    hash_md5: str | None = None
