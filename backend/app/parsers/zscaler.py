"""ZScaler NSS Web proxy logs -> OCSF HTTP Activity (4002). docs/03 "ZScaler NSS Web".

Tab- or comma-delimited with a header line (docs/03), matching `datagen.emitters.zscaler`'s
output exactly: `FIELDS`, in that module, is "docs/03 ... in the order that table lists them" —
the same field order hardcoded below as `_CANONICAL_FIELDS`. That is not a coincidence to
preserve; it is the parser and the generator agreeing independently on what the spec says, which
is the round-trip proof M3's acceptance bar asks for.

The first 25 fields are the original docs/03 table, unchanged. Fields 26-32 are the asset/device
extension (this task, docs/v1/zscaler-nss-web-fields.md "Zscaler Client Connector Device
Information" + "Miscellaneous"): `devicehostname`, `devicename`, `deviceostype`,
`deviceosversion`, `deviceowner`, `bypassed_traffic`, `flow_type` — the literal NSS `%s{...}`/
`%d{...}` token names, not renamed, unlike the original 25 (see that doc's "reconciliation"
section for why the original 25 carry different names than their own NSS tokens and why these
seven don't: there is no prior "friendly" convention to preserve continuity with for a field this
parser never emitted before). Only these seven of the documented device tokens are wired in —
`devicemodel`, `devicetype`, `deviceappversion`, `ztunnelversion`, `external_devid`,
`bypassed_etime` are catalogued in the field-inventory doc but do not back any tag or hot column
today, so parsing them would be new surface with no consumer (CLAUDE.md: "do not add a tag just
because a field exists" applies equally to fields).

Column binding is header-driven, not purely positional: `bind_header` reads the actual header row
and rebuilds the name->index map from it, so a real NSS export with a different column subset or
order (administrators reconfigure the NSS feed field list constantly in the wild) still binds
correctly instead of silently misreading columns. `_CANONICAL_FIELDS` is only the *default* used
before any header is seen, or if the sample handed to `sniff` never included one.

The `None` sentinel: per the emitter's own docstring, "absent values are the literal string
`None`" — every field reader below runs through `_none_if_sentinel` so that string is treated as
a real null rather than the four-letter word "None" leaking into `unmapped` or a hot column.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from app.ocsf import (
    OS,
    Actor,
    Certificate,
    Device,
    File,
    HTTPActivity,
    HttpRequest,
    HttpResponse,
    Location,
    Malware,
    NetworkEndpoint,
    Tls,
    Url,
    normalize_os_type,
)
from app.ocsf import Traffic as OcsfTraffic
from app.ocsf import User as OcsfUser
from app.parsers.base import ParseFailure, excerpt

# docs/03 "ZScaler NSS Web -> OCSF HTTP Activity (4002)", in the order that table lists them.
_CANONICAL_FIELDS: tuple[str, ...] = (
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
    # Asset/device extension (this task) — see module docstring.
    "devicehostname",
    "devicename",
    "deviceostype",
    "deviceosversion",
    "deviceowner",
    "bypassed_traffic",
    "flow_type",
    # Phase 2 detection fields (this task, docs/v1/zscaler-nss-web-fields.md "SSL/TLS",
    # "Server Connection", "Sandbox", "File Type Control", "Network", "Threat Protection") —
    # literal NSS token names, appended (not interspersed) for the same reason the device
    # extension above is: no prior "friendly" name to preserve continuity with, and every
    # existing fixture keeps working unmodified. See this task's report for the per-field
    # detector-design note (which detector each field would enable — none shipped in this change).
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
)

_HEADER_MATCH_FIELDS = frozenset(_CANONICAL_FIELDS)
_EMPTY = "None"
_DATETIME_FORMATS: tuple[str, ...] = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ")

# A handful of tokens that show up in a genuine ZScaler data row regardless of column order —
# used by the sniffer's body-heuristic fallback when no header line is in the sample.
_KNOWN_METHODS = frozenset({"GET", "POST", "HEAD", "PUT", "CONNECT", "DELETE", "OPTIONS", "PATCH"})
_KNOWN_ACTIONS = frozenset({"Allowed", "Blocked"})


def _split(line: str) -> tuple[str, list[str]]:
    delimiter = "\t" if "\t" in line else ","
    return delimiter, line.split(delimiter)


def _none_if_sentinel(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped == _EMPTY or stripped == "" else stripped


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def _to_bool(value: str | None) -> bool | None:
    """`%d{bypassed_traffic}`: the wire value is `1`/`0`, not `true`/`false` — same convention as
    every other `%d{...}` token in the doc. `None` (sentinel-or-absent) stays `None`; anything
    that isn't a parseable int is treated as `None` too rather than raising, matching `_to_int`'s
    own permissiveness for a malformed field."""
    parsed = _to_int(value)
    return None if parsed is None else parsed != 0


def _to_yesno_bool(value: str | None) -> bool | None:
    """`Yes`/`No`/`None` -> bool -- the wire convention for `ssldecrypted`, `is_sslselfsigned`,
    `is_sslexpiredca`, `is_src_cntry_risky`, `is_dst_cntry_risky` (docs/v1/
    zscaler-nss-web-fields.md "SSL/TLS", "Server Connection", "Network"; this task's Phase 2).
    Anything that isn't exactly `yes`/`no` (case-insensitive) is treated as `None` rather than
    raising, matching `_to_bool`'s own permissiveness for a malformed field."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "yes":
        return True
    if lowered == "no":
        return False
    return None


def _to_untrusted_ca_bool(value: str | None) -> bool | None:
    """`%s{is_ssluntrustedca}`'s own documented values are `Fail`/`Pass`/`None`, not `Yes`/`No` --
    "Indicates whether the server certificate is signed by a Zscaler-trusted certificate
    authority or not." `Fail` means the trust check failed, i.e. the CA *is* untrusted, so this
    maps `Fail -> True` ("is untrusted") / `Pass -> False`, matching every other boolean this
    parser produces where `True` means "the concerning condition is present." See
    `app.ocsf.common.Certificate`'s own docstring for the same note kept next to the field."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "fail":
        return True
    if lowered == "pass":
        return False
    return None


def _normalize_action(raw: str | None) -> str:
    """docs/03: "Allowed -> allowed, Blocked -> blocked, everything else -> other.\""""
    if raw is None:
        return "other"
    lowered = raw.strip().lower()
    if lowered == "allowed":
        return "allowed"
    if lowered == "blocked":
        return "blocked"
    return "other"


def _status_class(status: int | None) -> str:
    """HTTP status class bucket (`2xx`/`4xx`/...) — the `status_class` term in docs/03's ZScaler
    `event_key` formula, which names it but does not spell out the bucketing; this is the
    standard HTTP meaning of "status class" and the natural reading of that formula."""
    if status is None or status < 100 or status > 599:
        return "unknown"
    return f"{status // 100}xx"


# ------------------------------------------------------------------------ encoding variants
#
# docs/NSS_Feed_Output_Format__Web_Logs.pdf "Obfuscated Fields" / "Base64 Fields" /
# "Hex-Encoded Fields" (pp. 37-39), reproduced in full in
# docs/v1/zscaler-nss-web-fields.md. A real NSS feed is configured per-field, so a customer can
# turn any one of these on for a column this parser already maps -- e.g. request `b64host`
# instead of `host` in the field list, and every value in that column arrives base64-encoded.
# Today, before this change, that value would be ingested as a literal hostname: a real,
# shipping correctness bug that silently corrupts every domain-keyed detector (beaconing, DGA,
# rarity, the entity graph) the moment a customer turns Base64 or Hex encoding on for anything.
#
# Design: resolution is header-driven, not a blind rename. `bind_header` (unchanged) already
# rebuilds `self._fields` from the literal header row, so `values` (built by `_parse_line` from
# `zip(self._fields, parts)`) is keyed by whatever the header actually said -- `host`, `b64host`,
# or `ehost` are three different keys of the same dict. `_resolve_encoded` below looks for our
# canonical key first (the common case, and every fixture that predates this change), then falls
# back to scanning the alias table for whichever encoded variant is present. Only one variant of
# a given field is expected in a real header at a time; if a malformed header somehow declares
# more than one, plain wins (it needs no decoding to be "correct", the least-surprising tiebreak).


class _Encoding(Enum):
    PLAIN = "plain"
    OBFUSCATED = "obfuscated"
    BASE64 = "base64"
    HEX = "hex"


# wire header token (as it would appear in an NSS field-list header row) -> (our canonical
# field key, encoding). Only the encoded variants of fields this parser already maps land here --
# device/asset-field variants (`odevicehostname`, `edevicehostname`, `odevicename`, `edevicename`,
# `odeviceowner`) are deliberately excluded: that field family is owned by a concurrent change
# (see this module's own device-fields docstring above) and is out of scope here by agreement.
_ENCODING_ALIASES: dict[str, tuple[str, _Encoding]] = {
    # login -> user
    "ologin": ("user", _Encoding.OBFUSCATED),
    "b64login": ("user", _Encoding.BASE64),
    "elogin": ("user", _Encoding.HEX),
    # cip -> clientip (only an obfuscated variant is documented for this field)
    "ocip": ("clientip", _Encoding.OBFUSCATED),
    # host
    "b64host": ("host", _Encoding.BASE64),
    "ehost": ("host", _Encoding.HEX),
    # url
    "b64url": ("url", _Encoding.BASE64),
    "eurl": ("url", _Encoding.HEX),
    # ua -> useragent
    "b64ua": ("useragent", _Encoding.BASE64),
    "eua": ("useragent", _Encoding.HEX),
    # urlcat -> urlcategory (no hex variant documented)
    "ourlcat": ("urlcategory", _Encoding.OBFUSCATED),
    "b64urlcat": ("urlcategory", _Encoding.BASE64),
    # threatname (base64 only)
    "b64threatname": ("threatname", _Encoding.BASE64),
    # referer (no obfuscated variant documented)
    "b64referer": ("referer", _Encoding.BASE64),
    "ereferer": ("referer", _Encoding.HEX),
    # dlpeng -> dlpengine (obfuscated only)
    "odlpeng": ("dlpengine", _Encoding.OBFUSCATED),
    # dlpdict -> dlpdictionaries (obfuscated only)
    "odlpdict": ("dlpdictionaries", _Encoding.OBFUSCATED),
    # location (no obfuscated variant documented)
    "b64location": ("location", _Encoding.BASE64),
    "elocation": ("location", _Encoding.HEX),
    # dept -> department (no obfuscated variant documented)
    "b64dept": ("department", _Encoding.BASE64),
    "edepartment": ("department", _Encoding.HEX),
    # upload_filename (Phase 2 field, this task) -- no obfuscated variant documented, but both
    # Base64 and Hex are, same as every other free-text field above.
    "b64upload_filename": ("upload_filename", _Encoding.BASE64),
    "eupload_filename": ("upload_filename", _Encoding.HEX),
}

# Every canonical field this parser resolves through the encoding-aware path -- the union of
# `_ENCODING_ALIASES` targets, in field order, plus every field's own plain name (already handled
# implicitly by `_resolve_encoded`'s first check).
_ENCODED_CANONICAL_FIELDS: tuple[str, ...] = (
    "user",
    "clientip",
    "host",
    "url",
    "useragent",
    "urlcategory",
    "threatname",
    "referer",
    "dlpengine",
    "dlpdictionaries",
    "location",
    "department",
    "upload_filename",
)


def _resolve_encoded(values: dict[str, str], canonical: str) -> tuple[str | None, _Encoding]:
    """The raw wire value for `canonical`, plus which encoding it arrived in. Header-driven: scans
    `values` (keyed by whatever `bind_header` bound the columns to) for the plain key first, then
    every alias that targets this canonical field."""
    if canonical in values:
        return values[canonical], _Encoding.PLAIN
    for wire_key, (target, encoding) in _ENCODING_ALIASES.items():
        if target == canonical and wire_key in values:
            return values[wire_key], encoding
    return None, _Encoding.PLAIN


_HEX_PAIR_RE = re.compile(r"[0-9A-Fa-f]{2}")


def _hex_decode_field(value: str) -> str:
    """docs (PDF p.38-39) "Hex-Encoded Fields": non-printable ASCII (<=0x20 or >=0x7F) is
    percent-encoded as `%HH`; every other character passes through literally. Decode by walking
    the string, validating every `%` is followed by exactly two hex digits, accumulating raw
    bytes (a multi-byte UTF-8 character can have every one of its bytes individually %-escaped,
    since continuation bytes are always >=0x7F), then UTF-8 decoding the result once at the end.
    Raises `ValueError` on either a malformed escape or bytes that don't form valid UTF-8 --
    callers turn that into a recorded `ParseFailure`, never a silent pass-through of the encoded
    literal."""
    out = bytearray()
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch == "%":
            pair = value[i + 1 : i + 3]
            if len(pair) != 2 or not _HEX_PAIR_RE.fullmatch(pair):
                raise ValueError(f"malformed %-escape at offset {i}: {value[i : i + 3]!r}")
            out.append(int(pair, 16))
            i += 3
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"hex-decoded bytes are not valid utf-8: {exc}") from exc


def _base64_decode_field(value: str) -> str:
    """docs (PDF p.37-38) "Base64 Fields". `validate=True` rejects non-alphabet characters instead
    of silently discarding them (Python's default); malformed padding/length still raises
    `binascii.Error` regardless. Both that and a UTF-8 decode failure on the decoded bytes raise
    `ValueError` so the caller records a `ParseFailure` rather than passing the raw base64 text
    (or garbage bytes) through as if it were the real field."""
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"malformed base64: {exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"base64-decoded bytes are not valid utf-8: {exc}") from exc


class ZScalerParser:
    # Not ClassVar: LogParser (docs/03) declares these as plain instance attributes, and mypy's
    # Protocol structural matching checks that shape -- a ClassVar here would type-check as
    # incompatible with LogParser despite being identical at runtime. header_lines isn't part of
    # the Protocol, so it stays a straightforward shared default either way.
    source_type: str = "zscaler"
    ocsf_class_uid: int = 4002
    header_lines: int = 1

    def __init__(self) -> None:
        self._fields: tuple[str, ...] = _CANONICAL_FIELDS

    def bind_header(self, header_line: str) -> None:
        """Rebind column order from an actually-observed header row. See module docstring."""
        _, parts = _split(header_line)
        cols = tuple(p.strip().strip('"').lower() for p in parts)
        if cols:
            self._fields = cols

    # ------------------------------------------------------------------ sniff

    def sniff(self, sample: str) -> float:
        lines = [line for line in sample.splitlines() if line.strip()]
        if not lines:
            return 0.0

        for line in lines[:5]:
            _, parts = _split(line)
            cols = {p.strip().strip('"').lower() for p in parts}
            overlap = cols & _HEADER_MATCH_FIELDS
            if len(overlap) >= 5 and len(overlap) / max(len(cols), 1) >= 0.5:
                return 0.95

        # No header in this block (a mid-file chunk of a mixed export, or a header outside the
        # sniff window) -- fall back to a structural ratio over data rows. Only delimited rows
        # with enough fields count as *candidates* at all (the denominator): a JSON line, or a
        # short unrelated line, must not dilute this ratio the way an unconditional `total += 1`
        # over every sample line would -- the mixed-export failure mode a JSON-line-based source
        # (Okta, CloudTrail; both removed) used to guard against symmetrically on its own side,
        # now only relevant here since ZScaler is the only registered parser.
        hits, total = 0, 0
        for line in lines:
            if _looks_like_json_object(line):
                continue
            _, parts = _split(line)
            if len(parts) < 8:
                continue
            total += 1
            has_method = any(p.strip() in _KNOWN_METHODS for p in parts)
            has_action = any(p.strip() in _KNOWN_ACTIONS for p in parts)
            has_ip = any(_looks_like_ipv4(p.strip()) for p in parts[:4])
            if has_ip and (has_method or has_action):
                hits += 1
        return hits / total if total else 0.0

    # ------------------------------------------------------------------ parse

    def parse_line(self, line: str, line_no: int) -> HTTPActivity | ParseFailure:
        try:
            return self._parse_line(line, line_no)
        except Exception as exc:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unexpected error: {exc}",
                raw_excerpt=excerpt(line),
            )

    def _parse_line(self, line: str, line_no: int) -> HTTPActivity | ParseFailure:
        _, parts = _split(line)
        if len(parts) < 2:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"expected a delimited row, got {len(parts)} field(s)",
                raw_excerpt=excerpt(line),
            )

        values: dict[str, str] = dict(zip(self._fields, parts, strict=False))

        dt_raw = _none_if_sentinel(values.get("datetime"))
        if dt_raw is None:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason="missing required field 'datetime'",
                raw_excerpt=excerpt(line),
            )
        ts = _parse_datetime(dt_raw)
        if ts is None:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unparseable datetime {dt_raw!r}",
                raw_excerpt=excerpt(line),
            )

        # Encoding-variant resolution (obfuscated/base64/hex — see the module section above this
        # class). Each of these twelve fields may have arrived under its plain key or one of its
        # documented encoded aliases, depending on how this feed's NSS field list is configured.
        decoded: dict[str, str | None] = {}
        obfuscated_fields: list[str] = []
        for canonical in _ENCODED_CANONICAL_FIELDS:
            raw, encoding = _resolve_encoded(values, canonical)
            raw = _none_if_sentinel(raw)
            if raw is None:
                decoded[canonical] = None
            elif encoding is _Encoding.PLAIN:
                decoded[canonical] = raw
            elif encoding is _Encoding.OBFUSCATED:
                # docs (PDF p.37): "Instead of displaying [the real value], the obfuscated field
                # displays a random string." That string is never a usable identity/category/DLP
                # value -- carrying it through as if it were real would either silently corrupt
                # correlation (a random per-line "user" fabricates false distinct identities, or
                # worse, false joins if the feed happens to reuse a string) or make every rule
                # that matches on this field's real value (urlcategory, dlpengine/dlpdictionaries)
                # silently stop firing with no signal anything changed. So the canonical field is
                # left `None` -- never fed to a hot column, an entity, or a detector join key --
                # and the fact that it arrived obfuscated is recorded in `unmapped.
                # obfuscated_fields` instead of being dropped silently, so a quality/observability
                # consumer can see that identity- or category-linked detection is degraded for
                # this feed configuration rather than discovering it by an unexplained coverage
                # gap later.
                decoded[canonical] = None
                obfuscated_fields.append(canonical)
            else:
                try:
                    decoded[canonical] = (
                        _base64_decode_field(raw)
                        if encoding is _Encoding.BASE64
                        else _hex_decode_field(raw)
                    )
                except ValueError as exc:
                    return ParseFailure(
                        source_type=self.source_type,
                        line_no=line_no,
                        reason=f"{encoding.value} decode failed for field {canonical!r}: {exc}",
                        raw_excerpt=excerpt(line),
                    )

        user = decoded["user"]
        clientip = decoded["clientip"]
        serverip = _none_if_sentinel(values.get("serverip"))
        host = decoded["host"]
        url = decoded["url"]
        method = _none_if_sentinel(values.get("requestmethod"))
        status = _to_int(_none_if_sentinel(values.get("status")))
        bytes_out = _to_int(_none_if_sentinel(values.get("requestsize")))
        bytes_in = _to_int(_none_if_sentinel(values.get("responsesize")))
        ua = decoded["useragent"]
        action_raw = _none_if_sentinel(values.get("action"))
        disposition = _normalize_action(action_raw)
        urlcategory = decoded["urlcategory"]
        urlsupercategory = _none_if_sentinel(values.get("urlsupercategory"))
        appname = _none_if_sentinel(values.get("appname"))
        appclass = _none_if_sentinel(values.get("appclass"))
        threatname = decoded["threatname"]
        threatcategory = _none_if_sentinel(values.get("threatcategory"))
        riskscore = _to_int(_none_if_sentinel(values.get("riskscore")))
        reason = _none_if_sentinel(values.get("reason"))
        referer = decoded["referer"]
        dlpengine = decoded["dlpengine"]
        dlpdictionaries = decoded["dlpdictionaries"]
        location = decoded["location"]
        department = decoded["department"]

        devicehostname = _none_if_sentinel(values.get("devicehostname"))
        devicename = _none_if_sentinel(values.get("devicename"))
        deviceostype_raw = _none_if_sentinel(values.get("deviceostype"))
        deviceosversion = _none_if_sentinel(values.get("deviceosversion"))
        deviceowner = _none_if_sentinel(values.get("deviceowner"))
        bypassed_traffic = _to_bool(_none_if_sentinel(values.get("bypassed_traffic")))
        flow_type = _none_if_sentinel(values.get("flow_type"))

        # Phase 2 detection fields (this task) — see the module's `_CANONICAL_FIELDS` comment and
        # this task's report for the per-field detector-design note.
        ja4_str = _none_if_sentinel(values.get("ja4_str"))
        df_hostname = _none_if_sentinel(values.get("df_hostname"))
        df_hosthead = _none_if_sentinel(values.get("df_hosthead"))
        ssldecrypted = _to_yesno_bool(_none_if_sentinel(values.get("ssldecrypted")))
        is_sslselfsigned = _to_yesno_bool(_none_if_sentinel(values.get("is_sslselfsigned")))
        is_sslexpiredca = _to_yesno_bool(_none_if_sentinel(values.get("is_sslexpiredca")))
        is_ssluntrustedca = _to_untrusted_ca_bool(
            _none_if_sentinel(values.get("is_ssluntrustedca"))
        )
        srvcertvalidityperiod = _none_if_sentinel(values.get("srvcertvalidityperiod"))
        srvocspresult = _none_if_sentinel(values.get("srvocspresult"))
        sha256 = _none_if_sentinel(values.get("sha256"))
        bamd5 = _none_if_sentinel(values.get("bamd5"))
        srcip_country = _none_if_sentinel(values.get("srcip_country"))
        dstip_country = _none_if_sentinel(values.get("dstip_country"))
        is_src_cntry_risky = _to_yesno_bool(_none_if_sentinel(values.get("is_src_cntry_risky")))
        is_dst_cntry_risky = _to_yesno_bool(_none_if_sentinel(values.get("is_dst_cntry_risky")))
        upload_filename = decoded["upload_filename"]
        upload_filetype = _none_if_sentinel(values.get("upload_filetype"))
        filetype = _none_if_sentinel(values.get("filetype"))
        unscannabletype = _none_if_sentinel(values.get("unscannabletype"))
        threatseverity = _none_if_sentinel(values.get("threatseverity"))

        unmapped: dict[str, Any] = {}
        if urlsupercategory is not None:
            unmapped["url_supercategory"] = urlsupercategory
        if appname is not None:
            unmapped["app_name"] = appname
        if appclass is not None:
            unmapped["app_class"] = appclass
        if reason is not None:
            unmapped["block_reason"] = reason
        if dlpengine is not None:
            unmapped["dlp_engine"] = dlpengine
        if dlpdictionaries is not None:
            unmapped["dlp_dictionaries"] = dlpdictionaries
        # `location`/`department` already land in `actor.user.groups` (below, unchanged) for
        # backward compatibility, but that list is an unlabeled bag — a consumer that needs to
        # tell "which entry was the location" from "which was the department" (asset-tag
        # computation, `app.graph.asset_tags`) cannot recover that from `groups` alone. Duplicating
        # both into `unmapped` under their own names is additive, not a second source of truth: it
        # is the same two values, just also reachable by name.
        if location is not None:
            unmapped["location"] = location
        if department is not None:
            unmapped["department"] = department
        # Recorded, not dropped — see the OBFUSCATED branch above for the full reasoning. Sorted
        # so the list is deterministic regardless of `_ENCODING_ALIASES` dict-iteration order.
        if obfuscated_fields:
            unmapped["obfuscated_fields"] = sorted(obfuscated_fields)

        malware: list[Malware] = []
        if threatname is not None:
            malware.append(
                Malware(
                    name=threatname,
                    classification_ids=[threatcategory] if threatcategory else [],
                )
            )

        groups = [g for g in (location, department) if g is not None]

        device: Device | None = None
        if any(
            v is not None
            for v in (devicehostname, devicename, deviceowner, deviceostype_raw, deviceosversion)
        ):
            os_obj: OS | None = None
            if deviceostype_raw is not None or deviceosversion is not None:
                os_obj = OS(type=normalize_os_type(deviceostype_raw), version=deviceosversion)
            device = Device(hostname=devicehostname, name=devicename, owner=deviceowner, os=os_obj)

        # Phase 2 detection fields (this task): `Certificate`/`Tls`/`File`/`Location` are only
        # constructed — same "None when nothing was actually sent" discipline `device` above
        # already follows — when at least one of their constituent fields is present, so a
        # transaction that never populated any of these carries `tls=None`/`file=None` rather than
        # an object full of `None`s that looks like data.
        certificate: Certificate | None = None
        if any(
            v is not None
            for v in (
                is_sslselfsigned,
                is_sslexpiredca,
                is_ssluntrustedca,
                srvcertvalidityperiod,
                srvocspresult,
            )
        ):
            certificate = Certificate(
                is_self_signed=is_sslselfsigned,
                is_expired=is_sslexpiredca,
                is_untrusted_ca=is_ssluntrustedca,
                validity_period=srvcertvalidityperiod,
                ocsp_status=srvocspresult,
            )

        tls: Tls | None = None
        if ja4_str is not None or ssldecrypted is not None or certificate is not None:
            tls = Tls(ja4_hash=ja4_str, decrypted=ssldecrypted, certificate=certificate)

        file_info: File | None = None
        if any(
            v is not None
            for v in (upload_filename, upload_filetype, filetype, unscannabletype, sha256, bamd5)
        ):
            file_info = File(
                name=upload_filename,
                upload_type=upload_filetype,
                download_type=filetype,
                unscannable_type=unscannabletype,
                hash_sha256=sha256,
                hash_md5=bamd5,
            )

        src_location: Location | None = None
        if srcip_country is not None or is_src_cntry_risky is not None:
            src_location = Location(country=srcip_country, is_risky=is_src_cntry_risky)

        dst_location: Location | None = None
        if dstip_country is not None or is_dst_cntry_risky is not None:
            dst_location = Location(country=dstip_country, is_risky=is_dst_cntry_risky)

        event_key = (
            f"{method or 'UNKNOWN'}:{urlcategory or 'unknown'}:{disposition}:"
            f"{_status_class(status)}"
        )

        return HTTPActivity(
            class_uid=self.ocsf_class_uid,
            category_uid=4,
            activity_name=action_raw,
            time=ts,
            source_type=self.source_type,
            line_no=line_no,
            event_key=event_key,
            actor=Actor(user=OcsfUser(email_addr=user, groups=groups)),
            src_endpoint=NetworkEndpoint(ip=clientip, location=src_location),
            dst_endpoint=(
                NetworkEndpoint(ip=serverip, location=dst_location) if serverip else None
            ),
            device=device,
            bypassed_traffic=bypassed_traffic,
            flow_type=flow_type,
            df_hostname=df_hostname,
            df_hosthead=df_hosthead,
            threat_severity=threatseverity,
            tls=tls,
            file=file_info,
            http_request=HttpRequest(
                url=Url(
                    hostname=host,
                    path=url,
                    category_ids=[urlcategory] if urlcategory else [],
                ),
                http_method=method,
                user_agent=ua,
                referrer=referer,
            ),
            http_response=HttpResponse(code=status) if status is not None else None,
            traffic=OcsfTraffic(bytes_out=bytes_out, bytes_in=bytes_in),
            disposition=disposition,
            risk_score=riskscore,
            malware=malware,
            unmapped=unmapped,
        )


def _parse_datetime(raw: str) -> datetime | None:
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _looks_like_json_object(line: str) -> bool:
    """Cheap-then-exact check that `line` is a JSON object line (never a ZScaler one -- a
    JSON-line source's candidate, back when Okta/CloudTrail were registered parsers) -- used to
    keep such lines out of the sniff fallback's denominator."""
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return False
    try:
        return isinstance(json.loads(stripped), dict)
    except (json.JSONDecodeError, TypeError, RecursionError):
        return False


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
