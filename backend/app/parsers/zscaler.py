"""ZScaler NSS Web proxy logs -> OCSF HTTP Activity (4002). docs/03 "ZScaler NSS Web".

Tab- or comma-delimited with a header line (docs/03), matching `datagen.emitters.zscaler`'s
output exactly: `FIELDS`, in that module, is "docs/03 ... in the order that table lists them" —
the same 25-field order hardcoded below as `_CANONICAL_FIELDS`. That is not a coincidence to
preserve; it is the parser and the generator agreeing independently on what the spec says, which
is the round-trip proof M3's acceptance bar asks for.

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

import json
from datetime import UTC, datetime
from typing import Any

from app.ocsf import (
    Actor,
    HTTPActivity,
    HttpRequest,
    HttpResponse,
    Malware,
    NetworkEndpoint,
    Url,
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

        user = _none_if_sentinel(values.get("user"))
        clientip = _none_if_sentinel(values.get("clientip"))
        serverip = _none_if_sentinel(values.get("serverip"))
        host = _none_if_sentinel(values.get("host"))
        url = _none_if_sentinel(values.get("url"))
        method = _none_if_sentinel(values.get("requestmethod"))
        status = _to_int(_none_if_sentinel(values.get("status")))
        bytes_out = _to_int(_none_if_sentinel(values.get("requestsize")))
        bytes_in = _to_int(_none_if_sentinel(values.get("responsesize")))
        ua = _none_if_sentinel(values.get("useragent"))
        action_raw = _none_if_sentinel(values.get("action"))
        disposition = _normalize_action(action_raw)
        urlcategory = _none_if_sentinel(values.get("urlcategory"))
        urlsupercategory = _none_if_sentinel(values.get("urlsupercategory"))
        appname = _none_if_sentinel(values.get("appname"))
        appclass = _none_if_sentinel(values.get("appclass"))
        threatname = _none_if_sentinel(values.get("threatname"))
        threatcategory = _none_if_sentinel(values.get("threatcategory"))
        riskscore = _to_int(_none_if_sentinel(values.get("riskscore")))
        reason = _none_if_sentinel(values.get("reason"))
        referer = _none_if_sentinel(values.get("referer"))
        dlpengine = _none_if_sentinel(values.get("dlpengine"))
        dlpdictionaries = _none_if_sentinel(values.get("dlpdictionaries"))
        location = _none_if_sentinel(values.get("location"))
        department = _none_if_sentinel(values.get("department"))

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

        malware: list[Malware] = []
        if threatname is not None:
            malware.append(
                Malware(
                    name=threatname,
                    classification_ids=[threatcategory] if threatcategory else [],
                )
            )

        groups = [g for g in (location, department) if g is not None]

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
            src_endpoint=NetworkEndpoint(ip=clientip),
            dst_endpoint=NetworkEndpoint(ip=serverip) if serverip else None,
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
