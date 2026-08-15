"""Okta System Log -> OCSF Authentication (3002). docs/03 "Okta System Log".

JSON Lines from the `/api/v1/logs` export, one vendor-native record per physical line — see
`datagen.emitters.okta`'s module docstring: "The line is the contract." `fields` there holds
Okta's own key names, nested exactly as Okta nests them, so this parser reads back precisely the
shape `OktaEmitter.build_event` writes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.ocsf import (
    Actor,
    Authentication,
    AutonomousSystem,
    GeoCoordinates,
    HttpRequest,
    Location,
    NetworkEndpoint,
    Resource,
)
from app.ocsf import User as OcsfUser
from app.parsers._json_lines import json_line_ratio, register_signature
from app.parsers.base import ParseFailure, excerpt

_SOURCE_TYPE = "okta"
_REQUIRED_KEYS = register_signature(_SOURCE_TYPE, ("eventType", "outcome", "actor", "client"))
_TS_FORMATS: tuple[str, ...] = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")


def _parse_datetime(raw: str) -> datetime | None:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


class OktaParser:
    # Not ClassVar -- see ZScalerParser's comment on the same pattern.
    source_type: str = "okta"
    ocsf_class_uid: int = 3002
    header_lines: int = 0

    # ------------------------------------------------------------------ sniff

    def sniff(self, sample: str) -> float:
        return json_line_ratio(sample, _SOURCE_TYPE)

    # ------------------------------------------------------------------ parse

    def parse_line(self, line: str, line_no: int) -> Authentication | ParseFailure:
        try:
            return self._parse_line(line, line_no)
        except Exception as exc:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unexpected error: {exc}",
                raw_excerpt=excerpt(line),
            )

    def _parse_line(self, line: str, line_no: int) -> Authentication | ParseFailure:
        stripped = line.strip()
        if not stripped:
            return ParseFailure(
                source_type=self.source_type, line_no=line_no, reason="empty line", raw_excerpt=""
            )
        try:
            obj: Any = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"invalid JSON: {exc}",
                raw_excerpt=excerpt(line),
            )
        if not isinstance(obj, dict):
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"expected a JSON object, got {type(obj).__name__}",
                raw_excerpt=excerpt(line),
            )

        published = obj.get("published")
        if not isinstance(published, str):
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason="missing required field 'published'",
                raw_excerpt=excerpt(line),
            )
        ts = _parse_datetime(published)
        if ts is None:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unparseable 'published' timestamp {published!r}",
                raw_excerpt=excerpt(line),
            )

        event_type = obj.get("eventType")
        outcome = obj.get("outcome") or {}
        if not isinstance(outcome, dict):
            outcome = {}
        result = outcome.get("result")
        actor = obj.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        client = obj.get("client") or {}
        if not isinstance(client, dict):
            client = {}
        client_ua = client.get("userAgent") or {}
        if not isinstance(client_ua, dict):
            client_ua = {}
        geo = client.get("geographicalContext") or {}
        if not isinstance(geo, dict):
            geo = {}
        geolocation = geo.get("geolocation") or {}
        if not isinstance(geolocation, dict):
            geolocation = {}
        security_ctx = obj.get("securityContext") or {}
        if not isinstance(security_ctx, dict):
            security_ctx = {}
        auth_ctx = obj.get("authenticationContext") or {}
        if not isinstance(auth_ctx, dict):
            auth_ctx = {}
        debug_ctx = obj.get("debugContext") or {}
        if not isinstance(debug_ctx, dict):
            debug_ctx = {}
        targets = obj.get("target")
        if not isinstance(targets, list):
            targets = []

        coordinates = None
        if geolocation.get("lat") is not None or geolocation.get("lon") is not None:
            coordinates = GeoCoordinates(lat=geolocation.get("lat"), lon=geolocation.get("lon"))

        location = None
        if geo.get("country") is not None or geo.get("city") is not None or coordinates:
            location = Location(
                country=geo.get("country"), city=geo.get("city"), coordinates=coordinates
            )

        as_number = security_ctx.get("asNumber")
        autonomous_system = AutonomousSystem(number=as_number) if as_number is not None else None

        resources = [
            Resource(
                type=t.get("type") if isinstance(t, dict) else None,
                uid=t.get("id") if isinstance(t, dict) else None,
                name=(t.get("displayName") or t.get("alternateId"))
                if isinstance(t, dict)
                else None,
            )
            for t in targets
        ]

        unmapped: dict[str, Any] = {}
        is_proxy = security_ctx.get("isProxy")
        if is_proxy is not None:
            unmapped["is_proxy"] = is_proxy
        debug_data = debug_ctx.get("debugData")
        if debug_data:
            unmapped["debug"] = debug_data

        event_key = f"{event_type}:{result}"

        return Authentication(
            class_uid=self.ocsf_class_uid,
            category_uid=3,
            activity_name=event_type,
            time=ts,
            source_type=self.source_type,
            line_no=line_no,
            event_key=event_key,
            actor=Actor(
                user=OcsfUser(email_addr=actor.get("alternateId"), name=actor.get("displayName"))
            ),
            src_endpoint=NetworkEndpoint(
                ip=client.get("ipAddress"),
                location=location,
                autonomous_system=autonomous_system,
            ),
            http_request=HttpRequest(user_agent=client_ua.get("rawUserAgent")),
            status=result,
            status_detail=outcome.get("reason"),
            # docs/03 literally maps authenticationContext.authenticationStep -> auth_protocol.
            # That is an odd name for what is really a sub-factor step counter (0/1 in this
            # corpus), not a protocol identifier -- kept verbatim per the spec rather than
            # "corrected", and flagged in the M3 report as a spec quirk worth a second look.
            auth_protocol=auth_ctx.get("authenticationStep"),
            resources=resources,
            unmapped=unmapped,
        )
