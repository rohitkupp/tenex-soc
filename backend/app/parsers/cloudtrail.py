"""AWS CloudTrail -> OCSF API Activity (6003). docs/03 "AWS CloudTrail".

JSON Lines, one record per physical line -- matching `datagen.emitters.cloudtrail`'s output
format exactly. Real CloudTrail's native export is a single `{"Records": [...]}` document, not
line-oriented; that shape cannot fit `LogParser.parse_line(line, line_no)`'s one-event-per-line
contract at all, so (matching docs/03's own framing of CloudTrail as "thin, mainly to prove the
interface generalizes") this parser only supports the Lines form. Flagged as a known limitation
in the M3 report rather than worked around.

Deliberately thin, per docs/03: eleven fields, nothing else.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.ocsf import Actor, Api, APIActivity, ApiService, Cloud, HttpRequest, NetworkEndpoint
from app.ocsf import User as OcsfUser
from app.parsers._json_lines import json_line_ratio, register_signature
from app.parsers.base import ParseFailure, excerpt

_SOURCE_TYPE = "cloudtrail"
_REQUIRED_KEYS = register_signature(
    _SOURCE_TYPE, ("eventSource", "eventName", "eventTime", "userIdentity")
)
_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class CloudTrailParser:
    # Not ClassVar -- see ZScalerParser's comment on the same pattern.
    source_type: str = "cloudtrail"
    ocsf_class_uid: int = 6003
    header_lines: int = 0

    # ------------------------------------------------------------------ sniff

    def sniff(self, sample: str) -> float:
        return json_line_ratio(sample, _SOURCE_TYPE)

    # ------------------------------------------------------------------ parse

    def parse_line(self, line: str, line_no: int) -> APIActivity | ParseFailure:
        try:
            return self._parse_line(line, line_no)
        except Exception as exc:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unexpected error: {exc}",
                raw_excerpt=excerpt(line),
            )

    def _parse_line(self, line: str, line_no: int) -> APIActivity | ParseFailure:
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

        event_time = obj.get("eventTime")
        if not isinstance(event_time, str):
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason="missing required field 'eventTime'",
                raw_excerpt=excerpt(line),
            )
        try:
            ts = datetime.strptime(event_time, _TS_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason=f"unparseable 'eventTime' timestamp {event_time!r}",
                raw_excerpt=excerpt(line),
            )

        event_name = obj.get("eventName")
        event_source = obj.get("eventSource")
        if not event_name or not event_source:
            return ParseFailure(
                source_type=self.source_type,
                line_no=line_no,
                reason="missing required field 'eventName' or 'eventSource'",
                raw_excerpt=excerpt(line),
            )

        user_identity = obj.get("userIdentity") or {}
        if not isinstance(user_identity, dict):
            user_identity = {}

        error_code = obj.get("errorCode")
        event_key = f"{event_source}:{event_name}:{error_code or 'OK'}"

        request_params = obj.get("requestParameters")
        response_elements = obj.get("responseElements")

        return APIActivity(
            class_uid=self.ocsf_class_uid,
            category_uid=6,
            activity_name=event_name,
            time=ts,
            source_type=self.source_type,
            line_no=line_no,
            event_key=event_key,
            actor=Actor(
                user=OcsfUser(uid=user_identity.get("arn"), type=user_identity.get("type"))
            ),
            src_endpoint=NetworkEndpoint(ip=obj.get("sourceIPAddress")),
            http_request=HttpRequest(user_agent=obj.get("userAgent")),
            api=Api(
                operation=event_name,
                service=ApiService(name=event_source),
                request=request_params if isinstance(request_params, dict) else None,
                response=response_elements if isinstance(response_elements, dict) else None,
            ),
            cloud=Cloud(region=obj.get("awsRegion")),
            status_code=error_code,
        )
