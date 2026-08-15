"""Typed OCSF event classes (docs/13 M3).

ZScaler is the only source this pipeline parses (Okta and CloudTrail, and their OCSF
Authentication (3002) / API Activity (6003) classes, were removed — see `app/parsers/registry.py`
for the extensibility argument that survives their removal). `OCSFEvent` is the return-type alias
`app/parsers`'s `LogParser.parse_line` uses, matching docs/03's `LogParser` Protocol verbatim
(`parse_line(...) -> OCSFEvent | ParseFailure`) -- kept as a union (of one member today) rather
than collapsed to `HTTPActivity` outright, so a future second parser only has to add its class
back into this alias, not touch every call site that names `OCSFEvent`.
"""

from __future__ import annotations

from app.ocsf.base import OCSFEventBase
from app.ocsf.common import (
    Actor,
    Api,
    ApiService,
    AutonomousSystem,
    Cloud,
    GeoCoordinates,
    HttpRequest,
    HttpResponse,
    Location,
    Malware,
    NetworkEndpoint,
    Resource,
    Traffic,
    Url,
    User,
)
from app.ocsf.http_activity import CATEGORY_UID as HTTP_ACTIVITY_CATEGORY_UID
from app.ocsf.http_activity import CLASS_UID as HTTP_ACTIVITY_CLASS_UID
from app.ocsf.http_activity import HTTPActivity

OCSFEvent = HTTPActivity

__all__ = [
    "HTTP_ACTIVITY_CATEGORY_UID",
    "HTTP_ACTIVITY_CLASS_UID",
    "Actor",
    "Api",
    "ApiService",
    "AutonomousSystem",
    "Cloud",
    "GeoCoordinates",
    "HTTPActivity",
    "HttpRequest",
    "HttpResponse",
    "Location",
    "Malware",
    "NetworkEndpoint",
    "OCSFEvent",
    "OCSFEventBase",
    "Resource",
    "Traffic",
    "Url",
    "User",
]
