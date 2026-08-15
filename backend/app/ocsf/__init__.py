"""Typed OCSF event classes for the three classes docs/03 names (docs/13 M3).

`OCSFEvent` is the return-type alias `app/parsers`'s `LogParser.parse_line` uses, matching
docs/03's `LogParser` Protocol verbatim (`parse_line(...) -> OCSFEvent | ParseFailure`).
"""

from __future__ import annotations

from app.ocsf.api_activity import CATEGORY_UID as API_ACTIVITY_CATEGORY_UID
from app.ocsf.api_activity import CLASS_UID as API_ACTIVITY_CLASS_UID
from app.ocsf.api_activity import APIActivity
from app.ocsf.authentication import CATEGORY_UID as AUTHENTICATION_CATEGORY_UID
from app.ocsf.authentication import CLASS_UID as AUTHENTICATION_CLASS_UID
from app.ocsf.authentication import Authentication
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

OCSFEvent = HTTPActivity | Authentication | APIActivity

__all__ = [
    "API_ACTIVITY_CATEGORY_UID",
    "API_ACTIVITY_CLASS_UID",
    "AUTHENTICATION_CATEGORY_UID",
    "AUTHENTICATION_CLASS_UID",
    "HTTP_ACTIVITY_CATEGORY_UID",
    "HTTP_ACTIVITY_CLASS_UID",
    "APIActivity",
    "Actor",
    "Api",
    "ApiService",
    "Authentication",
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
