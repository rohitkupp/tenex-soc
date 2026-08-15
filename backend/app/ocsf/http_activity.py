"""OCSF HTTP Activity (4002) — ZScaler NSS Web -> OCSF (docs/03).

Category 4 (Network Activity), class 4002, matching real OCSF's own numbering — the reviewing
team came from Chronicle/UDM, so getting the taxonomy numbers right rather than inventing our own
is a small but deliberate nod to that (see docs/03 "Why OCSF").
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import Field

from app.ocsf.base import OCSFEventBase
from app.ocsf.common import HttpRequest, HttpResponse, Malware, Traffic

# Module-level constants, not class attributes -- `ClassVar` is only valid inside a class body;
# mypy rejects it here even though the two are otherwise interchangeable at this scope.
CLASS_UID: Final[int] = 4002
CATEGORY_UID: Final[int] = 4


class HTTPActivity(OCSFEventBase):
    """One ZScaler NSS Web transaction.

    `disposition` carries the docs/03 action-normalization result (`allowed` / `blocked` /
    `other`); `activity_name` carries the vendor's own literal `action` string (`Allowed`,
    `Blocked`, ...) unchanged, so the raw verdict survives even though the hot `action` column
    (see `hot_columns`) uses the normalized token detectors actually key on.
    """

    http_request: HttpRequest | None = None
    http_response: HttpResponse | None = None
    traffic: Traffic | None = None
    disposition: str | None = None
    risk_score: int | None = None
    malware: list[Malware] = Field(default_factory=list)

    def hot_columns(self) -> dict[str, Any]:
        url = self.http_request.url if self.http_request else None
        return {
            "ts": self.time,
            "source_type": self.source_type,
            "raw_line_no": self.line_no,
            "ocsf_class_uid": self.class_uid,
            "principal": self.actor.user.email_addr,
            "src_ip": self.src_endpoint.ip,
            "dst_ip": self.dst_endpoint.ip if self.dst_endpoint else None,
            "domain": url.hostname if url else None,
            "url_path": url.path if url else None,
            "action": self.disposition,
            "http_method": self.http_request.http_method if self.http_request else None,
            "status_code": self.http_response.code if self.http_response else None,
            "bytes_out": self.traffic.bytes_out if self.traffic else None,
            "bytes_in": self.traffic.bytes_in if self.traffic else None,
            "user_agent": self.http_request.user_agent if self.http_request else None,
            "event_key": self.event_key,
        }
