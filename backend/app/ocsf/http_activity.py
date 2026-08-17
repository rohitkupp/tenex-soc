"""OCSF HTTP Activity (4002) — ZScaler NSS Web -> OCSF (docs/03).

Category 4 (Network Activity), class 4002, matching real OCSF's own numbering — the reviewing
team came from Chronicle/UDM, so getting the taxonomy numbers right rather than inventing our own
is a small but deliberate nod to that (see docs/03 "Why OCSF").
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import Field

from app.ocsf.base import OCSFEventBase
from app.ocsf.common import File, HttpRequest, HttpResponse, Malware, Tls, Traffic

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
    # Client-Connector-transaction fields (docs/v1/zscaler-nss-web-fields.md "Zscaler Client
    # Connector Device Information" + "Miscellaneous"), first-class on the event rather than
    # buried in `unmapped` — like `disposition`/`risk_score` above, these are security-relevant on
    # their own (a device bypassing the Client Connector is unmonitored traffic), not inventory.
    bypassed_traffic: bool | None = None
    flow_type: str | None = None
    # Phase 2 detection fields (docs/v1/zscaler-nss-web-fields.md "HTTP Transaction",
    # "Threat Protection", "SSL/TLS", "Server Connection", "Sandbox", "File Type Control") — see
    # this task's report for the per-field detector-design note. `df_hostname`/`df_hosthead` keep
    # the PDF's own literal NSS token names (same precedent `bypassed_traffic`/`flow_type` set):
    # no prior "friendly" name to preserve continuity with, and "domain fronting" doesn't map onto
    # any existing OCSF-ish path on this event. `threat_severity` is a light rename matching its
    # sibling `risk_score`'s own precedent (both are Threat Protection fields already renamed from
    # their raw `%s{...}` spelling).
    df_hostname: str | None = None
    df_hosthead: str | None = None
    threat_severity: str | None = None
    tls: Tls | None = None
    file: File | None = None

    def hot_columns(self) -> dict[str, Any]:
        url = self.http_request.url if self.http_request else None
        os_ = self.device.os if self.device else None
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
            # Device/asset hot columns (this task's own gap-close — see
            # `app.models.event.Event`'s module docstring section on them).
            "hostname": self.device.hostname if self.device else None,
            "device_name": self.device.name if self.device else None,
            "device_owner": self.device.owner if self.device else None,
            "os_type": os_.type if os_ else None,
            "os_version": os_.version if os_ else None,
            "bypassed_traffic": self.bypassed_traffic,
            "flow_type": self.flow_type,
            # Phase 2's one hot column: `ja4_str` is the field this task's brief calls out as
            # "a better cross-tenant Tier 2 indicator than a domain" — the only new field worth
            # the indexed-column cost (`app.models.event.Event`'s new `ja4_hash` index); every
            # other Phase 2 field rides in `ocsf` JSONB only, same treatment `urlcategory`/
            # `threatname`/... already get.
            "ja4_hash": self.tls.ja4_hash if self.tls else None,
        }
