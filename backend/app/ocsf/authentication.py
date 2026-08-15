"""OCSF Authentication (3002) — Okta System Log -> OCSF (docs/03).

Category 3 (IAM), class 3002, matching real OCSF's numbering (see http_activity.py's docstring
for why that number is not arbitrary here).
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import Field

from app.ocsf.base import OCSFEventBase
from app.ocsf.common import HttpRequest, Resource

# Module-level constants, not class attributes -- see http_activity.py's identical note.
CLASS_UID: Final[int] = 3002
CATEGORY_UID: Final[int] = 3


class Authentication(OCSFEventBase):
    """One Okta System Log event.

    `auth_protocol` is docs/03's literal mapping of `authenticationContext.authenticationStep`
    (an integer sub-factor counter, 0 or 1 in the corpus, not a protocol name) — an odd-looking
    but intentional mapping; see this parser's module docstring in `app/parsers/okta.py` for the
    same note next to the code that implements it.
    """

    http_request: HttpRequest | None = None
    status: str | None = None
    status_detail: str | None = None
    auth_protocol: int | None = None
    resources: list[Resource] = Field(default_factory=list)

    def hot_columns(self) -> dict[str, Any]:
        return {
            "ts": self.time,
            "source_type": self.source_type,
            "raw_line_no": self.line_no,
            "ocsf_class_uid": self.class_uid,
            "principal": self.actor.user.email_addr,
            "src_ip": self.src_endpoint.ip,
            "dst_ip": None,
            "domain": None,
            "url_path": None,
            # docs/03: `outcome.result -> status -> action` — Authentication's hot `action`
            # column carries the SUCCESS/FAILURE/... outcome, the identity-source analogue of
            # ZScaler's allowed/blocked/other.
            "action": self.status,
            "http_method": None,
            "status_code": None,
            "bytes_out": None,
            "bytes_in": None,
            "user_agent": self.http_request.user_agent if self.http_request else None,
            "event_key": self.event_key,
        }
