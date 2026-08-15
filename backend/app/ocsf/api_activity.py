"""OCSF API Activity (6003) — AWS CloudTrail -> OCSF (docs/03).

Category 6 (Application Activity), class 6003, matching real OCSF's numbering (see
http_activity.py's docstring for why that number is not arbitrary here). docs/03 is explicit that
CloudTrail is deliberately thin ("exists mainly to prove the parser interface generalizes") — this
class carries exactly the eleven fields docs/03's table names and nothing more.
"""

from __future__ import annotations

from typing import Any, Final

from app.ocsf.base import OCSFEventBase
from app.ocsf.common import Api, Cloud, HttpRequest

# Module-level constants, not class attributes -- see http_activity.py's identical note.
CLASS_UID: Final[int] = 6003
CATEGORY_UID: Final[int] = 6


class APIActivity(OCSFEventBase):
    """One CloudTrail management-event record.

    `status_code` is docs/03's literal mapping of `errorCode` — a **string** (`"AccessDenied"`,
    `"ThrottlingException"`, ...) or `None` on success, never an HTTP-style integer. Kept as
    `str | None` here (in the OCSF-fidelity field, and therefore in the `ocsf` JSONB column the
    event-store writer persists verbatim) because that is what the source actually produces;
    coercing it to an int on this object would just be a different, silent lie.

    This is a genuine, verified disagreement with docs/02's `events.status_code INTEGER` hot
    column: `app/storage/event_writer.py` (built independently against docs/02) types its
    `EventRecord.status_code` as `int | None` and hands it straight to psycopg's COPY protocol,
    which would raise on a non-numeric string. `hot_columns()` below is a *projection*, not a
    same-name passthrough (docs/02: hot columns are "a projection of" `ocsf`, not a second source
    of truth) — so it deliberately leaves the hot `status_code` column `None` for every CloudTrail
    event rather than ever attempting to write `errorCode` into an integer column. The full,
    untruncated `errorCode` string always survives in `ocsf.status_code`, so nothing is lost; it
    is just not available as a filterable hot column under its docs/03 name without a docs/02
    schema change (widening the column to `TEXT`, most likely) that is outside this package's
    ownership. Flagged prominently in the M3 report.

    `principal` (see `hot_columns`) reads from `actor.user.uid`, not `email_addr` — CloudTrail is
    the one source docs/03 identifies by ARN rather than email.
    """

    http_request: HttpRequest | None = None
    api: Api | None = None
    cloud: Cloud | None = None
    status_code: str | None = None

    def hot_columns(self) -> dict[str, Any]:
        return {
            "ts": self.time,
            "source_type": self.source_type,
            "raw_line_no": self.line_no,
            "ocsf_class_uid": self.class_uid,
            "principal": self.actor.user.uid,
            "src_ip": self.src_endpoint.ip,
            "dst_ip": None,
            "domain": None,
            "url_path": None,
            "action": None,
            "http_method": None,
            # Deliberately None, not self.status_code -- see the class docstring. The real value
            # is never lost: it is always in the OCSF blob at `ocsf["status_code"]`.
            "status_code": None,
            "bytes_out": None,
            "bytes_in": None,
            "user_agent": self.http_request.user_agent if self.http_request else None,
            "event_key": self.event_key,
        }
