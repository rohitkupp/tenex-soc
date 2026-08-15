"""Event-level pseudonymization (docs/06-PRIVACY-SECURITY.md "Pseudonymization").

The seam function `app/workers`' anonymizer worker is expected to call: it runs after
enrichment (which needs real values, docs/03) and before detect (docs/01's stage table --
"anonymize | events enriched | `pseudonym_map` written, `events.redacted` populated").

Applies docs/06's do/do-NOT list to a hot-column-shaped event mapping:

    Pseudonymize: usernames, email addresses, IPs, hostnames, session IDs, device IDs.
    Do NOT pseudonymize: domains (needed for threat intelligence), user-agent strings,
    HTTP methods, status codes, byte counts, timestamps.

The do-NOT list is enforced *by omission*, not by a denylist check: `_PSEUDONYMIZE_FIELDS`
below is the complete allowlist of keys this function will ever touch, and every key not in
it -- `domain`, `user_agent`, `http_method`, `status_code`, `bytes_in`, `bytes_out`, `ts`,
`action`, `url_path`, and anything else on the input -- is copied through to the output
completely unchanged. That is deliberate: an allowlist can only fail closed (a field docs/06
says must be pseudonymized but that this module doesn't yet know about stays in plaintext,
which is a visible, testable gap -- see the module docstring's accounting below); a denylist
of the do-NOT fields could fail *open* the moment a new identifying field is added upstream
and nobody remembers to add it to the denylist. Getting this the wrong way round is exactly
the class of defect docs/06 calls out ("Getting this wrong in either direction is a real
defect").

**What the current OCSF schema (`app/ocsf`, `app/parsers` -- a concurrent agent's ownership,
M3) actually carries today:** `principal` (kind `"user"`), `src_ip`/`dst_ip` (kind `"ip"`).
It does not yet expose a device/workstation hostname distinct from `domain` -- the http_request
URL hostname is exactly the "domain" docs/06 says must stay plaintext, a different concept
entirely from a client machine's own hostname -- nor a session ID or device ID field. This
function still accepts `hostname`/`session_id`/`device_id` as optional input keys so that
the moment a parser starts emitting one of them under these names, it is pseudonymized
correctly with zero changes here; until then those three kinds are exercised only by this
package's own unit tests (`tests/test_privacy_pseudonymize.py`), not by any live event field.
Flagged here plainly rather than left to be discovered later.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.privacy.pseudonymize import PseudonymKind, pseudonymize
from app.privacy.reverse_map import ReverseMapEntry

# event key -> pseudonymize() kind. The complete allowlist -- see module docstring.
_PSEUDONYMIZE_FIELDS: dict[str, PseudonymKind] = {
    "principal": "user",
    "src_ip": "ip",
    "dst_ip": "ip",
    "hostname": "host",  # not yet emitted by any parser -- see module docstring
    "session_id": "session",  # not yet emitted by any parser
    "device_id": "device",  # not yet emitted by any parser
}


@dataclass(frozen=True, slots=True)
class AnonymizedEvent:
    event: dict[str, Any]
    reverse_entries: tuple[ReverseMapEntry[Any], ...]


def anonymize_event(event: Mapping[str, Any], *, tenant_id: Any, salt: bytes) -> AnonymizedEvent:
    """Pseudonymize the identifiable hot-column fields of one event. Returns a *new* dict
    (`event` is never mutated) plus the reverse-map rows the anonymizer worker should
    persist so that tenant's own UI can later render the real values back
    (`reverse_map.PseudonymReverseMap.record_many` accepts this tuple directly).

    Empty string and `None` are both treated as "no value" and left alone -- pseudonymizing
    an empty string would still produce a deterministic, technically-valid-looking pseudonym
    that means nothing, which is worse than just leaving the field empty.
    """
    out = dict(event)
    entries: list[ReverseMapEntry[Any]] = []
    for field, kind in _PSEUDONYMIZE_FIELDS.items():
        value = out.get(field)
        if not value:
            continue
        original = str(value)
        pseudonym = pseudonymize(original, kind, salt)
        out[field] = pseudonym
        entries.append(
            ReverseMapEntry(
                tenant_id=tenant_id, kind=kind, pseudonym=pseudonym, original_value=original
            )
        )
    return AnonymizedEvent(event=out, reverse_entries=tuple(entries))


def anonymize_events(
    events: Iterable[Mapping[str, Any]], *, tenant_id: Any, salt: bytes
) -> list[AnonymizedEvent]:
    """Batch convenience -- same order as `events`."""
    return [anonymize_event(event, tenant_id=tenant_id, salt=salt) for event in events]
