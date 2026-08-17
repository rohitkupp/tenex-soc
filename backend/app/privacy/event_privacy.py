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

**What the current OCSF schema (`app/ocsf`, `app/parsers`) actually carries today:** `principal`
(kind `"user"`), `src_ip`/`dst_ip` (kind `"ip"`), plus the asset/device hot columns the asset-tag
task added: `hostname` (kind `"host"` -- a Zscaler Client Connector device's own hostname,
`"THINKPADSMITH"`, a different concept entirely from `domain`, which is the http_request URL
hostname docs/06 says must stay plaintext), `device_name` (kind `"device"` -- the opaque
hash-suffixed device identifier, `"PC11NLPA:5F08D97B..."`), and `device_owner` (kind `"user"` --
the asset's assigned username, e.g. `"jsmith"`; a *different* value from `principal` when a device
is shared/borrowed, which is exactly why `app.graph.asset_tags` tags that divergence rather than
treating the two as redundant). `os_type`/`os_version`/`bypassed_traffic`/`flow_type` are
deliberately **not** in `_PSEUDONYMIZE_FIELDS` below -- categorical/behavioral metadata, not
identifiers, the same status `user_agent`/`http_method`/`status_code` already have on docs/06's
do-NOT list.

This function still accepts `session_id` as an optional input key so that the moment a parser
starts emitting one under that name, it is pseudonymized correctly with zero changes here; that
kind is exercised only by this package's own unit tests (`tests/test_privacy_pseudonymize.py`),
not by any live event field. Flagged here plainly rather than left to be discovered later.

**`ja4_hash` (Phase 2, this task) is a hot column but deliberately excluded from
`_PSEUDONYMIZE_FIELDS`.** It is an identifier (a client TLS fingerprint, tracking-capable) and
does need to be routed through the HMAC path before it reaches an LLM prompt or a Tier 2 record
(CLAUDE.md rule 4) -- but not through *this* module's per-tenant `pseudonymize()`. Unlike every
field in `_PSEUDONYMIZE_FIELDS`, a JA4 fingerprint's value as a detection signal depends on the
*same raw string* hashing to the *same pseudonym* across different tenants (that recurrence is
the whole Tier 2 point -- "this exact fingerprint showed up in three other tenants too"); a
per-tenant salt would make an identical fingerprint hash differently per tenant and silently
break that comparison, the same failure mode `domain` already has an exception for. It routes
through `app.privacy.pseudonymize.indicator_hash` (the shared, cross-tenant salt) at whichever
call site actually serializes it to a prompt or a `tier2_signatures` row instead -- not wired up
here, since this task's cost constraint is "nothing under `app/agent/` may execute" and no Tier 2
consumer for this specific field exists yet either. `sha256`/`bamd5` (also Phase 2, also
identifiers, also indicator_hash-routed by the same reasoning) never reach even that decision
point today: they are not hot columns (`app.ocsf.common.File`, `ocsf` JSONB only), so they are
outside this hot-column-shaped function's contract entirely, same status `urlcategory`/
`threatname` already have.

**Not wired into the LLM prompt boundary (`app.agent.tools._serialize_event`), by design.** The
asset/device fields above are asset-inventory metadata, irrelevant to the disposition/narrative/
technique-mapping judgement CLAUDE.md scopes the LLM to (rule 5) and to this task's own explicit
requirement that the tagging service itself contain no LLM. The safest privacy posture for a field
the LLM's job never needs is exclusion, not "expose it and then pseudonymize it" -- a field that
never crosses the boundary needs no pseudonymization *at* that boundary to already be safe. They
are registered here (the pipeline-wide `anonymize` stage audit, `app.pipeline.stages.anonymize`)
so the audit's reported "N identifiers pseudonymizable" count stays honest about every identifier
this pipeline now carries, independent of whether any of them ever reach a prompt.
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
    "hostname": "host",  # Client Connector device hostname (this task) -- see module docstring
    "device_name": "device",  # opaque device identifier (this task)
    "device_owner": "user",  # the asset's assigned user (this task)
    "session_id": "session",  # not yet emitted by any parser
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
