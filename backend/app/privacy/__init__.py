"""Pseudonymization and redaction (docs/06-PRIVACY-SECURITY.md, normative; docs/13-
MILESTONES.md M5). Everything here runs before anything leaves the tenant boundary --
before the LLM, before Tier 2 (docs/06).

**Pseudonymize** (HMAC-SHA256, deterministic per tenant -- `pseudonymize.py`): usernames,
email addresses, IPs, hostnames, session IDs, device IDs.

**Do NOT pseudonymize**: domains (needed for threat intelligence -- every downstream DGA/
threat-intel detector depends on this), user-agent strings, HTTP methods, status codes,
byte counts, timestamps. `event_privacy.py`'s `anonymize_event` enforces this by allowlist,
not denylist -- see that module's docstring for why the difference matters.

**Redact** (`redact.py`, patterns in `redaction_patterns.yml`): secrets and PII embedded in
free-text fields -- API tokens, bearer headers, AWS keys, JWTs, private key blocks,
Luhn-valid card numbers, emails in URL paths. Lossy and irreversible by design, with a count
per pattern so the UI can report "N secrets redacted before LLM submission."

**Reverse map** (`reverse_map.py`): a tenant-scoped, in-memory reference implementation of
the pseudonym -> original-value lookup docs/06 says exists *only* to render values back in
that tenant's own UI -- never a prompt, a Tier 2 record, or a log line.

**Tier 2 exception** (`pseudonymize.indicator_hash`): domains and dst IPs going into
`tier2_signatures.indicator_hashes` (docs/02) use a *separate*, shared cross-tenant salt so
cross-tenant indicator overlap is detectable -- a deliberate privacy/utility tradeoff, not an
inconsistency with the do-NOT-pseudonymize-domains rule above (that rule is about the normal
per-tenant event/prompt path; this is a distinct mechanism entirely). See
`pseudonymize.py`'s `indicator_hash` docstring. Phase 2 detection fields (this task) extend the
same exception to two more identifier kinds: `file_hash` (`sha256`/`bamd5`) and `ja4` (`ja4_str`)
-- both are indicators whose Tier 2 value depends on the same raw value hashing identically
across tenants, exactly like a domain, so they route through `indicator_hash`'s shared salt at
*both* boundaries this package cares about (an LLM prompt and a Tier 2 signature), not through
`pseudonymize`'s per-tenant one -- see `_INDICATOR_KINDS`'s comment in `pseudonymize.py`.

Public surface:

    pseudonymize(value: str, kind: str, salt: bytes) -> str
    indicator_hash(value: str, kind: Literal["domain", "ip", "file_hash", "ja4"], shared_salt: bytes) -> str
    anonymize_event(event: Mapping, *, tenant_id, salt: bytes) -> AnonymizedEvent
    anonymize_events(events, *, tenant_id, salt: bytes) -> list[AnonymizedEvent]
    redact_text(text: str) -> RedactionResult
    redact_many(texts: Iterable[str | None]) -> tuple[list[str | None], dict[str, int]]
    PseudonymReverseMap, ReverseMapEntry
"""

from __future__ import annotations

from app.privacy.event_privacy import AnonymizedEvent, anonymize_event, anonymize_events
from app.privacy.pseudonymize import PREFIX, PseudonymKind, indicator_hash, pseudonymize
from app.privacy.redact import RedactionResult, redact_many, redact_text
from app.privacy.reverse_map import PseudonymReverseMap, ReverseMapEntry

__all__ = [
    "PREFIX",
    "AnonymizedEvent",
    "PseudonymKind",
    "PseudonymReverseMap",
    "RedactionResult",
    "ReverseMapEntry",
    "anonymize_event",
    "anonymize_events",
    "indicator_hash",
    "pseudonymize",
    "redact_many",
    "redact_text",
]
