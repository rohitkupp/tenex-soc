"""HMAC pseudonymization (docs/06-PRIVACY-SECURITY.md "Pseudonymization", normative).

Implements the doc's spec byte for byte:

    def pseudonymize(value: str, kind: str, salt: bytes) -> str:
        digest = hmac.new(salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
        return f"{PREFIX[kind]}_{digest[:12]}"     # u_8f3a91c204de, ip_1b7e..., h_...

Deterministic within one `(value, kind, salt)` triple: the same input always produces the
same pseudonym, which is what keeps entities correlatable across a whole analysis (docs/06)
-- the same principal's pseudonym is identical in every event it appears in. Not reversible
without both the salt and the original value: an attacker who only sees the pseudonym has no
feasible way back (HMAC-SHA256 is a one-way PRF; see `tests/test_privacy_pseudonymize.py`
for the non-reversibility argument this module's docstrings promise). The *only* sanctioned
way back is the tenant-scoped reverse map (`reverse_map.py`), and only for that tenant's own
UI -- never a prompt, a Tier 2 record, or a log line (docs/06).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final, Literal, get_args

PseudonymKind = Literal["user", "ip", "host", "session", "device"]

# docs/06 gives three worked examples (u_, ip_, h_) for three of the six things it says must
# be pseudonymized (usernames, IPs, hostnames); this table adds the other three (email
# addresses share "user" with usernames -- both identify a principal, and `events.principal`
# is exactly one merged column for both per docs/02 -- plus session IDs and device IDs, which
# docs/06 lists but doesn't give example prefixes for).
PREFIX: Final[dict[PseudonymKind, str]] = {
    "user": "u",
    "ip": "ip",
    "host": "h",
    "session": "sess",
    "device": "dev",
}

# docs/06's Tier 2 exception is a *separate* mechanism (see `indicator_hash` below),
# deliberately not reachable through `PREFIX`/`pseudonymize()` -- domains must never be
# pseudonymized on the normal per-tenant path (see the do-NOT list in this package's
# `__init__` docstring).
#
# `file_hash`/`ja4` (Phase 2 detection fields, this task -- docs/v1/zscaler-nss-web-fields.md
# "Sandbox", "SSL/TLS") join `domain`/`ip` here for a reason specific to them: unlike
# `principal`/`src_ip`/the device fields (which only ever need to stay *self-consistent within
# one tenant*, exactly what `pseudonymize()`'s per-tenant salt gives), a file hash
# (`sha256`/`bamd5`) or a JA4 client fingerprint is valuable specifically *because* the same raw
# value can recur across unrelated tenants -- that recurrence is the whole Tier 2 signal ("this
# exact malware hash / this exact TLS fingerprint showed up in three other tenants too"). Hashing
# either one under a per-tenant salt would make the same real-world indicator hash to a different
# pseudonym in every tenant, silently making that overlap uncomputable -- the identical failure
# mode this comment's sibling note already states for `domain`/`ip`. So `file_hash`/`ja4` route
# through *this* function, with the shared salt, at both boundaries CLAUDE.md rule 4 cares about
# (an LLM prompt, a Tier 2 signature) -- there is no second, per-tenant-salted pseudonym for them
# to also carry, unlike the identity fields in `PREFIX` above. `sha256` and `bamd5` (MD5) share
# one `file_hash` kind rather than getting `sha256`/`md5` kinds of their own: a Tier 2 consumer
# cares whether *this file* recurred, not which algorithm produced the hash string that proves it,
# and the two algorithms' outputs never collide in value space regardless.
_INDICATOR_KINDS = ("domain", "ip", "file_hash", "ja4")
INDICATOR_PREFIX: Final[dict[str, str]] = {"domain": "d", "ip": "ip", "file_hash": "fh", "ja4": "j"}


def pseudonymize(value: str, kind: str, salt: bytes) -> str:
    """docs/06's `pseudonymize`, verbatim. `kind` must be one of `PREFIX`'s keys -- an
    unknown kind raises rather than silently reusing some default prefix, because a typo'd
    kind string would otherwise start colliding two different entity types into the same
    pseudonym namespace with no error anywhere."""
    if kind not in PREFIX:
        raise ValueError(
            f"unknown pseudonymization kind: {kind!r}; expected one of {sorted(PREFIX)}"
        )
    digest = hmac.new(salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{PREFIX[kind]}_{digest[:12]}"


def indicator_hash(
    value: str, kind: Literal["domain", "ip", "file_hash", "ja4"], shared_salt: bytes
) -> str:
    """docs/06's Tier 2 exception, quoted here in full because it is easy to misread as
    "reuse pseudonymize() with a different salt" -- it is not:

        "indicator hashes (domains, dst IPs) use a *shared* salt across tenants so
        cross-tenant overlap is detectable. That is a deliberate privacy/utility
        tradeoff[.]"

    `file_hash` (`sha256`/`bamd5`) and `ja4` (`ja4_str`) extend that same exception to two more
    Phase 2 detection fields (this task) for the identical reason -- see `_INDICATOR_KINDS`'s own
    comment above for the full argument: both are indicators whose entire Tier 2 value depends on
    the *same raw value* hashing to the *same pseudonym* across tenants, which a per-tenant salt
    would break.

    This is the *only* place a domain (or now a file hash / JA4 fingerprint) is ever hashed
    anywhere in this package -- and only for constructing `tier2_signatures.indicator_hashes`
    (docs/02) or an equivalent LLM-prompt-boundary citation, a Tier 2/agent-context concern outside
    this package's ownership to call (CLAUDE.md's "nothing under `app/agent/` may execute"
    constraint on this task means that call site is not wired up here). `pseudonymize()` above
    must never be called with a domain, a file hash, or a JA4 fingerprint; this function must
    never be called with a tenant's own `pseudonym_salt`. Callers are responsible for passing the
    genuinely shared, cross-tenant salt.
    """
    if kind not in _INDICATOR_KINDS:
        raise ValueError(f"unknown indicator kind: {kind!r}; expected one of {_INDICATOR_KINDS}")
    digest = hmac.new(shared_salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{INDICATOR_PREFIX[kind]}_{digest[:12]}"


# Keeps PREFIX's key set honest against the PseudonymKind Literal at import time -- if one
# is ever extended without the other, every caller of this module fails immediately and
# loudly instead of a kind silently falling through to the ValueError above at runtime.
assert set(PREFIX) == set(get_args(PseudonymKind))
