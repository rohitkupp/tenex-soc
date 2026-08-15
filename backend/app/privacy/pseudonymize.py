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
_INDICATOR_KINDS = ("domain", "ip")
INDICATOR_PREFIX: Final[dict[str, str]] = {"domain": "d", "ip": "ip"}


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


def indicator_hash(value: str, kind: Literal["domain", "ip"], shared_salt: bytes) -> str:
    """docs/06's Tier 2 exception, quoted here in full because it is easy to misread as
    "reuse pseudonymize() with a different salt" -- it is not:

        "indicator hashes (domains, dst IPs) use a *shared* salt across tenants so
        cross-tenant overlap is detectable. That is a deliberate privacy/utility
        tradeoff[.]"

    This is the *only* place a domain is ever hashed anywhere in this package -- and only
    for constructing `tier2_signatures.indicator_hashes` (docs/02), a Tier 2/M14 concern
    outside this package's ownership to write. `pseudonymize()` above must never be called
    with a domain; this function must never be called with a tenant's own `pseudonym_salt`.
    Callers are responsible for passing the genuinely shared, cross-tenant salt.
    """
    if kind not in _INDICATOR_KINDS:
        raise ValueError(f"unknown indicator kind: {kind!r}; expected one of {_INDICATOR_KINDS}")
    digest = hmac.new(shared_salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{INDICATOR_PREFIX[kind]}_{digest[:12]}"


# Keeps PREFIX's key set honest against the PseudonymKind Literal at import time -- if one
# is ever extended without the other, every caller of this module fails immediately and
# loudly instead of a kind silently falling through to the ValueError above at runtime.
assert set(PREFIX) == set(get_args(PseudonymKind))
