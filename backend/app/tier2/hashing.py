"""The two HMAC constructions `app.tier2.signature_sync` needs, both deliberately *not*
reusing `app.privacy.pseudonymize.pseudonymize` (that function's `PseudonymKind` is closed
over the six kinds docs/06 lists for per-event pseudonymization -- users, IPs, hostnames,
sessions, devices, and it deliberately has no seventh "tenant" kind, because a tenant
identity is a different thing than an event-scoped principal and does not belong in that
module's reversible-namespace bookkeeping).

See `app.tier2.__init__`'s module docstring for the salt tradeoff these two functions are
built to opposite sides of:

* `tenant_hash` -- **per-tenant** salt, like every other principal-shaped value.
* `indicator_hash` -- imported, unmodified, from `app.privacy.pseudonymize`, which already
  implements the **shared**-salt exception docs/06 specifies for domains/dst IPs. Re-
  exported here so every Tier 2 call site imports hashing primitives from one place.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from typing import Final

# Re-exported, not reimplemented -- app.privacy.pseudonymize.indicator_hash *is* the
# shared-salt Tier 2 exception docs/06 specifies; duplicating its HMAC construction here
# would risk the two silently diverging.
from app.privacy.pseudonymize import indicator_hash as indicator_hash

_TENANT_HASH_PREFIX: Final[str] = "th"


def tenant_hash(tenant_id: uuid.UUID, tenant_salt: bytes) -> str:
    """A stable, per-tenant, non-reversible grouping key for `tier2_signatures.tenant_hash`
    (docs/02: "HMAC, not tenant_id"). Uses `tenant_salt` -- each tenant's own
    `tenants.pseudonym_salt`, the same column every other pseudonym in that tenant's data
    is HMAC'd with -- **not** `settings.tier2_indicator_salt`. Deterministic per
    `(tenant_id, tenant_salt)`, so every signature emitted for the same tenant carries the
    same `tenant_hash`, which is what lets `COUNT(DISTINCT tenant_hash)` mean "N distinct
    tenants" in `app.tier2.indicator_overlap`. Two different tenants get two different
    hashes with overwhelming probability (different salts, SHA-256) without either tenant
    -- or anyone holding only the hash -- being able to recover the other's `tenant_id`.
    """
    digest = hmac.new(tenant_salt, f"tenant:{tenant_id}".encode(), hashlib.sha256).hexdigest()
    return f"{_TENANT_HASH_PREFIX}_{digest[:16]}"


__all__ = ["indicator_hash", "tenant_hash"]
