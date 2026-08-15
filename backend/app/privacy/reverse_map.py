"""Tenant-scoped pseudonym reverse map (docs/06-PRIVACY-SECURITY.md "Pseudonymization").

    "The reverse map lives in a tenant-scoped table and is only used to render values in
    the UI for that tenant's own users. It never enters a prompt, a Tier 2 record, or a log
    line."

docs/01-ARCHITECTURE.md names the durable version of this `pseudonym_map`, written as the
anonymize stage's postcondition; owning that table is `app/models`/`app/pipeline` territory
(a concurrent agent's, per the M5 task seam), not this package's. What lives here is the
storage-agnostic *contract*: an in-memory, tenant-partitioned pseudonym -> original-value
store with the exact shape a durable-storage-backed version needs to replicate --
`ReverseMapEntry` is the row shape to persist, and `record`/`record_many`/`resolve` are the
three operations a real table-backed implementation needs to support. Safe to use standalone
(a single worker process, or tests) as-is.

Two guarantees enforced structurally here, not just documented:

  1. Every read and write is keyed by `tenant_id` first -- there is no method that returns
     or iterates every tenant's data at once, so a caller cannot leak across the boundary by
     forgetting a filter (docs/06's own complaint about *why* tenant scoping needs
     structural enforcement elsewhere in this codebase applies equally here).
  2. Nothing in this class ever logs, prints, or otherwise surfaces a value it holds.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from threading import Lock
from typing import Generic, TypeVar

TenantId = TypeVar("TenantId", bound=Hashable)


@dataclass(frozen=True, slots=True)
class ReverseMapEntry(Generic[TenantId]):
    """One row of the reverse map -- what the anonymizer worker should persist per
    pseudonymized value. `kind` is one of `pseudonymize.PseudonymKind`'s values."""

    tenant_id: TenantId
    kind: str
    pseudonym: str
    original_value: str


class PseudonymReverseMap(Generic[TenantId]):
    """In-memory reference implementation. Thread-safe for concurrent writers in the same
    process; not durable across process restarts -- see module docstring."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._by_tenant: dict[TenantId, dict[str, str]] = {}

    def record(self, entry: ReverseMapEntry[TenantId]) -> None:
        """Idempotent for a repeated `(tenant_id, pseudonym)` pair mapping to the *same*
        value (recording an event's principal pseudonym twice, once per event it appears
        in, is the expected common case). A repeat with a *different* value raises instead
        of silently overwriting -- since the HMAC is deterministic, that can only happen
        from a salt rotation or a genuine hash collision, either of which is a bug worth
        surfacing immediately rather than quietly corrupting the map."""
        with self._lock:
            bucket = self._by_tenant.setdefault(entry.tenant_id, {})
            existing = bucket.get(entry.pseudonym)
            if existing is not None and existing != entry.original_value:
                raise ValueError(
                    f"reverse map collision for tenant {entry.tenant_id!r}: pseudonym "
                    f"{entry.pseudonym!r} already maps to a different value"
                )
            bucket[entry.pseudonym] = entry.original_value

    def record_many(self, entries: Iterable[ReverseMapEntry[TenantId]]) -> None:
        for entry in entries:
            self.record(entry)

    def resolve(self, tenant_id: TenantId, pseudonym: str) -> str | None:
        """The only sanctioned way to go from a pseudonym back to a real value, for
        rendering in that tenant's own UI (docs/06). Callers outside `app/privacy` are
        responsible for verifying the *requesting* user actually belongs to `tenant_id`
        before calling this -- this class only guarantees the lookup itself cannot cross a
        tenant boundary, not that the caller is authorized to make the request at all."""
        with self._lock:
            return self._by_tenant.get(tenant_id, {}).get(pseudonym)

    def __len__(self) -> int:
        with self._lock:
            return sum(len(bucket) for bucket in self._by_tenant.values())
