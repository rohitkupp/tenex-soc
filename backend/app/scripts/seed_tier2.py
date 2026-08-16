"""`make seed` → `python -m app.scripts.seed_tier2` (after `seed.py`). docs/v2_migration/
MIGRATION-01-evidence-first.md, change 23 ("Shared workspace, single live tenant"):

    Two seeded peer tenants, `contoso` and `fabrikam`, loaded at seed time as
    `tier2_signatures` only — they exist for cross-tenant analytics, not as login
    targets.

Neither `contoso` nor `fabrikam` gets a `tenants` row, a `User`, or any other
tenant-scoped data — only `tier2_signatures` rows, which is exactly what
`app.models.tier2_signature.Tier2Signature` is built for: it carries `tenant_hash`
(an HMAC, docs/02), never `tenant_id`, so there is nothing that requires a real
tenant to exist. Their `tenant_hash` values are computed from a fixed, deterministic
`(tenant_id, salt)` pair per org (`_peer_tenant_id`/`_peer_tenant_salt` below) instead
of a live `tenants` row's own id/`pseudonym_salt` — same HMAC construction
(`app.tier2.hashing.tenant_hash`) a real tenant would get, just with synthetic inputs.

The live tenant (`northwind`, `app.models.tenant.get_or_create_live_tenant`) gets
signatures the same way, using its real `id`/`pseudonym_salt`.

## Why overlap is asserted, not just intended

CLAUDE.md's brief for this migration is explicit: "a Tier 2 page that renders empty is
the failure mode here." `_SHARED_CAMPAIGN_DOMAIN` below is deliberately used for one
signature in every org, so the same `indicator_hash` appears under all three
`tenant_hash` values *by construction*, not by chance — mirroring the "shared
campaign-domain pool" `docs/v2_migration/generate_corpus.py`'s `SHARED_CAMPAIGN_DOMAINS`
describes for the full synthetic corpus (change 13, out of scope here; this script does
not import that file — it is documentation/reference material for the eventual full
corpus, not a runtime dependency of the application).

`seed_tier2()` then queries `app.tier2.indicator_overlap.list_indicator_overlap` itself
before returning and **raises** if it finds nothing — a real assertion in the seed path,
not a comment, so a change that breaks the hashing or the overlap view fails `make seed`
loudly instead of shipping a Tier 2 page that silently renders empty.

## Idempotency

Every row this script writes has a fixed, deterministic `id` (`uuid.uuid5`, keyed off a
stable string) so re-running `make seed` finds the same rows already present and skips
them, the same "safe to re-run" guarantee `seed.py`/`seed_feedback.py` give (docs/13
M13's "idempotent" bar).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.models.tenant import LIVE_TENANT_NAME, get_or_create_live_tenant
from app.models.tier2_signature import Tier2Signature
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.indicator_overlap import list_indicator_overlap

log = get_logger(__name__)

# Fixed namespace for the deterministic (tenant_id, salt, signature_id) triples this
# script derives for the two peer orgs -- see module docstring, "Idempotency".
_SEED_NAMESPACE = uuid.UUID("2f6e9d3a-8b41-4b8e-9c2d-6a7f0e5d3c11")

_PEER_ORG_NAMES: tuple[str, ...] = ("contoso", "fabrikam")

# Used for one signature in every org (live tenant included) -- guarantees a genuine,
# non-probabilistic 3-way cross-tenant overlap. Thematically a DGA-shaped C2 domain, to
# match the T1071.001 technique attached to the signature that carries it.
_SHARED_CAMPAIGN_DOMAIN = "kx7mrzq4ap.xyz"

# One org-unique domain per org -- never shared, so the overlap listing also has a
# realistic majority of non-overlapping indicators, not only the one planted collision.
_ORG_UNIQUE_DOMAIN: dict[str, str] = {
    LIVE_TENANT_NAME: "nw-partner-portal19.com",
    "contoso": "cto-fileshare33.com",
    "fabrikam": "fab-vendor-upload07.com",
}


def _peer_tenant_id(org: str) -> uuid.UUID:
    """Deterministic stand-in for a `tenants.id` this org will never actually have."""
    return uuid.uuid5(_SEED_NAMESPACE, f"tier2-peer-tenant:{org}")


def _peer_tenant_salt(org: str) -> bytes:
    """Deterministic stand-in for a `tenants.pseudonym_salt` this org will never
    actually have."""
    return hashlib.sha256(f"tier2-peer-salt:{org}".encode()).digest()


def _signature_id(org: str, slot: str) -> uuid.UUID:
    return uuid.uuid5(_SEED_NAMESPACE, f"tier2-seed-signature:{org}:{slot}")


@dataclass(frozen=True, slots=True)
class _SignatureSpec:
    slot: str
    domain: str
    technique: str
    incident_type: str
    confidence: float
    age_days: int


def _specs_for(org: str) -> tuple[_SignatureSpec, ...]:
    return (
        # The planted cross-tenant collision -- same domain, every org.
        _SignatureSpec(
            slot="campaign",
            domain=_SHARED_CAMPAIGN_DOMAIN,
            technique="T1071.001",
            incident_type="c2_beaconing",
            confidence=0.83,
            age_days=6,
        ),
        # A realistic, non-overlapping signature so the overlap listing isn't the only
        # row in the table.
        _SignatureSpec(
            slot="unique",
            domain=_ORG_UNIQUE_DOMAIN[org],
            technique="T1567.002",
            incident_type="data_exfiltration",
            confidence=0.68,
            age_days=2,
        ),
    )


@dataclass(frozen=True, slots=True)
class SeedTier2Result:
    signatures_written: int
    overlapping_indicators: int


def seed_tier2() -> SeedTier2Result:
    session = get_session_factory()()
    try:
        live_tenant = get_or_create_live_tenant(session)
        session.commit()

        settings = get_settings()
        shared_salt = settings.tier2_indicator_salt.get_secret_value().encode()

        orgs: tuple[tuple[str, uuid.UUID, bytes], ...] = (
            (LIVE_TENANT_NAME, live_tenant.id, live_tenant.pseudonym_salt),
            *((org, _peer_tenant_id(org), _peer_tenant_salt(org)) for org in _PEER_ORG_NAMES),
        )

        written = 0
        now = datetime.now(UTC)
        for org, org_tenant_id, org_salt in orgs:
            org_tenant_hash = tenant_hash(org_tenant_id, org_salt)
            for spec in _specs_for(org):
                sig_id = _signature_id(org, spec.slot)
                if session.get(Tier2Signature, sig_id) is not None:
                    continue  # already seeded by a previous `make seed` run
                session.add(
                    Tier2Signature(
                        id=sig_id,
                        tenant_hash=org_tenant_hash,
                        incident_type=spec.incident_type,
                        mitre_techniques=[spec.technique],
                        source_types=["zscaler"],
                        confidence=spec.confidence,
                        indicator_hashes=[indicator_hash(spec.domain, "domain", shared_salt)],
                        observed_at=now - timedelta(days=spec.age_days),
                    )
                )
                written += 1
        session.commit()

        # The real assertion, not a comment: a Tier 2 page that renders empty is the
        # failure mode change 23 calls out explicitly. Fail `make seed` loudly if the
        # planted collision above didn't actually produce overlap.
        overlap = list_indicator_overlap(session, min_tenants=2, limit=10)
        if not overlap:
            raise RuntimeError(
                "seed_tier2: cross-tenant indicator overlap is zero after seeding "
                f"{LIVE_TENANT_NAME!r} / {', '.join(_PEER_ORG_NAMES)!r} — Tier 2 would "
                "render empty. This is a hard failure, not a warning."
            )

        log.info(
            "seed_tier2.overlap_verified",
            signatures_written=written,
            overlapping_indicators=len(overlap),
            top_tenant_count=overlap[0].tenant_count,
        )
        return SeedTier2Result(signatures_written=written, overlapping_indicators=len(overlap))
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def main() -> None:
    configure_logging()
    seed_tier2()


if __name__ == "__main__":
    main()
