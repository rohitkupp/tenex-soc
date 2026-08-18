"""Seed a realistic Tier 2 fleet so every panel on the Tier 2 page has something to show.

`seed_tier2.py` creates two peer orgs with a handful of signatures — enough to prove indicator
overlap exists at all, not enough for the charts to say anything. This builds a fleet: many
tenants, hundreds of signatures, techniques distributed unevenly, and indicators that genuinely
recur across subsets of tenants at different times.

## What each panel needs, and how this supplies it

* **Overview** — signature and tenant totals. Falls out of volume.
* **Indicator overlap** — indicators seen by >= 2 tenants. Every campaign indicator here is
  deliberately shared by a *subset* of the fleet, never all of it, so the table has a spread to
  rank rather than one flat value.
* **Overlap distribution** — buckets by tenant count. The campaigns are sized so tenants-per-
  indicator lands across the buckets instead of piling into one.
* **Technique prevalence** — per-technique tenant counts. Techniques are assigned on a long tail:
  a few appear fleet-wide, most in a handful of tenants, which is what makes the chart readable.
  Every one comes from the 13-technique proxy-observable allowlist — CLAUDE.md is explicit that
  ids outside it are a bug, and seed data is not an excuse to invent one.
* **First-seen propagation** — the same indicator observed by different tenants at different
  times. `observed_at` is staggered per tenant per campaign, so an indicator has a real
  first-seen ordering to plot rather than N identical timestamps.

## Determinism

Every id, salt and timestamp derives from a fixed seed, so re-running replaces the same rows
rather than accumulating a second fleet. That is what makes this safe to run repeatedly against
a demo environment (and what `--reset` relies on to know which rows are its own).

This writes only to the Tier 2 database. It is synthetic peer-tenant data by construction: these
orgs have no `tenants` row, no user, and no login path — exactly the property
`test_seed_tier2.py` already asserts for the two hand-written peers.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import delete

from app.core.config import get_settings
from app.core.db import get_tier2_session_factory, init_tier2_schema
from app.core.logging import configure_logging, get_logger
from app.models.tier2_signature import Tier2Signature
from app.tier2.signature_sync import CLASSIFIED_INCIDENT_TYPES
from app.tier2.embedding import canonical_text, embed_text
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.mitre_allowlist import load_allowlisted_techniques

log = get_logger(__name__)

# A namespace uuid so every generated id is reproducible and cannot collide with a real tenant's.
_NAMESPACE: Final[uuid.UUID] = uuid.UUID("6f9c1e3a-2b7d-4c58-9a10-5e8f2d4b7c31")
_SEED: Final[int] = 20260818

N_TENANTS: Final[int] = 24
SIGNATURES_PER_TENANT: Final[tuple[int, int]] = (8, 22)

# Derived from the real sync path, never hand-listed. The first version of this file spelled
# its own six labels ("c2_beacon", "credential_access", "web_shell", ...) and only one of them
# — data_exfiltration — was a label `app.tier2.signature_sync` can actually emit. The Tier 2
# overview then showed `c2_beacon` (86 signatures, seeded) and `c2_beaconing` (1, real) as two
# separate incident types for the same thing, and four more rows that no real triage could ever
# add to. Reading the vocabulary off `signature_sync.CLASSIFIED_INCIDENT_TYPES` means a seeded fleet and a live
# run are describing the same taxonomy by construction, and adding a technique mapping there
# cannot silently desynchronize this file.
_INCIDENT_TYPES: Final[tuple[str, ...]] = tuple(sorted(CLASSIFIED_INCIDENT_TYPES))
_SOURCE_TYPES: Final[tuple[str, ...]] = ("zscaler",)


@dataclass(frozen=True, slots=True)
class _Campaign:
    """One indicator shared by a subset of the fleet — the unit that makes overlap meaningful.

    `spread` is how many tenants see it. Sized across the range so the distribution chart gets
    buckets rather than a single spike, and so the overlap table has something to rank.
    """

    domain: str
    technique: str
    spread: int
    first_day: int  # days ago the earliest tenant saw it — first-seen propagation needs an origin


def _campaigns(techniques: list[str], rng: random.Random) -> list[_Campaign]:
    """Wide, medium and narrow campaigns. A fleet where every indicator is seen by everyone has
    no signal in it; neither does one where nothing is shared."""
    plan: list[tuple[str, int, int]] = [
        ("cdn-metrics-sync.link", 19, 88),
        ("update-delivery-node.cc", 15, 76),
        ("telemetry-egress.workers.dev", 12, 64),
        ("api-gateway-mirror.top", 9, 55),
        ("secure-doc-portal.click", 7, 47),
        ("vault-auth-refresh.live", 6, 39),
        ("mail-relay-outbound.icu", 5, 31),
        ("pkg-registry-proxy.xyz", 4, 25),
        ("status-heartbeat.monster", 3, 18),
        ("backup-sync-agent.quest", 3, 14),
        ("crash-report-intake.sbs", 2, 9),
        ("license-check-daemon.cfd", 2, 5),
    ]
    return [
        _Campaign(domain=d, technique=rng.choice(techniques), spread=s, first_day=f)
        for d, s, f in plan
    ]


def _org_names(n: int) -> list[str]:
    stems = (
        "northwind",
        "contoso",
        "fabrikam",
        "adventure",
        "wingtip",
        "litware",
        "proseware",
        "tailspin",
        "woodgrove",
        "lucerne",
        "alpine",
        "coho",
        "fourthcoffee",
        "graphicdesign",
        "humongous",
        "trey",
        "blueyonder",
        "consolidated",
        "margies",
        "relecloud",
        "vanarsdel",
        "wideworld",
        "worldwide",
        "southridge",
    )
    return [
        f"{stems[i % len(stems)]}-{i // len(stems)}" if i >= len(stems) else stems[i]
        for i in range(n)
    ]


def _tenant_id(org: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, f"tenant:{org}")


def _tenant_salt(org: str) -> bytes:
    return hashlib.sha256(f"salt:{org}".encode()).digest()


def _signature_id(org: str, slot: int) -> uuid.UUID:
    """Deterministic, so a re-run overwrites its own rows instead of doubling the fleet."""
    return uuid.uuid5(_NAMESPACE, f"sig:{org}:{slot}")


def seed_tier2_fleet(*, reset: bool = True) -> dict[str, int]:
    settings = get_settings()
    shared_salt = settings.tier2_indicator_salt.get_secret_value().encode()
    techniques = sorted(load_allowlisted_techniques())
    # Seeded `random`, deliberately: this is demo fixture data, not a security
    # primitive, and reproducibility across runs is the whole point of the seed.
    rng = random.Random(_SEED)  # noqa: S311

    orgs = _org_names(N_TENANTS)
    campaigns = _campaigns(techniques, rng)
    now = datetime.now(UTC)

    # Which tenants see which campaign. Taken from the front of a shuffled fleet so the same
    # tenants recur across campaigns — real overlap has structure, and a fresh random subset per
    # campaign would produce a flat, structureless graph.
    ordered = list(orgs)
    rng.shuffle(ordered)
    campaign_members = {c.domain: ordered[: c.spread] for c in campaigns}

    init_tier2_schema()
    session = get_tier2_session_factory()()
    n_written = 0
    try:
        if reset:
            ids = [
                _signature_id(o, s)
                for o in orgs
                for s in range(SIGNATURES_PER_TENANT[1] + len(campaigns))
            ]
            session.execute(delete(Tier2Signature).where(Tier2Signature.id.in_(ids)))

        for org in orgs:
            org_id, org_salt = _tenant_id(org), _tenant_salt(org)
            org_hash = tenant_hash(org_id, org_salt)
            slot = 0

            # Campaign signatures — the shared indicators every overlap-based panel reads.
            for campaign in campaigns:
                if org not in campaign_members[campaign.domain]:
                    continue
                # Each tenant sees the campaign a little later than the last: that lag *is* the
                # first-seen propagation the chart plots.
                position = campaign_members[campaign.domain].index(org)
                observed = (
                    now
                    - timedelta(days=campaign.first_day)
                    + timedelta(hours=position * rng.uniform(5, 30))
                )
                session.merge(
                    Tier2Signature(
                        id=_signature_id(org, slot),
                        tenant_hash=org_hash,
                        incident_type=rng.choice(_INCIDENT_TYPES),
                        mitre_techniques=[campaign.technique],
                        source_types=list(_SOURCE_TYPES),
                        confidence=round(rng.uniform(0.62, 0.99), 3),
                        # Independent of `confidence` on purpose. The two measure different
                        # things (traffic anomaly vs. evidentiary support for the conclusion),
                        # and seeding them correlated would manufacture a relationship the Tier 2
                        # charts would then appear to discover. Drawn a little lower and wider
                        # than the campaign confidence because real rubric scores cluster below
                        # the detector scores that surfaced them.
                        evidence_confidence=round(rng.uniform(0.45, 0.92), 3),
                        indicator_hashes=[indicator_hash(campaign.domain, "domain", shared_salt)],
                        observed_at=observed,
                        embedding=embed_text(
                            canonical_text(
                                technique_ids=[campaign.technique],
                                detector_keys=["signal.beaconing"],
                                entity_types=["domain"],
                                enrichment_tags=[],
                            )
                        ),
                    )
                )
                slot += 1
                n_written += 1

            # Tenant-local noise: indicators nobody else sees. Without these every indicator in
            # the store would be shared, and "overlapping" would stop meaning anything.
            for _ in range(rng.randint(*SIGNATURES_PER_TENANT)):
                technique = rng.choice(techniques)
                local_domain = f"{org}-{rng.randrange(10_000):04d}.internal.example"
                session.merge(
                    Tier2Signature(
                        id=_signature_id(org, slot),
                        tenant_hash=org_hash,
                        incident_type=rng.choice(_INCIDENT_TYPES),
                        mitre_techniques=[technique],
                        source_types=list(_SOURCE_TYPES),
                        confidence=round(rng.uniform(0.35, 0.95), 3),
                        evidence_confidence=round(rng.uniform(0.40, 0.90), 3),
                        indicator_hashes=[indicator_hash(local_domain, "domain", shared_salt)],
                        observed_at=now - timedelta(days=rng.uniform(0.5, 85)),
                        embedding=embed_text(
                            canonical_text(
                                technique_ids=[technique],
                                detector_keys=["ml.eif"],
                                entity_types=["domain"],
                                enrichment_tags=[],
                            )
                        ),
                    )
                )
                slot += 1
                n_written += 1

        session.commit()
    finally:
        session.close()

    result = {
        "tenants": len(orgs),
        "signatures": n_written,
        "campaigns": len(campaigns),
    }
    log.info("seed_tier2_fleet.done", **result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="do not delete this seeder's previous rows first",
    )
    args = parser.parse_args()
    configure_logging()
    result = seed_tier2_fleet(reset=not args.keep_existing)
    log.info(
        "seed_tier2_fleet.summary",
        summary=f"seeded {result['signatures']} signatures across {result['tenants']} tenants "
        f"({result['campaigns']} shared campaigns)",
    )


if __name__ == "__main__":
    main()
