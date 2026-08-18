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
from app.tier2.embedding import canonical_text, embed_text
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.mitre_allowlist import load_allowlisted_techniques

log = get_logger(__name__)

# A namespace uuid so every generated id is reproducible and cannot collide with a real tenant's.
_NAMESPACE: Final[uuid.UUID] = uuid.UUID("6f9c1e3a-2b7d-4c58-9a10-5e8f2d4b7c31")
_SEED: Final[int] = 20260818

N_TENANTS: Final[int] = 24
SIGNATURES_PER_TENANT: Final[tuple[int, int]] = (8, 22)

_INCIDENT_TYPES: Final[tuple[str, ...]] = (
    "c2_beacon",
    "data_exfiltration",
    "credential_access",
    "web_shell",
    "suspicious_activity",
    "ingress_tool_transfer",
)
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
    reliability = seed_detector_reliability()
    result["reliability_tenants"] = reliability["tenants"]
    result["feedback_rows"] = reliability["feedback_rows"]
    log.info(
        "seed_tier2_fleet.summary",
        summary=f"seeded {result['signatures']} signatures across {result['tenants']} tenants "
        f"({result['campaigns']} shared campaigns)",
    )


# =================================================================================================
# Detector reliability — the one Tier 2 panel that does NOT read the Tier 2 database.
#
# `app.tier2.detector_reliability` aggregates `analyst_feedback` joined through
# `triage_verdicts -> incidents -> signals`, all of which live in the primary database, because
# the question it answers is "when an analyst disagreed with the agent, which detector had fired?"
# — and that is tenant-scoped evidence, not cross-tenant intelligence. So the fleet above cannot
# fill it: this needs real analysis chains.
#
# These are synthetic tenants with a login path that cannot be used: the password hash is a fixed
# non-verifying placeholder and no verification row exists, so the accounts are unusable by
# construction rather than by convention.
# =================================================================================================

_RELIABILITY_TENANTS: Final[int] = 6
_INCIDENTS_PER_TENANT: Final[int] = 7

# Per-detector confirm rate. Deliberately spread: a chart where every detector is equally reliable
# tells an analyst nothing, and the whole point of this panel is to rank them.
_DETECTOR_PRECISION: Final[dict[tuple[str, str], float]] = {
    ("signal.beaconing", "signal"): 0.86,
    ("signal.dga", "signal"): 0.78,
    ("sigma.large_post_to_new_domain", "rule"): 0.71,
    ("ml.eif", "ml"): 0.54,
    ("ml.kth_nn", "ml"): 0.41,
    ("signal.rarity", "signal"): 0.33,
    ("ml.peer_group", "ml"): 0.22,
    ("signal.burst", "signal"): 0.18,
}


def seed_detector_reliability() -> dict[str, int]:
    """Build tenant -> upload -> analysis -> signals -> incident -> verdict -> feedback chains."""
    from app.core.db import get_session_factory
    from app.models.analysis import Analysis
    from app.models.analyst_feedback import AnalystFeedback
    from app.models.base import tenant_scope
    from app.models.incident import Incident
    from app.models.signal import Signal
    from app.models.tenant import Tenant
    from app.models.triage_verdict import TriageVerdict
    from app.models.upload import Upload
    from app.models.user import User

    rng = random.Random(_SEED + 1)  # noqa: S311 - demo fixture data, see seed_tier2_fleet
    now = datetime.now(UTC)
    detectors = list(_DETECTOR_PRECISION)
    n_feedback = 0

    session = get_session_factory()()
    try:
        for t in range(_RELIABILITY_TENANTS):
            org = f"peerorg-{t:02d}"
            tenant_id = uuid.uuid5(_NAMESPACE, f"reliability-tenant:{org}")

            if session.get(Tenant, tenant_id) is not None:
                continue  # already seeded — idempotent, same contract as the fleet above

            with tenant_scope(session, tenant_id):
                session.add(Tenant(id=tenant_id, name=org, pseudonym_salt=_tenant_salt(org)))
                user = User(
                    id=uuid.uuid5(_NAMESPACE, f"reliability-user:{org}"),
                    email=f"analyst@{org}.example",
                    # Not a usable credential: a fixed placeholder that no password can hash to,
                    # so these tenants cannot be logged into even though the row exists.
                    password_hash="!seeded-peer-tenant-no-login",  # noqa: S106
                    tenant_id=tenant_id,
                )
                session.add(user)
                session.flush()

                upload = Upload(
                    id=uuid.uuid5(_NAMESPACE, f"reliability-upload:{org}"),
                    user_id=user.id,
                    tenant_id=tenant_id,
                    filename=f"{org}-proxy.log",
                    size_bytes=1_048_576,
                    sha256="0" * 64,
                    storage_ref=f"{tenant_id}/seeded",
                )
                session.add(upload)
                session.flush()

                analysis = Analysis(
                    id=uuid.uuid5(_NAMESPACE, f"reliability-analysis:{org}"),
                    upload_id=upload.id,
                    tenant_id=tenant_id,
                    status="complete",
                    stage="tier2",
                    progress=1.0,
                    started_at=now - timedelta(days=rng.uniform(2, 60)),
                    finished_at=now - timedelta(days=rng.uniform(0.1, 1.9)),
                )
                session.add(analysis)
                session.flush()

                for i in range(_INCIDENTS_PER_TENANT):
                    detector_key, detector_layer = rng.choice(detectors)
                    precision = _DETECTOR_PRECISION[(detector_key, detector_layer)]

                    signal = Signal(
                        analysis_id=analysis.id,
                        tenant_id=tenant_id,
                        detector_key=detector_key,
                        detector_layer=detector_layer,
                        raw_score=round(rng.uniform(0.3, 0.99), 3),
                        confidence=round(rng.uniform(0.3, 0.99), 3),
                        entity_type="domain",
                        entity_value=f"{org}-{i}.example",
                        evidence_event_ids=[],
                        explanation={},
                    )
                    session.add(signal)
                    session.flush()

                    incident = Incident(
                        analysis_id=analysis.id,
                        tenant_id=tenant_id,
                        title=f"{detector_key} on {org}-{i}.example",
                        severity=rng.choice(("low", "medium", "high", "critical")),
                        fused_score=round(rng.uniform(0.2, 0.99), 3),
                        anomaly_confidence=round(rng.uniform(20, 99), 1),
                        entity_ids=[],
                        signal_ids=[signal.id],
                    )
                    session.add(incident)
                    session.flush()

                    # The agent's own call. Whether the analyst agreed is what the panel measures,
                    # so the disposition here is the *starting* point, not the answer.
                    verdict = TriageVerdict(
                        incident_id=incident.id,
                        disposition="true_positive",
                        threat_confidence="moderate",
                        threat_confidence_reason="seeded",
                        mitre_techniques=[],
                        summary=f"Seeded verdict for {detector_key}.",
                        narrative=[],
                        recommended_actions=[],
                        tool_trace=[],
                        citation_valid=True,
                        model="seeded",
                    )
                    session.add(verdict)
                    session.flush()

                    # `corrected_disposition` is what the reliability query actually reads
                    # (COALESCE over the verdict's own), so a disagreement has to carry one.
                    confirmed = rng.random() < precision
                    session.add(
                        AnalystFeedback(
                            verdict_id=verdict.id,
                            user_id=user.id,
                            agrees=confirmed,
                            corrected_disposition=None if confirmed else "benign",
                            dismissal_reason=None if confirmed else "known_good",
                            mark_benign_baseline=False,
                            note=None,
                        )
                    )
                    n_feedback += 1

        session.commit()
    finally:
        session.close()

    result = {"tenants": _RELIABILITY_TENANTS, "feedback_rows": n_feedback}
    log.info("seed_detector_reliability.done", **result)
    return result


if __name__ == "__main__":
    main()
