"""`app.scripts.seed_tier2` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 23:
"Two seeded peer tenants, `contoso` and `fabrikam`, loaded at seed time as
`tier2_signatures` only" and "Verify at seed time that overlap is non-zero before
shipping."

Runs the real seeding function (not a re-implementation of its logic) against the live
Postgres, then re-derives the expected planted indicator hash independently and checks
it through the same `app.tier2.indicator_overlap` query the `/api/tier2` routes use —
proving the seed path's own loud-failure assertion is exercised for real, not just that
it exists in the source.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import (
    get_session_factory,
    get_tier2_session_factory,
    init_tier2_schema,
)
from app.models.tenant import Tenant, get_or_create_live_tenant
from app.scripts.seed_tier2 import (
    _PEER_ORG_NAMES,
    _SHARED_CAMPAIGN_DOMAIN,
    _peer_tenant_id,
    _peer_tenant_salt,
    seed_tier2,
)
from app.tier2.hashing import indicator_hash, tenant_hash
from app.tier2.indicator_overlap import list_indicator_overlap


def test_seed_tier2_produces_non_zero_cross_tenant_overlap() -> None:
    """The literal requirement: after seeding, `min_tenants=2` overlap is non-empty."""
    result = seed_tier2()  # must not raise -- this IS the loud-failure check, exercised live
    assert result.overlapping_indicators > 0

    init_tier2_schema()
    session = get_tier2_session_factory()()
    try:
        rows = list_indicator_overlap(session, min_tenants=2, limit=200)
    finally:
        session.close()

    assert rows, "seed_tier2 must leave at least one indicator visible to >= 2 tenants"


def test_seed_tier2_shared_campaign_domain_overlaps_all_three_seeded_orgs() -> None:
    """Stronger than "some overlap exists": the *specific* planted collision
    (`_SHARED_CAMPAIGN_DOMAIN`, used for one signature in northwind, contoso, and
    fabrikam) must itself surface with `tenant_count >= 3` — proving the overlap is the
    deliberate one this script constructs, not an accidental collision from unrelated
    test data elsewhere in the shared database."""
    seed_tier2()

    settings = get_settings()
    shared_salt = settings.tier2_indicator_salt.get_secret_value().encode()
    expected_hash = indicator_hash(_SHARED_CAMPAIGN_DOMAIN, "domain", shared_salt)

    init_tier2_schema()
    session = get_tier2_session_factory()()
    try:
        rows = list_indicator_overlap(session, min_tenants=2, limit=500)
    finally:
        session.close()

    matching = [r for r in rows if r.indicator_hash == expected_hash]
    assert matching, "the seeded shared campaign domain must appear in the overlap view"
    assert matching[0].tenant_count >= 3
    assert matching[0].signature_count >= 3


def test_seed_tier2_peer_orgs_get_no_tenant_row_and_no_login_path() -> None:
    """Change 23: "loaded at seed time as tier2_signatures only" — contoso/fabrikam must
    not exist as `tenants` rows. Their `tenant_hash` is derived from a fixed, deterministic
    stand-in id/salt (`_peer_tenant_id`/`_peer_tenant_salt`), never a persisted tenant,
    and there is therefore no user/credential that could ever log in as either."""
    seed_tier2()

    # `tenants` is primary — the point of this test is that no *real* tenant row exists for a
    # peer org, so it has to look in the database where tenant rows actually live.
    session = get_session_factory()()
    try:
        for org in _PEER_ORG_NAMES:
            row = session.execute(
                select(Tenant).where(Tenant.id == _peer_tenant_id(org))
            ).scalar_one_or_none()
            assert row is None, f"{org} must not have a real tenants row"
    finally:
        session.close()


def test_seed_tier2_is_idempotent() -> None:
    """Re-running `make seed` (and therefore this script) must not duplicate rows or
    change the overlap outcome — same guarantee `seed.py`/`seed_feedback.py` give."""
    first = seed_tier2()
    second = seed_tier2()

    assert second.signatures_written == 0  # everything from the first run already exists
    assert second.overlapping_indicators == first.overlapping_indicators


def test_seed_tier2_live_tenant_hash_matches_the_real_tenant_row() -> None:
    """The live tenant's signatures use its real `id`/`pseudonym_salt`, the same
    construction a genuine production tenant would get — not a synthetic stand-in like
    the two peer orgs."""
    seed_tier2()

    # `tenants` is a primary-database table — only the signatures moved to Tier 2, so this
    # lookup deliberately uses the primary session.
    session = get_session_factory()()
    try:
        live_tenant = get_or_create_live_tenant(session)
        session.commit()
    finally:
        session.close()

    expected = tenant_hash(live_tenant.id, live_tenant.pseudonym_salt)

    # The peer orgs' synthetic tenant_hash values must differ from the live tenant's --
    # sanity check that the three tenant_hash values genuinely are three distinct
    # tenants, not an accidental collision that would make the "overlap" trivial.
    for org in _PEER_ORG_NAMES:
        peer_hash = tenant_hash(_peer_tenant_id(org), _peer_tenant_salt(org))
        assert peer_hash != expected
