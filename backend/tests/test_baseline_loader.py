"""`app.baseline.loader` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1.

Fixtures under `tests/fixtures/baseline/` are a small, hand-built stand-in for
`datagen.labeled_corpus.build_baseline`'s real output, shaped identically (same three files,
same key names) but sized for a fast, precise unit test rather than the real 250-user / 6-month
scale. `bjohann@northwind.example` and `kgaither@northwind.example` (Finance) and
`rpanter@northwind.example` (Engineering) are real users of the deterministic seeded org
`app.baseline.org_directory` reconstructs — picked by inspecting
`datagen.labeled_corpus.build_split_org(DEFAULT_SPLITS[0])` directly, not invented, so the
department rollup below exercises the same `department_for_user` lookup production code path
uses.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.baseline.loader import load_baseline
from app.core.db import get_session_factory
from app.models.base import MissingTenantScopeError, tenant_scope
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile
from app.models.baseline_window import BaselineWindow
from tests.conftest import make_tenant

FIXTURES = Path(__file__).parent / "fixtures" / "baseline"


@pytest.fixture
def db() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def tenant_id(db: Session) -> Iterator[uuid.UUID]:
    tenant = make_tenant(name="Baseline Loader Test Tenant")
    yield tenant.id
    # Direct DELETE, not the ORM (these tables have no FK back to `tenants`, so
    # tests/conftest.py's tenant_cleanup wouldn't sweep them anyway) -- cheap and total.
    with tenant_scope(db, tenant.id):
        db.execute(BaselineWindow.__table__.delete().where(BaselineWindow.tenant_id == tenant.id))
        db.execute(BaselineProfile.__table__.delete().where(BaselineProfile.tenant_id == tenant.id))
        db.execute(BaselineContact.__table__.delete().where(BaselineContact.tenant_id == tenant.id))
    db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant.id})
    db.commit()


def test_load_baseline_missing_dir_raises_file_not_found(db: Session, tenant_id: uuid.UUID) -> None:
    with pytest.raises(FileNotFoundError):
        load_baseline(db, tenant_id, Path("/nonexistent/does/not/exist"))


def test_load_baseline_loads_windows_profiles_and_rolled_up_contacts(
    db: Session, tenant_id: uuid.UUID
) -> None:
    summary = load_baseline(db, tenant_id, FIXTURES)
    db.commit()

    assert summary.windows_loaded == 6
    assert summary.profiles_loaded == 2
    assert summary.contacts_user_loaded == 5
    assert summary.users_without_department == 0

    with tenant_scope(db, tenant_id):
        windows = (
            db.execute(select(BaselineWindow).where(BaselineWindow.tenant_id == tenant_id))
            .scalars()
            .all()
        )
    assert len(windows) == 6
    assert {w.entity_value for w in windows} == {
        "bjohann@northwind.example",
        "rpanter@northwind.example",
    }

    assert summary.window_period_start is not None
    assert summary.window_period_start.isoformat().startswith("2025-09-01")
    assert summary.window_period_end is not None
    assert summary.window_period_end.isoformat().startswith("2026-02-25")


def test_department_and_org_rollups_sum_correctly_from_user_scope_contacts(
    db: Session, tenant_id: uuid.UUID
) -> None:
    """Fixture: bjohann (Finance) 120 + kgaither (Finance) 30 + rpanter (Engineering) 500 on
    github.com; bjohann (Finance) 40 + rpanter (Engineering) 10 on salesforce.com. Department
    totals must sum only same-department users; org totals must sum every user regardless of
    department -- the two are deliberately made to disagree (Finance's salesforce.com total,
    40, is not the org total, 50) so a rollup bug that conflates the two scopes fails loudly.
    """
    load_baseline(db, tenant_id, FIXTURES)
    db.commit()

    with tenant_scope(db, tenant_id):
        rows = (
            db.execute(select(BaselineContact).where(BaselineContact.tenant_id == tenant_id))
            .scalars()
            .all()
        )
    by_key = {(r.scope, r.scope_value, r.domain): r.contact_count for r in rows}

    assert by_key[("user", "bjohann@northwind.example", "github.com")] == 120
    assert by_key[("user", "kgaither@northwind.example", "github.com")] == 30
    assert by_key[("user", "rpanter@northwind.example", "github.com")] == 500

    assert by_key[("department", "Finance", "github.com")] == 150  # 120 + 30
    assert by_key[("department", "Engineering", "github.com")] == 500
    assert by_key[("department", "Finance", "salesforce.com")] == 40
    assert by_key[("department", "Engineering", "salesforce.com")] == 10

    assert by_key[("org", "org", "github.com")] == 650  # 120 + 30 + 500
    assert by_key[("org", "org", "salesforce.com")] == 50  # 40 + 10, not Finance's 40

    # Exactly 5 user + 4 department + 2 org rows -- no extras, no drops.
    assert len(rows) == 11


def test_load_baseline_is_idempotent(db: Session, tenant_id: uuid.UUID) -> None:
    first = load_baseline(db, tenant_id, FIXTURES)
    db.commit()
    second = load_baseline(db, tenant_id, FIXTURES)
    db.commit()

    assert first == second

    with tenant_scope(db, tenant_id):
        n_windows = len(
            db.execute(select(BaselineWindow).where(BaselineWindow.tenant_id == tenant_id)).all()
        )
        n_profiles = len(
            db.execute(select(BaselineProfile).where(BaselineProfile.tenant_id == tenant_id)).all()
        )
        n_contacts = len(
            db.execute(select(BaselineContact).where(BaselineContact.tenant_id == tenant_id)).all()
        )

    assert n_windows == 6
    assert n_profiles == 2
    assert n_contacts == 11


def test_tenant_scoping_holds_on_all_three_baseline_tables(
    db: Session, tenant_id: uuid.UUID
) -> None:
    other = make_tenant(name="Baseline Loader Test Tenant (other)")
    try:
        load_baseline(db, tenant_id, FIXTURES)
        db.commit()

        # A bare, unscoped session must refuse to read any of the three tables outright --
        # not return zero rows, refuse.
        bare_session = get_session_factory()()
        try:
            with pytest.raises(MissingTenantScopeError):
                bare_session.execute(select(BaselineWindow)).all()
            with pytest.raises(MissingTenantScopeError):
                bare_session.execute(select(BaselineProfile)).all()
            with pytest.raises(MissingTenantScopeError):
                bare_session.execute(select(BaselineContact)).all()
        finally:
            bare_session.close()

        # A session scoped to the *other* tenant sees none of this tenant's rows.
        with tenant_scope(db, other.id):
            assert db.execute(select(BaselineWindow)).first() is None
            assert db.execute(select(BaselineProfile)).first() is None
            assert db.execute(select(BaselineContact)).first() is None

        # Scoped back to the real tenant, the rows are there.
        with tenant_scope(db, tenant_id):
            assert db.execute(select(BaselineWindow)).first() is not None
    finally:
        db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": other.id})
        db.commit()
