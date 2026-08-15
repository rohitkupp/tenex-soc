"""docs/04: "Each rule needs a positive and a negative fixture in tests/fixtures/rules/." — this
is the M6 acceptance test that proves it: every rule in `app/detection/rules/*.yml` fires on its
own positive fixture and stays silent on its own negative fixture, evaluated for real against the
live Postgres `events` table (docs/13 M6: "Every rule fires on its positive fixture and stays
silent on its negative").

One (tenant, analysis) pair per fixture side, so a rule's positive and negative events never share
an `analysis_id` and cannot accidentally interact (an aggregation rule's rolling window is scoped
to `analysis_id`, per `app.detection.sigma.compiler`).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import psycopg
import pytest

from app.core.config import get_settings
from app.core.db import get_engine
from app.detection.sigma import RULES_DIR, evaluate_rule, load_rule_file
from app.models.analysis import Analysis
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.rules.cases import CASES


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


@pytest.fixture
def analysis_factory(tenant_cleanup: list[uuid.UUID]) -> Callable[[str], Analysis]:
    counter = {"n": 0}

    def _make(label: str) -> Analysis:
        counter["n"] += 1
        tenant = make_tenant(name=f"Rule Fixture {label} {counter['n']}")
        tenant_cleanup.append(tenant.id)
        user = make_user(tenant_id=tenant.id, email=f"fixture{counter['n']}@example.com")
        return make_analysis(tenant_id=tenant.id, user_id=user.id, filename=f"{label}.log")

    return _make


def _load(analysis: Analysis, rows: list[SimpleEventRecord]) -> None:
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=rows)
    finally:
        conn.close()


@pytest.fixture
def all_rule_ids() -> list[str]:
    return sorted(p.stem for p in RULES_DIR.glob("*.yml"))


def test_every_rule_file_has_a_fixture_case(all_rule_ids: list[str]) -> None:
    missing = set(all_rule_ids) - set(CASES)
    assert not missing, f"rules with no fixture case in tests/fixtures/rules/cases.py: {missing}"
    extra = set(CASES) - set(all_rule_ids)
    assert not extra, f"fixture cases with no matching rule YAML: {extra}"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_positive_fixture(
    rule_id: str, analysis_factory: Callable[[str], Analysis]
) -> None:
    rule = load_rule_file(RULES_DIR / f"{rule_id}.yml")
    case = CASES[rule_id]
    analysis = analysis_factory(f"{rule_id}-positive")
    _load(analysis, case.positive)

    with get_engine().connect() as conn:
        matches = evaluate_rule(conn, rule, analysis.id, analysis.tenant_id)

    assert matches, f"{rule_id} did not fire on its positive fixture ({len(case.positive)} events)"
    for m in matches:
        assert m.evidence_event_ids, f"{rule_id} match has no evidence_event_ids: {m}"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_silent_on_negative_fixture(
    rule_id: str, analysis_factory: Callable[[str], Analysis]
) -> None:
    rule = load_rule_file(RULES_DIR / f"{rule_id}.yml")
    case = CASES[rule_id]
    analysis = analysis_factory(f"{rule_id}-negative")
    _load(analysis, case.negative)

    with get_engine().connect() as conn:
        matches = evaluate_rule(conn, rule, analysis.id, analysis.tenant_id)

    assert not matches, f"{rule_id} fired on its negative fixture: {matches}"


def test_every_rule_declares_an_attack_technique() -> None:
    for path in sorted(RULES_DIR.glob("*.yml")):
        rule = load_rule_file(path)
        assert rule.mitre_techniques, f"{rule.id}: no attack.t<technique> tag in {path}"
