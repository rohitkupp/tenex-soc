"""docs/08 "Suppression rule generation": an accepted suppression under
`app/detection/rules/suppressions/` subtracts matches from the detection rules it names in
`applies_to`, without touching the detection rule's own YAML or any Python.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest

from app.core.config import get_settings
from app.core.db import get_engine
from app.detection.sigma import (
    RULES_DIR,
    SUPPRESSIONS_DIR,
    evaluate_rule,
    load_rule_file,
    load_rules,
    load_suppressions,
    run_rules,
)
from app.detection.sigma.rule import RuleLoadError
from app.models.analysis import Analysis
from app.storage.event_writer import bulk_copy_events
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.rules.events import T0, zscaler_event


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


@pytest.fixture
def analysis_factory(tenant_cleanup: list[uuid.UUID]) -> Callable[[], Analysis]:
    counter = {"n": 0}

    def _make() -> Analysis:
        counter["n"] += 1
        tenant = make_tenant(name=f"Suppression Tenant {counter['n']}")
        tenant_cleanup.append(tenant.id)
        user = make_user(tenant_id=tenant.id, email=f"suppress{counter['n']}@example.com")
        return make_analysis(tenant_id=tenant.id, user_id=user.id)

    return _make


def test_suppressions_load_and_declare_applies_to() -> None:
    suppressions = load_suppressions()
    assert suppressions, "expected at least one suppression under app/detection/rules/suppressions/"
    example = next(s for s in suppressions if s.rule.id == "backup-service-account-non-browser-ua")
    assert example.covers("sigma.non_browser_user_agent")
    assert example.covers("sigma.large_post_to_new_domain")
    assert not example.covers("sigma.brute_force")


def test_suppression_missing_applies_to_key_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad_suppression.yml"
    bad.write_text(
        """
title: t
id: bad-suppression
status: experimental
logsource: {product: zscaler}
detection:
  a: {principal: 'x'}
  condition: a
level: informational
tags: [attack.t1105]
entity: {type: user, by: principal}
"""
    )
    with pytest.raises(RuleLoadError):
        load_suppressions(tmp_path)


def test_backup_account_non_browser_ua_is_suppressed_end_to_end(
    analysis_factory: Callable[[], Analysis],
) -> None:
    analysis = analysis_factory()
    rows = [
        # The catalogued backup account's own automation traffic, from its own known egress --
        # would otherwise trip non-browser-user-agent.
        zscaler_event(
            "svc-backup@corp.example",
            T0,
            "storage.example",
            user_agent="curl/8.4.0",
            http_method="PUT",
            src_ip="10.10.5.5",
        ),
        # An unrelated principal, different src_ip, identical automation UA -- must still fire.
        zscaler_event(
            "attacker@corp.example",
            T0,
            "storage.example",
            user_agent="curl/8.4.0",
            http_method="PUT",
            src_ip="198.51.100.77",
        ),
    ]
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=rows)
    finally:
        conn.close()

    ua_rule = load_rule_file(RULES_DIR / "non-browser-user-agent.yml")

    with get_engine().connect() as sa_conn:
        raw_matches = evaluate_rule(sa_conn, ua_rule, analysis.id, analysis.tenant_id)
        entity_values_raw = {m.entity_value for m in raw_matches}
        assert "10.10.5.5" in entity_values_raw, (
            "sanity check: the rule itself must fire on the backup account's src_ip before "
            "suppression is applied, or this test would prove nothing"
        )

        drafts = run_rules(
            sa_conn,
            analysis.id,
            analysis.tenant_id,
            rules=[ua_rule],
            suppressions=load_suppressions(),
        )

    entity_values = {
        d.entity_value for d in drafts if d.detector_key == "sigma.non_browser_user_agent"
    }
    assert "10.10.5.5" not in entity_values, "suppressed entity still produced a signal"
    assert "198.51.100.77" in entity_values, "suppression over-matched and ate an unrelated src_ip"


def test_suppressions_directory_is_not_picked_up_as_detection_rules() -> None:
    rules = load_rules()
    assert "backup-service-account-non-browser-ua" not in {r.id for r in rules}
    assert SUPPRESSIONS_DIR.parent.name == "rules"
