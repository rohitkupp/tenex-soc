"""`app.detection.sigma.compiler` — field resolution errors, and the "everything is SQL, nothing
is pulled into Python to be filtered there" claim (CLAUDE.md's spirit, docs/04's "compile Sigma
`detection` blocks into SQL predicates ... do not pull a million rows into Python").
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import Connection

from app.core.config import get_settings
from app.core.db import get_engine
from app.detection.sigma.compiler import UnsupportedConditionError, evaluate_rule
from app.detection.sigma.fields import FieldResolutionError, resolve_field
from app.detection.sigma.rule import RuleLoadError, load_rule_file
from app.models.analysis import Analysis
from app.storage.event_writer import bulk_copy_events
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.rules.events import T0, okta_event

_MINIMAL_RULE = """
title: t
id: minimal-presence
status: experimental
logsource: {{product: okta}}
detection:
  sel:
    activity_name: '{event_type}'
  condition: sel
level: medium
tags: [attack.t1078]
entity: {{type: user, by: principal}}
"""


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


@pytest.fixture
def analysis(tenant_cleanup: list[uuid.UUID]) -> Analysis:
    tenant = make_tenant(name="Sigma Compiler Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="compiler@example.com")
    return make_analysis(tenant_id=tenant.id, user_id=user.id)


def test_unknown_field_raises_field_resolution_error() -> None:
    with pytest.raises(FieldResolutionError):
        resolve_field("this_field_does_not_exist")


def test_rule_referencing_unknown_field_raises_at_evaluation(
    tmp_path: Path, analysis: Analysis
) -> None:
    bad_rule = tmp_path / "bad.yml"
    bad_rule.write_text(
        """
title: t
id: bad-field
status: experimental
logsource: {product: okta}
detection:
  sel:
    this_field_does_not_exist: 'x'
  condition: sel
level: medium
tags: [attack.t1078]
entity: {type: user, by: principal}
"""
    )
    rule = load_rule_file(bad_rule)
    with get_engine().connect() as conn, pytest.raises(FieldResolutionError):
        evaluate_rule(conn, rule, analysis.id, analysis.tenant_id)


def test_condition_referencing_undefined_block_raises(tmp_path: Path, analysis: Analysis) -> None:
    bad_rule = tmp_path / "bad_block.yml"
    bad_rule.write_text(
        """
title: t
id: bad-block
status: experimental
logsource: {product: okta}
detection:
  sel:
    activity_name: 'user.session.start'
  condition: not_a_real_block
level: medium
tags: [attack.t1078]
entity: {type: user, by: principal}
"""
    )
    rule = load_rule_file(bad_rule)
    with get_engine().connect() as conn, pytest.raises(RuleLoadError):
        evaluate_rule(conn, rule, analysis.id, analysis.tenant_id)


def test_unsupported_condition_shape_raises(tmp_path: Path, analysis: Analysis) -> None:
    """Two aggregations ANDed together is not one of the supported strategies (module docstring,
    `app.detection.sigma.compiler`) — must fail loudly, not silently mishandle."""
    bad_rule = tmp_path / "double_agg.yml"
    bad_rule.write_text(
        """
title: t
id: double-agg
status: experimental
logsource: {product: okta}
detection:
  a:
    activity_name: 'user.session.start'
    status: 'FAILURE'
  b:
    activity_name: 'user.authentication.auth_via_mfa'
    status: 'FAILURE'
  timeframe: 15m
  condition: a | count() by principal >= 3 and b | count() by principal >= 3
level: medium
tags: [attack.t1078]
entity: {type: user, by: principal}
"""
    )
    rule = load_rule_file(bad_rule)
    with get_engine().connect() as conn, pytest.raises(UnsupportedConditionError):
        evaluate_rule(conn, rule, analysis.id, analysis.tenant_id)


def test_evaluation_is_a_single_sql_round_trip_regardless_of_event_count(
    tmp_path: Path, analysis: Analysis
) -> None:
    """The evaluator must not pull events into Python to filter/aggregate them there — every
    predicate and aggregation is SQL. Proven here by counting `Connection.execute` calls via a
    real SQLAlchemy event hook rather than trusting the implementation not to have snuck in a
    second query: evaluating a presence rule over 500 events takes exactly one round trip."""
    rule_path = tmp_path / "presence.yml"
    rule_path.write_text(_MINIMAL_RULE.format(event_type="user.session.start"))
    rule = load_rule_file(rule_path)

    rows = [
        okta_event(
            "same.user@corp.example", T0 + timedelta(seconds=i), "user.session.start", "SUCCESS"
        )
        for i in range(500)
    ]
    conn = _raw_connection()
    try:
        bulk_copy_events(conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=rows)
    finally:
        conn.close()

    calls: list[str] = []

    def _before_execute(
        conn: Connection,
        clauseelement: object,
        multiparams: object,
        params: object,
        execution_options: object,
    ) -> None:
        calls.append(str(clauseelement)[:80])

    engine = get_engine()
    with engine.connect() as sa_conn:
        from sqlalchemy import event as sa_event

        sa_event.listen(sa_conn, "before_execute", _before_execute)
        try:
            matches = evaluate_rule(sa_conn, rule, analysis.id, analysis.tenant_id)
        finally:
            sa_event.remove(sa_conn, "before_execute", _before_execute)

    assert len(matches) == 1
    assert matches[0].detail["matched_events"] == 500
    assert len(calls) == 1, f"expected exactly one SQL round trip, got {len(calls)}: {calls}"
