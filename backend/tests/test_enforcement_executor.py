"""`app.response.executor` — docs/08's executor loop and rollback, run for real against the live
Postgres `enforcement_state`/`enforcement_journal` tables. This file is where the milestone's
core acceptance bar lives:

  * ordering matters: revoke-then-reset produces a different end state than reset-then-revoke
  * a deliberately failing precondition halts the plan and is recorded in the journal
  * rollback restores exactly
"""

from __future__ import annotations

import uuid

import pytest

from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.models.response_plan import ResponsePlan
from app.response import effects, executor, state
from app.response.planner import PlanStep
from tests.conftest import make_tenant
from tests.fixtures.response import response_tenant_cleanup  # noqa: F401


@pytest.fixture
def tenant_id(response_tenant_cleanup: list[uuid.UUID]) -> uuid.UUID:  # noqa: F811
    tenant = make_tenant(name="Enforcement Executor Test Tenant")
    response_tenant_cleanup.append(tenant.id)
    return tenant.id


def _step(
    action_id: str,
    target: str,
    *,
    step: int,
    preconditions: tuple[str, ...],
    depends_on: tuple[str, ...] = (),
) -> PlanStep:
    from app.response.catalog import get_catalog

    definition = get_catalog()[action_id]
    return PlanStep(
        step=step,
        action_id=action_id,
        name=definition.name,
        target=target,
        target_type=definition.target_type,
        preconditions=preconditions,
        blast_radius=definition.blast_radius,
        reversible=definition.reversible,
        rollback=definition.rollback,
        rollback_available=definition.rollback is not None,
        depends_on=depends_on,
        mitre_mitigation=definition.mitre_mitigation,
        rationale=None,
        implied=False,
    )


def _make_incident_and_plan(
    tenant_id: uuid.UUID, steps: list[PlanStep]
) -> tuple[uuid.UUID, uuid.UUID]:
    """`enforcement_journal.plan_id REFERENCES response_plans.id` and `response_plans.incident_id
    REFERENCES incidents.id` are real FKs (docs/02) — every executor test needs a real row on
    both to legally journal against. Returns `(incident_id, plan_id)`."""
    from tests.conftest import make_analysis, make_user
    from tests.fixtures.response import make_incident

    user = make_user(tenant_id=tenant_id, email=f"executor-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant_id, user_id=user.id)
    incident = make_incident(tenant_id=tenant_id, analysis_id=analysis.id)

    session = get_session_factory()()
    try:
        plan = ResponsePlan(
            incident_id=incident.id,
            actions=[s.model_dump(mode="json") for s in steps],
            verification={"skipped": "llm_disabled"},
            status="pending_approval",
            execution_log=[],
        )
        session.add(plan)
        session.commit()
        session.refresh(plan)
        return incident.id, plan.id
    finally:
        session.close()


# ---------------------------------------------------------------------------- happy path


def test_execute_plan_single_action_succeeds_and_journals(tenant_id: uuid.UUID) -> None:
    steps = [
        _step(
            "block_domain_at_proxy",
            "evil.example.com",
            step=1,
            preconditions=("domain_not_allowlisted",),
        )
    ]
    _incident_id, plan_id = _make_incident_and_plan(tenant_id, steps)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = executor.execute_plan(session, tenant_id, plan_id, steps)
            session.commit()

            assert result.halted is False
            assert len(result.journal) == 1
            assert result.journal[0].succeeded is True
            assert result.journal[0].before_state == {
                "kind": "domain",
                "blocked": False,
                "allowlisted": False,
            }
            assert result.journal[0].after_state == {
                "kind": "domain",
                "blocked": True,
                "allowlisted": False,
            }

            live = state.read_state(
                session, tenant_id, state.RESOURCE_PROXY_POLICY, "evil.example.com"
            )
        assert live is not None and live["blocked"] is True
    finally:
        session.close()


# ---------------------------------------------------------------------------- ordering + halting


def test_ordering_matters_and_a_failing_precondition_halts_the_plan(tenant_id: uuid.UUID) -> None:
    """The single most load-bearing test in this milestone. Runs the SAME two actions
    (revoke_okta_sessions, force_credential_reset) against the SAME freshly-seeded user in both
    orders and shows the end states genuinely differ — and, in the same run, that the wrong order
    halts on a real failing precondition with the failure recorded in the journal (docs/08's
    "ordering is observable" and "a deliberately failing precondition halts the plan" bars,
    proven together since they are the same underlying mechanism).
    """
    revoke = _step(
        "revoke_okta_sessions",
        "alice",
        step=1,
        preconditions=("user_exists", "has_active_sessions"),
    )
    reset = _step(
        "force_credential_reset",
        "alice",
        step=2,
        preconditions=("user_exists", "sessions_revoked"),
        depends_on=("revoke_okta_sessions",),
    )

    # ---- correct order: revoke, then reset ----
    correct_steps = [revoke, reset]
    _incident_a, plan_a = _make_incident_and_plan(tenant_id, correct_steps)
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result_correct = executor.execute_plan(session, tenant_id, plan_a, correct_steps)
            session.commit()
            end_state_correct = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "alice"
            )
    finally:
        session.close()

    assert result_correct.halted is False
    assert len(result_correct.journal) == 2
    assert all(row.succeeded for row in result_correct.journal)
    assert end_state_correct is not None
    assert all(not s["active"] for s in end_state_correct["sessions"])
    assert end_state_correct["credential_reset_required"] is True

    # ---- reversed order: reset attempted before revoke, for a DIFFERENT user (bob) so the two
    # runs don't share seeded state ----
    reversed_steps = [
        _step(
            "force_credential_reset",
            "bob",
            step=1,
            preconditions=("user_exists", "sessions_revoked"),
        ),
        _step(
            "revoke_okta_sessions",
            "bob",
            step=2,
            preconditions=("user_exists", "has_active_sessions"),
        ),
    ]
    _incident_b, plan_b = _make_incident_and_plan(tenant_id, reversed_steps)
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result_reversed = executor.execute_plan(session, tenant_id, plan_b, reversed_steps)
            session.commit()
            end_state_reversed = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "bob"
            )
    finally:
        session.close()

    # Halted on the very first step: force_credential_reset's sessions_revoked precondition
    # fails because bob's sessions are still live (this is a real check against real state).
    assert result_reversed.halted is True
    assert result_reversed.halted_step == 1
    assert len(result_reversed.journal) == 1
    failed_entry = result_reversed.journal[0]
    assert failed_entry.succeeded is False
    assert failed_entry.action_id == "force_credential_reset"
    assert failed_entry.after_state is None
    assert failed_entry.precondition_failure is not None
    assert "sessions_revoked" in failed_entry.precondition_failure

    # revoke_okta_sessions never ran — the plan stopped, per docs/08, rather than skipping ahead.
    assert end_state_reversed is not None
    assert all(s["active"] for s in end_state_reversed["sessions"])
    assert end_state_reversed["credential_reset_required"] is False

    # The two end states are genuinely different, from the SAME two actions, purely because of
    # order — this is the "ordering is observable" bar.
    assert end_state_correct != end_state_reversed
    assert (
        end_state_correct["credential_reset_required"]
        != end_state_reversed["credential_reset_required"]
    )
    assert all(not s["active"] for s in end_state_correct["sessions"])
    assert all(s["active"] for s in end_state_reversed["sessions"])


def test_precondition_failure_on_an_allowlisted_domain_halts_independent_of_ordering(
    tenant_id: uuid.UUID,
) -> None:
    """A second, non-ordering-related failing precondition: a domain explicitly marked
    allowlisted in the enforcement plane. Proves precondition failure is a general mechanism,
    not something only `sessions_revoked` can trigger."""
    step = _step(
        "block_domain_at_proxy",
        "partner.example.com",
        step=1,
        preconditions=("domain_not_allowlisted",),
    )
    _incident_id, plan_id = _make_incident_and_plan(tenant_id, [step])

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            # Seed the domain as allowlisted BEFORE execution — a real state fact the plan must
            # respect.
            state.seed_if_missing(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "partner.example.com",
                {"kind": "domain", "blocked": False, "allowlisted": True},
            )
            session.commit()

            result = executor.execute_plan(session, tenant_id, plan_id, [step])
            session.commit()
    finally:
        session.close()

    assert result.halted is True
    assert len(result.journal) == 1
    assert result.journal[0].succeeded is False
    assert "allowlisted" in (result.journal[0].precondition_failure or "")


# ---------------------------------------------------------------------------- rollback


def test_rollback_restores_state_exactly(tenant_id: uuid.UUID) -> None:
    revoke = _step(
        "revoke_okta_sessions",
        "carol",
        step=1,
        preconditions=("user_exists", "has_active_sessions"),
    )
    reset = _step(
        "force_credential_reset",
        "carol",
        step=2,
        preconditions=("user_exists", "sessions_revoked"),
        depends_on=("revoke_okta_sessions",),
    )
    steps = [revoke, reset]
    _incident_id, plan_id = _make_incident_and_plan(tenant_id, steps)
    plan_actions = [s.model_dump(mode="json") for s in steps]

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            before_anything = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "carol"
            )
            # not seeded yet
            assert before_anything is None

            result = executor.execute_plan(session, tenant_id, plan_id, steps)
            session.commit()
            assert result.halted is False

            after_execution = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "carol"
            )
            assert after_execution is not None
            assert all(not s["active"] for s in after_execution["sessions"])
            assert after_execution["credential_reset_required"] is True

            rolled_back_rows = executor.rollback_plan(session, tenant_id, plan_id, plan_actions)
            session.commit()

            after_rollback = state.read_state(
                session, tenant_id, state.RESOURCE_OKTA_SESSION, "carol"
            )
    finally:
        session.close()

    assert len(rolled_back_rows) == 2
    # Exactly the pre-seeded default state — the seed created when execute_plan first touched
    # this resource, restored byte-for-byte via the journal.
    assert after_rollback == {
        "sessions": [{"id": "sess-1", "active": True}, {"id": "sess-2", "active": True}],
        "credential_reset_required": False,
        "account_status": "active",
    }
    assert after_rollback != after_execution


def test_rollback_skips_the_halted_steps_own_journal_row(tenant_id: uuid.UUID) -> None:
    """A halted plan's failing step never mutated anything (`after_state=None`) — rollback must
    only reverse the steps that actually succeeded before the halt. Step 2's failure here is
    deliberately independent of step 1 (a pre-allowlisted domain, not anything about `dave`'s
    own state) so the halt reason can't be confused with an ordering dependency."""
    revoke = _step(
        "revoke_okta_sessions", "dave", step=1, preconditions=("user_exists", "has_active_sessions")
    )
    block_allowlisted = _step(
        "block_domain_at_proxy",
        "partner-b.example.com",
        step=2,
        preconditions=("domain_not_allowlisted",),
    )
    steps = [revoke, block_allowlisted]

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.seed_if_missing(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                "partner-b.example.com",
                {"kind": "domain", "blocked": False, "allowlisted": True},
            )
            session.commit()
    finally:
        session.close()

    _incident_id, plan_id = _make_incident_and_plan(tenant_id, steps)
    plan_actions = [s.model_dump(mode="json") for s in steps]

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            result = executor.execute_plan(session, tenant_id, plan_id, steps)
            session.commit()
            assert result.halted is True
            assert len(result.journal) == 2  # revoke succeeded, reset failed and halted
            assert result.journal[0].succeeded is True
            assert result.journal[1].succeeded is False

            rolled_back = executor.rollback_plan(session, tenant_id, plan_id, plan_actions)
            session.commit()

            end_state = state.read_state(session, tenant_id, state.RESOURCE_OKTA_SESSION, "dave")
    finally:
        session.close()

    # Only the one succeeded row (revoke) is reversed.
    assert len(rolled_back) == 1
    assert rolled_back[0].action_id == "revoke_okta_sessions"
    assert end_state is not None
    assert all(s["active"] for s in end_state["sessions"])  # back to pre-revoke


# ---------------------------------------------------------------------------- effects.py unit coverage


def test_apply_effects_quarantine_file() -> None:
    before = {
        "isolated": False,
        "hostname": "host-1",
        "files": {"deadbeef": {"present": True, "quarantined": False}},
    }
    after = effects.apply_effects("quarantine_file", "host-1:deadbeef", before)
    assert after["files"]["deadbeef"]["quarantined"] is True
    assert before["files"]["deadbeef"]["quarantined"] is False  # input untouched


def test_apply_effects_is_pure_and_does_not_mutate_input() -> None:
    before = {
        "sessions": [{"id": "s1", "active": True}],
        "credential_reset_required": False,
        "account_status": "active",
    }
    after = effects.apply_effects("revoke_okta_sessions", "alice", before)
    assert after["sessions"][0]["active"] is False
    assert before["sessions"][0]["active"] is True


def test_apply_effects_unknown_action_raises() -> None:
    with pytest.raises(effects.UnknownEffectError):
        effects.apply_effects("not_a_real_action", "alice", {})
