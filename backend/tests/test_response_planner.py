"""`app.response.planner` — mapping recommended_actions to catalog ids, per-target dependency
closure, deterministic topological ordering, and loud failure on an unmapped action or a cycle.
Pure unit tests, no DB — `derive_plan` takes an optional injected `catalog`, which is exactly
what makes the cycle test possible (the real, on-disk `actions.yml` is guaranteed acyclic by
`app.response.catalog`'s own load-time guard, tested separately in test_response_catalog.py)."""

from __future__ import annotations

import pytest

from app.response.catalog import ActionCatalog, ActionDef
from app.response.planner import (
    InvalidRecommendationError,
    PlanCycleError,
    UnknownActionError,
    derive_plan,
)


def test_unknown_action_is_rejected() -> None:
    """docs/07: "recommended_actions[].action must be an action ID from the response action
    graph... Free-text actions are rejected." This is that rejection."""
    with pytest.raises(UnknownActionError) as exc_info:
        derive_plan([{"action": "delete_the_evidence", "target": "alice"}])
    assert exc_info.value.action == "delete_the_evidence"


def test_missing_action_field_is_rejected() -> None:
    with pytest.raises(InvalidRecommendationError):
        derive_plan([{"target": "alice"}])


def test_missing_target_field_is_rejected() -> None:
    with pytest.raises(InvalidRecommendationError):
        derive_plan([{"action": "block_domain_at_proxy"}])


def test_non_object_entry_is_rejected() -> None:
    with pytest.raises(InvalidRecommendationError):
        derive_plan(["block_domain_at_proxy"])  # type: ignore[list-item]


def test_single_action_with_no_dependencies() -> None:
    steps = derive_plan([{"action": "block_domain_at_proxy", "target": "evil.example.com"}])
    assert len(steps) == 1
    assert steps[0].action_id == "block_domain_at_proxy"
    assert steps[0].target == "evil.example.com"
    assert steps[0].implied is False
    assert steps[0].step == 1


def test_dependency_closure_inserts_the_missing_prerequisite() -> None:
    """Requesting force_credential_reset for alice without separately requesting
    revoke_okta_sessions for alice must still insert the prerequisite step — targeting alice,
    not some other principal."""
    steps = derive_plan([{"action": "force_credential_reset", "target": "alice"}])
    action_ids = [s.action_id for s in steps]
    assert action_ids == ["revoke_okta_sessions", "force_credential_reset"]
    assert all(s.target == "alice" for s in steps)
    assert steps[0].implied is True  # pulled in by closure
    assert steps[1].implied is False  # directly requested


def test_dependency_ordering_is_respected_regardless_of_input_order() -> None:
    steps = derive_plan(
        [
            {"action": "force_credential_reset", "target": "alice"},
            {"action": "revoke_okta_sessions", "target": "alice"},
        ]
    )
    assert [s.action_id for s in steps] == ["revoke_okta_sessions", "force_credential_reset"]


def test_three_dependents_all_ordered_after_shared_dependency() -> None:
    steps = derive_plan(
        [
            {"action": "suspend_user_account", "target": "bob"},
            {"action": "deactivate_compromised_mfa_factor", "target": "bob"},
            {"action": "force_credential_reset", "target": "bob"},
        ]
    )
    action_ids = [s.action_id for s in steps]
    assert action_ids[0] == "revoke_okta_sessions"
    assert set(action_ids[1:]) == {
        "suspend_user_account",
        "deactivate_compromised_mfa_factor",
        "force_credential_reset",
    }


def test_different_targets_do_not_share_a_closure() -> None:
    """force_credential_reset for alice must not be satisfied by revoking bob's sessions."""
    steps = derive_plan(
        [
            {"action": "revoke_okta_sessions", "target": "bob"},
            {"action": "force_credential_reset", "target": "alice"},
        ]
    )
    by_target: dict[str, list[str]] = {}
    for s in steps:
        by_target.setdefault(s.target, []).append(s.action_id)
    assert by_target["bob"] == ["revoke_okta_sessions"]
    assert by_target["alice"] == ["revoke_okta_sessions", "force_credential_reset"]


def test_independent_actions_preserve_a_stable_order() -> None:
    """Two actions with no dependency relationship keep their requested (discovery) order —
    determinism, not an arbitrary topological tie-break."""
    steps = derive_plan(
        [
            {"action": "block_domain_at_proxy", "target": "evil.example.com"},
            {"action": "isolate_host", "target": "host-1"},
        ]
    )
    assert [s.action_id for s in steps] == ["block_domain_at_proxy", "isolate_host"]


def test_derive_plan_is_deterministic_across_calls() -> None:
    recs = [
        {"action": "suspend_user_account", "target": "carol"},
        {"action": "block_dst_ip", "target": "203.0.113.9"},
        {"action": "deactivate_compromised_mfa_factor", "target": "carol"},
    ]
    first = [s.action_id for s in derive_plan(recs)]
    second = [s.action_id for s in derive_plan(recs)]
    assert first == second


def test_annotations_carry_blast_radius_and_rollback_availability() -> None:
    steps = derive_plan([{"action": "revoke_okta_sessions", "target": "alice"}])
    step = steps[0]
    assert step.blast_radius == "user"
    assert step.reversible is False
    assert step.rollback_available is False
    assert step.preconditions == ("user_exists", "has_active_sessions")
    assert step.mitre_mitigation == "M1018"


def test_rationale_is_carried_through() -> None:
    steps = derive_plan(
        [
            {
                "action": "block_domain_at_proxy",
                "target": "evil.example.com",
                "rationale": "C2 beaconing domain",
            }
        ]
    )
    assert steps[0].rationale == "C2 beaconing domain"


# ---------------------------------------------------------------------------- cycle detection


def _node(action_id: str, depends_on: list[str]) -> ActionDef:
    return ActionDef(
        id=action_id,
        name=action_id,
        target_type="user",
        preconditions=(),
        effects=(),
        blast_radius="user",
        reversible=True,
        rollback=f"undo_{action_id}",
        depends_on=tuple(depends_on),
        mitre_mitigation="M1018",
    )


def test_planner_fails_loudly_on_a_cyclic_catalog() -> None:
    """The real actions.yml is guaranteed acyclic (test_response_catalog.py) — this proves
    derive_plan's *own* topological sort also fails loudly, per docs/08 ("Cycles are a config
    bug; fail loudly"), independent of that separate load-time guard. `ActionCatalog` is
    constructed directly here (bypassing `load_catalog`'s `_validate_graph_shape` check) so the
    only thing standing between a broken catalog and a silent, wrong ordering is the planner's
    own cycle detection.
    """
    broken = ActionCatalog(
        actions={
            "a": _node("a", depends_on=["b"]),
            "b": _node("b", depends_on=["a"]),
        }
    )
    with pytest.raises(PlanCycleError) as exc_info:
        derive_plan([{"action": "a", "target": "alice"}], catalog=broken)
    assert ("a", "alice") in exc_info.value.cycle or ("b", "alice") in exc_info.value.cycle


def test_cycle_error_message_names_the_cycle() -> None:
    broken = ActionCatalog(
        actions={
            "a": _node("a", depends_on=["b"]),
            "b": _node("b", depends_on=["a"]),
        }
    )
    with pytest.raises(PlanCycleError, match=r"a\(alice\).*b\(alice\)|b\(alice\).*a\(alice\)"):
        derive_plan([{"action": "a", "target": "alice"}], catalog=broken)


def test_three_node_cycle_is_also_caught() -> None:
    broken = ActionCatalog(
        actions={
            "a": _node("a", depends_on=["b"]),
            "b": _node("b", depends_on=["c"]),
            "c": _node("c", depends_on=["a"]),
        }
    )
    with pytest.raises(PlanCycleError):
        derive_plan([{"action": "a", "target": "alice"}], catalog=broken)


def test_acyclic_custom_catalog_still_plans_normally() -> None:
    custom = ActionCatalog(
        actions={
            "a": _node("a", depends_on=[]),
            "b": _node("b", depends_on=["a"]),
        }
    )
    steps = derive_plan([{"action": "b", "target": "alice"}], catalog=custom)
    assert [s.action_id for s in steps] == ["a", "b"]
