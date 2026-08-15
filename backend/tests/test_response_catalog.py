"""`app.response.catalog` — the on-disk `actions.yml` loads and validates, and the loader's own
graph-shape guard fails loudly on a broken catalog. Pure unit tests, no DB."""

from __future__ import annotations

import pytest

from app.response.catalog import CatalogError, get_catalog, load_catalog

EXPECTED_ACTION_IDS = {
    "revoke_okta_sessions",
    "force_credential_reset",
    "deactivate_compromised_mfa_factor",
    "disable_api_key",
    "block_domain_at_proxy",
    "block_dst_ip",
    "isolate_host",
    "suspend_user_account",
    "quarantine_file",
}


def _node(
    action_id: str,
    *,
    depends_on: list[str] | None = None,
    reversible: bool = True,
    rollback: str | None = "some_rollback",
    target_type: str = "user",
    blast_radius: str = "user",
) -> dict:
    return {
        "id": action_id,
        "name": action_id,
        "target_type": target_type,
        "preconditions": [],
        "effects": [],
        "blast_radius": blast_radius,
        "reversible": reversible,
        "rollback": rollback,
        "depends_on": depends_on or [],
        "mitre_mitigation": "M1018",
    }


def test_real_catalog_has_every_action_docs_08_lists() -> None:
    catalog = get_catalog()
    assert set(catalog.actions.keys()) == EXPECTED_ACTION_IDS


def test_real_catalog_is_cached_singleton() -> None:
    assert get_catalog() is get_catalog()


@pytest.mark.parametrize("action_id", sorted(EXPECTED_ACTION_IDS))
def test_every_action_has_required_fields(action_id: str) -> None:
    action = get_catalog()[action_id]
    assert action.name
    assert action.target_type
    assert action.blast_radius in ("user", "host", "org")
    assert action.mitre_mitigation.startswith("M")
    # rollback availability must be consistent with reversibility (catalog.py's own invariant,
    # exercised here for documentation — the loader would already have rejected a mismatch).
    assert action.reversible == (action.rollback is not None)


def test_revoke_sessions_is_irreversible_with_no_rollback() -> None:
    action = get_catalog()["revoke_okta_sessions"]
    assert action.reversible is False
    assert action.rollback is None


def test_force_credential_reset_depends_on_revoke_sessions() -> None:
    # docs/08's explicit ordering example, verbatim: "resetting first leaves live sessions."
    action = get_catalog()["force_credential_reset"]
    assert action.depends_on == ("revoke_okta_sessions",)


def test_domain_and_dst_ip_blocks_have_org_blast_radius() -> None:
    assert get_catalog()["block_domain_at_proxy"].blast_radius == "org"
    assert get_catalog()["block_dst_ip"].blast_radius == "org"


def test_unknown_depends_on_fails_loudly() -> None:
    with pytest.raises(CatalogError, match="unknown action"):
        load_catalog(raw=[_node("a", depends_on=["does_not_exist"])])


def test_self_loop_fails_loudly() -> None:
    with pytest.raises(CatalogError, match="depends on itself"):
        load_catalog(raw=[_node("a", depends_on=["a"])])


def test_duplicate_action_id_fails_loudly() -> None:
    with pytest.raises(CatalogError, match="duplicate action id"):
        load_catalog(raw=[_node("a"), _node("a")])


def test_two_node_cycle_fails_loudly() -> None:
    with pytest.raises(CatalogError, match="dependency cycle"):
        load_catalog(raw=[_node("a", depends_on=["b"]), _node("b", depends_on=["a"])])


def test_three_node_cycle_fails_loudly() -> None:
    with pytest.raises(CatalogError, match="dependency cycle"):
        load_catalog(
            raw=[
                _node("a", depends_on=["b"]),
                _node("b", depends_on=["c"]),
                _node("c", depends_on=["a"]),
            ]
        )


def test_malformed_node_fails_loudly() -> None:
    with pytest.raises(CatalogError):
        load_catalog(raw=[{"id": "a"}])  # missing every other required field


def test_not_reversible_but_has_rollback_is_rejected() -> None:
    with pytest.raises(CatalogError):
        load_catalog(raw=[_node("a", reversible=False, rollback="undo_a")])


def test_reversible_but_no_rollback_is_rejected() -> None:
    with pytest.raises(CatalogError):
        load_catalog(raw=[_node("a", reversible=True, rollback=None)])
