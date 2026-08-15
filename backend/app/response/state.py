"""The simulated enforcement plane's storage layer — docs/08 "Simulated enforcement plane",
backed by `enforcement_state` (docs/02).

**What is simulated versus real, precisely.** The *resources* here (Okta sessions/factors, proxy
policy rows, host inventory, API keys) are simulated — there is no real Okta tenant or real proxy
behind them, just rows in Postgres seeded to look like one. Everything that operates on those
rows — reading current state, checking preconditions against it, applying effects, journaling
before/after, and reversing via the journal — is real code with real, observable behavior. See
`app.response.executor` and `app.response.preconditions` for where that happens; this module only
owns the resource shapes and the read/write/seed primitives.

**Resource-type -> action binding.** `enforcement_state.resource_type` is fixed by docs/02 to
`proxy_policy|okta_session|okta_factor|host|api_key` (no `user` type — see `actions.yml`'s header
comment for why `okta_session` doubles as the "Okta user record"). `ACTION_RESOURCE_TYPE` below is
the one place that maps a catalog action id to the resource type it actually mutates; every other
module (`executor.py`, `outcome.py`) goes through `resolve_primary_resource` rather than
duplicating this table.
"""

from __future__ import annotations

import uuid
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.enforcement_state import EnforcementState

# ---------------------------------------------------------------------------- resource typing

RESOURCE_OKTA_SESSION: Final[str] = "okta_session"
RESOURCE_OKTA_FACTOR: Final[str] = "okta_factor"
RESOURCE_PROXY_POLICY: Final[str] = "proxy_policy"
RESOURCE_HOST: Final[str] = "host"
RESOURCE_API_KEY: Final[str] = "api_key"

# action_id -> the one resource_type its `effects` mutate. Preconditions may read a *different*
# resource_type for the same action (e.g. deactivate_compromised_mfa_factor's `user_exists`
# precondition reads `okta_session`, even though the action's effect is on `okta_factor`) — see
# preconditions.py, which is not restricted to this table.
ACTION_RESOURCE_TYPE: Final[dict[str, str]] = {
    "revoke_okta_sessions": RESOURCE_OKTA_SESSION,
    "force_credential_reset": RESOURCE_OKTA_SESSION,
    "suspend_user_account": RESOURCE_OKTA_SESSION,
    "deactivate_compromised_mfa_factor": RESOURCE_OKTA_FACTOR,
    "disable_api_key": RESOURCE_API_KEY,
    "block_domain_at_proxy": RESOURCE_PROXY_POLICY,
    "block_dst_ip": RESOURCE_PROXY_POLICY,
    "isolate_host": RESOURCE_HOST,
    "quarantine_file": RESOURCE_HOST,
}


class UnknownActionResourceError(Exception):
    """`ACTION_RESOURCE_TYPE` (or the quarantine_file target convention) doesn't cover this
    action id — a catalog/state module drift, not a runtime data problem."""


def split_host_file_target(target: str) -> tuple[str, str]:
    """`quarantine_file`'s target convention is `"<host_id>:<file_ref>"` (actions.yml's header
    comment). Splits on the first `:` — host identifiers and file refs (hashes) never contain
    one, but if a future target ever needs to, this is the one place to widen the format."""
    host_id, sep, file_ref = target.partition(":")
    if not sep:
        raise ValueError(f"quarantine_file target must be '<host_id>:<file_ref>', got {target!r}")
    return host_id, file_ref


def resolve_primary_resource(action_id: str, target: str) -> tuple[str, str]:
    """`(resource_type, resource_id)` for the one `enforcement_state` row an action's `effects`
    read-then-write — mirrors docs/08's executor pseudocode ("before = read_state(action.target)"
    — one resource per action). Used by both `executor.py` (to apply effects) and
    `app.api.plans` (rollback, state-diff) to recover which row a journal entry touched, since
    `enforcement_journal` itself carries no resource_type/resource_id column (docs/02) — see
    `executor.rollback_plan`'s docstring for how that recovery works.
    """
    resource_type = ACTION_RESOURCE_TYPE.get(action_id)
    if resource_type is None:
        raise UnknownActionResourceError(action_id)
    if action_id == "quarantine_file":
        host_id, _file_ref = split_host_file_target(target)
        return resource_type, host_id
    return resource_type, target


# ---------------------------------------------------------------------------- read / write


def read_state(
    db: Session, tenant_id: uuid.UUID, resource_type: str, resource_id: str
) -> dict[str, Any] | None:
    """The live `state` JSON for one resource, or `None` if it has never been seeded/touched."""
    row = db.execute(
        select(EnforcementState).where(
            EnforcementState.tenant_id == tenant_id,
            EnforcementState.resource_type == resource_type,
            EnforcementState.resource_id == resource_id,
        )
    ).scalar_one_or_none()
    return row.state if row is not None else None


def write_state(
    db: Session, tenant_id: uuid.UUID, resource_type: str, resource_id: str, state: dict[str, Any]
) -> None:
    """Upsert `state` for one resource — the only way any code in this package mutates
    `enforcement_state`, so every write is unconditionally observable via the
    `UNIQUE (tenant_id, resource_type, resource_id)` row it lands on."""
    stmt = pg_insert(EnforcementState).values(
        tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id, state=state
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "resource_type", "resource_id"],
        set_={"state": stmt.excluded.state, "updated_at": func.now()},
    )
    db.execute(stmt)


def seed_if_missing(
    db: Session,
    tenant_id: uuid.UUID,
    resource_type: str,
    resource_id: str,
    default_state: dict[str, Any],
) -> None:
    """Insert `default_state` only if this resource has never been seeded. Idempotent and
    non-destructive by design — calling this again after a plan has already mutated the resource
    must never clobber real (simulated-real) execution history."""
    stmt = pg_insert(EnforcementState).values(
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        state=default_state,
    )
    stmt = stmt.on_conflict_do_nothing(index_elements=["tenant_id", "resource_type", "resource_id"])
    db.execute(stmt)


# ---------------------------------------------------------------------------- default seeding


def default_okta_session_state() -> dict[str, Any]:
    """A freshly-seeded user: two live sessions, no reset pending, active account — i.e. the
    state a genuinely still-compromised identity would be in before any response action runs."""
    return {
        "sessions": [{"id": "sess-1", "active": True}, {"id": "sess-2", "active": True}],
        "credential_reset_required": False,
        "account_status": "active",
    }


def default_okta_factor_state() -> dict[str, Any]:
    return {"factors": [{"id": "factor-1", "type": "push", "active": True}]}


def default_proxy_policy_state(*, kind: str) -> dict[str, Any]:
    return {"kind": kind, "blocked": False, "allowlisted": False}


def default_host_state(*, hostname: str, file_ref: str | None = None) -> dict[str, Any]:
    files: dict[str, Any] = {}
    if file_ref is not None:
        files[file_ref] = {"present": True, "quarantined": False}
    return {"isolated": False, "hostname": hostname, "files": files}


def default_api_key_state(*, key_id: str) -> dict[str, Any]:
    return {"enabled": True, "key_id": key_id}


def seed_for_step(db: Session, tenant_id: uuid.UUID, action_id: str, target: str) -> None:
    """Seed every resource a given plan step's preconditions or effects will read, if it isn't
    already present. docs/08: "Seeded from the analysis: every principal gets an Okta user
    record with sessions and factors, every domain a proxy policy row, every host an inventory
    row" — applied here per plan step's target rather than by scanning `entities` directly (see
    `app.response.orchestration` for why: a synthetic incident built directly against these
    tables in tests has no `entities` rows to scan, and every target this plan will ever touch
    is already known from the plan itself, so seeding off the plan is both sufficient and
    strictly more decoupled from the detection pipeline's own tables).
    """
    target_type = _target_type_for(action_id)

    if target_type == "user":
        seed_if_missing(db, tenant_id, RESOURCE_OKTA_SESSION, target, default_okta_session_state())
        seed_if_missing(db, tenant_id, RESOURCE_OKTA_FACTOR, target, default_okta_factor_state())
    elif target_type == "domain":
        seed_if_missing(
            db, tenant_id, RESOURCE_PROXY_POLICY, target, default_proxy_policy_state(kind="domain")
        )
    elif target_type == "dst_ip":
        seed_if_missing(
            db, tenant_id, RESOURCE_PROXY_POLICY, target, default_proxy_policy_state(kind="dst_ip")
        )
    elif target_type == "api_key":
        seed_if_missing(
            db, tenant_id, RESOURCE_API_KEY, target, default_api_key_state(key_id=target)
        )
    elif target_type == "host" and action_id == "quarantine_file":
        host_id, file_ref = split_host_file_target(target)
        seed_if_missing(
            db,
            tenant_id,
            RESOURCE_HOST,
            host_id,
            default_host_state(hostname=host_id, file_ref=file_ref),
        )
    elif target_type == "host":
        seed_if_missing(db, tenant_id, RESOURCE_HOST, target, default_host_state(hostname=target))
    else:  # pragma: no cover — defensive; every target_type in actions.yml is handled above
        raise UnknownActionResourceError(action_id)


def _target_type_for(action_id: str) -> str:
    from app.response.catalog import get_catalog

    return get_catalog()[action_id].target_type
