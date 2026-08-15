"""Precondition checks — evaluated against REAL rows in `enforcement_state`, per docs/08: "so a
failing precondition genuinely blocks the plan." Every function here reads whatever the DB
currently holds; none of them consult the plan or the catalog for anything beyond a target
string, so a check run twice against the same state always returns the same answer (no hidden
plan-relative state).

`app.response.executor` uses `check_preconditions` as the real gate before applying an action's
effects. `app.api.plans` uses the same function to render a live precondition preview on
`GET /api/incidents/{id}/plan` — one implementation, two call sites, so the preview a human
approver sees is never allowed to drift from what execution will actually enforce.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.response import state as enforcement_state


@dataclass(frozen=True)
class PreconditionCheck:
    id: str
    satisfied: bool
    reason: str


def _user_exists(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(
        db, tenant_id, enforcement_state.RESOURCE_OKTA_SESSION, target
    )
    return PreconditionCheck(
        "user_exists",
        row is not None,
        "no Okta user record for this principal" if row is None else "user record present",
    )


def _has_active_sessions(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(
        db, tenant_id, enforcement_state.RESOURCE_OKTA_SESSION, target
    )
    sessions = (row or {}).get("sessions", [])
    active = any(s.get("active") for s in sessions)
    return PreconditionCheck(
        "has_active_sessions",
        active,
        "at least one active session" if active else "no active sessions to revoke",
    )


def _sessions_revoked(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(
        db, tenant_id, enforcement_state.RESOURCE_OKTA_SESSION, target
    )
    sessions = (row or {}).get("sessions", [])
    all_revoked = row is not None and not any(s.get("active") for s in sessions)
    return PreconditionCheck(
        "sessions_revoked",
        all_revoked,
        "all sessions inactive" if all_revoked else "one or more sessions are still active",
    )


def _has_active_mfa_factor(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(
        db, tenant_id, enforcement_state.RESOURCE_OKTA_FACTOR, target
    )
    factors = (row or {}).get("factors", [])
    active = any(f.get("active") for f in factors)
    return PreconditionCheck(
        "has_active_mfa_factor",
        active,
        "at least one active MFA factor" if active else "no active MFA factor to deactivate",
    )


def _api_key_exists(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(db, tenant_id, enforcement_state.RESOURCE_API_KEY, target)
    return PreconditionCheck(
        "api_key_exists", row is not None, "no such API key" if row is None else "API key present"
    )


def _api_key_enabled(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(db, tenant_id, enforcement_state.RESOURCE_API_KEY, target)
    enabled = bool((row or {}).get("enabled"))
    return PreconditionCheck(
        "api_key_enabled", enabled, "key is enabled" if enabled else "key is already disabled"
    )


def _proxy_not_allowlisted(
    precondition_id: str,
) -> Callable[[Session, uuid.UUID, str], PreconditionCheck]:
    def check(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
        row = enforcement_state.read_state(
            db, tenant_id, enforcement_state.RESOURCE_PROXY_POLICY, target
        )
        # A resource that was never seeded is, by construction, not allowlisted — there is no
        # policy exception for it.
        allowlisted = bool((row or {}).get("allowlisted"))
        return PreconditionCheck(
            precondition_id,
            not allowlisted,
            "not on the allowlist" if not allowlisted else "target is explicitly allowlisted",
        )

    return check


def _host_exists(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(db, tenant_id, enforcement_state.RESOURCE_HOST, target)
    return PreconditionCheck(
        "host_exists", row is not None, "no such host" if row is None else "host present"
    )


def _host_not_isolated(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    row = enforcement_state.read_state(db, tenant_id, enforcement_state.RESOURCE_HOST, target)
    isolated = bool((row or {}).get("isolated"))
    return PreconditionCheck(
        "host_not_isolated",
        not isolated,
        "host is on the network" if not isolated else "host is already isolated",
    )


def _file_present(db: Session, tenant_id: uuid.UUID, target: str) -> PreconditionCheck:
    host_id, file_ref = enforcement_state.split_host_file_target(target)
    row = enforcement_state.read_state(db, tenant_id, enforcement_state.RESOURCE_HOST, host_id)
    files: dict[str, Any] = (row or {}).get("files", {})
    entry = files.get(file_ref)
    present = bool(entry and entry.get("present") and not entry.get("quarantined"))
    if entry is None:
        reason = "file not found in host inventory"
    elif entry.get("quarantined"):
        reason = "file is already quarantined"
    else:
        reason = "file present and not yet quarantined"
    return PreconditionCheck("file_present", present, reason)


_CHECKS: dict[str, Callable[[Session, uuid.UUID, str], PreconditionCheck]] = {
    "user_exists": _user_exists,
    "has_active_sessions": _has_active_sessions,
    "sessions_revoked": _sessions_revoked,
    "has_active_mfa_factor": _has_active_mfa_factor,
    "api_key_exists": _api_key_exists,
    "api_key_enabled": _api_key_enabled,
    "domain_not_allowlisted": _proxy_not_allowlisted("domain_not_allowlisted"),
    "dst_ip_not_allowlisted": _proxy_not_allowlisted("dst_ip_not_allowlisted"),
    "host_exists": _host_exists,
    "host_not_isolated": _host_not_isolated,
    "file_present": _file_present,
}


class UnknownPreconditionError(Exception):
    """A catalog action references a precondition id with no registered check function — a
    drift between `actions.yml` and this module, caught the first time that action is planned
    rather than silently treated as always-satisfied."""


def evaluate(
    precondition_id: str, db: Session, tenant_id: uuid.UUID, target: str
) -> PreconditionCheck:
    check_fn = _CHECKS.get(precondition_id)
    if check_fn is None:
        raise UnknownPreconditionError(precondition_id)
    return check_fn(db, tenant_id, target)


def check_preconditions(
    db: Session,
    tenant_id: uuid.UUID,
    action_id: str,
    target: str,
    *,
    precondition_ids: tuple[str, ...],
) -> tuple[bool, list[PreconditionCheck]]:
    """Evaluate every precondition `action_id` declares (passed in explicitly as
    `precondition_ids` — from the catalog, or from a plan step that already resolved them — so
    this module never has to import `app.response.catalog` itself). Returns `(all_satisfied,
    [PreconditionCheck, ...])`; callers that only need the boolean still get the full list, which
    `executor.py` writes into the journal's `precondition_failure` on halt."""
    results = [evaluate(pid, db, tenant_id, target) for pid in precondition_ids]
    return all(r.satisfied for r in results), results
