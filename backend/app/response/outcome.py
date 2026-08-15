"""Outcome verification — docs/08 "Outcome verification — loop closure".

> After execution, re-run detection against post-remediation state and re-evaluate the
> incident's signals: contained (all resolve) / partially_contained (some) / failed (none
> resolve, or the plan halted).

This build's `detection/**` runs Sigma rules, signal processors, and ML models over immutable
historical log events (docs/04) — remediation targets Okta/proxy/host state, not those events, so
literally re-running the detection pipeline would reproduce byte-identical signals regardless of
what the response plan did. "Re-evaluating the incident's signals" is implemented here as a
direct, per-signal check of whether the enforcement control that would neutralize *that signal's
entity* has actually been applied — e.g. a `signal.beaconing` signal on `entity_type="domain"` is
"resolved" exactly when `block_domain_at_proxy` (or any action that ends up blocking that domain)
has landed in `enforcement_state`. This is the real re-evaluation the loop needs (it reads live
post-execution state, not a cached verdict) while staying honest that it is not literally
replaying the ML/rule pipeline. See `_resolve_signal` for the full entity_type -> control mapping
and the one documented assumption it rests on (`src_ip` -> `host`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.response_plan import ResponsePlan
from app.models.signal import Signal
from app.response import state as enforcement_state

OUTCOME_CONTAINED = "contained"
OUTCOME_PARTIALLY_CONTAINED = "partially_contained"
OUTCOME_FAILED = "failed"


@dataclass(frozen=True)
class SignalResolution:
    signal_id: int
    entity_type: str
    entity_value: str
    resolved: bool
    reason: str


@dataclass(frozen=True)
class OutcomeResult:
    outcome: str
    resolutions: list[SignalResolution]


def fetch_incident_signals(db: Session, incident: Incident) -> list[Signal]:
    """`Signal` rows for `incident.signal_ids` (docs/02: `incidents.signal_ids BIGINT[]`), in a
    stable order. Relies on the caller's session already being tenant-scoped, same as every
    other `Signal` query in this codebase."""
    if not incident.signal_ids:
        return []
    rows = (
        db.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)).order_by(Signal.id))
        .scalars()
        .all()
    )
    return list(rows)


def _resolve_signal(db: Session, tenant_id: uuid.UUID, signal: Signal) -> SignalResolution:
    entity_type = signal.entity_type
    entity_value = signal.entity_value

    if entity_type == "user":
        row = enforcement_state.read_state(
            db, tenant_id, enforcement_state.RESOURCE_OKTA_SESSION, entity_value
        )
        if row is None:
            return SignalResolution(
                signal.id, entity_type, entity_value, False, "user was never targeted by the plan"
            )
        sessions_cleared = not any(s.get("active") for s in row.get("sessions", []))
        contained = (
            sessions_cleared
            or row.get("credential_reset_required") is True
            or row.get("account_status") == "suspended"
        )
        reason = (
            "sessions revoked, credentials reset, or account suspended"
            if contained
            else "user's Okta identity is unchanged — sessions still active"
        )
        return SignalResolution(signal.id, entity_type, entity_value, contained, reason)

    if entity_type in ("domain", "dst_ip"):
        row = enforcement_state.read_state(
            db, tenant_id, enforcement_state.RESOURCE_PROXY_POLICY, entity_value
        )
        blocked = bool(row and row.get("blocked"))
        reason = "blocked at the proxy" if blocked else "not blocked at the proxy"
        return SignalResolution(signal.id, entity_type, entity_value, blocked, reason)

    if entity_type == "src_ip":
        # Documented assumption: ZScaler proxy logs identify the internal client by src_ip, and
        # that is the identifier `isolate_host` keys its `host` resource on in this simulated
        # plane — see app.response.state's module docstring for the wider resource-typing
        # rationale. A src_ip-keyed signal is therefore resolved by isolating that host.
        row = enforcement_state.read_state(
            db, tenant_id, enforcement_state.RESOURCE_HOST, entity_value
        )
        isolated = bool(row and row.get("isolated"))
        reason = "host isolated from the network" if isolated else "host is still on the network"
        return SignalResolution(signal.id, entity_type, entity_value, isolated, reason)

    return SignalResolution(
        signal.id,
        entity_type,
        entity_value,
        False,
        f"entity_type {entity_type!r} has no corresponding control in the response action catalog",
    )


def evaluate_outcome(
    db: Session, tenant_id: uuid.UUID, signals: list[Signal], *, halted: bool
) -> OutcomeResult:
    """Re-evaluate every signal on the incident against current `enforcement_state` and roll the
    per-signal resolutions up into docs/08's three-value outcome."""
    resolutions = [_resolve_signal(db, tenant_id, s) for s in signals]
    resolved_count = sum(1 for r in resolutions if r.resolved)
    total = len(resolutions)

    if halted:
        # docs/08's table reads "failed: none resolve, *or* the plan halted" — a plan that did
        # not finish is failed outright, even if steps that did run happened to resolve a signal
        # along the way. The per-signal detail below still records that honestly; only the
        # top-level rollup is forced to `failed`.
        outcome = OUTCOME_FAILED
    elif total == 0 or resolved_count == total:
        outcome = OUTCOME_CONTAINED
    elif resolved_count > 0:
        outcome = OUTCOME_PARTIALLY_CONTAINED
    else:
        outcome = OUTCOME_FAILED

    return OutcomeResult(outcome=outcome, resolutions=resolutions)


def outcome_detail(result: OutcomeResult) -> dict[str, Any]:
    """The `response_plans.outcome_detail` JSONB payload — per-signal resolution, so the UI (and
    this milestone's verification report) can show exactly which signals contained and which
    didn't, not just the rollup label."""
    return {
        "resolved_count": sum(1 for r in result.resolutions if r.resolved),
        "total_count": len(result.resolutions),
        "signals": [
            {
                "signal_id": r.signal_id,
                "entity_type": r.entity_type,
                "entity_value": r.entity_value,
                "resolved": r.resolved,
                "reason": r.reason,
            }
            for r in result.resolutions
        ],
    }


def containment_rate(db: Session, tenant_id: uuid.UUID) -> dict[str, Any]:
    """Autonomous containment rate — docs/08's headline metric: "share of incidents fully
    contained after plan execution." Counts every `response_plans` row that has been executed
    (`outcome IS NOT NULL`) for this tenant. `response_plans` carries no `tenant_id` column
    itself (docs/02 — isolation is transitive through `incident_id`), so this joins through
    `incidents` and filters explicitly, as defense-in-depth on top of (not a substitute for) the
    caller passing a session already bound via `tenant_scope`/`tenant_session` — `Incident` is
    still `TenantScopedMixin`, so the structural guard (`app.models.base`) fires on this query
    the same as any other, and refuses to run at all on a session with no tenant bound."""
    rows = (
        db.execute(
            select(ResponsePlan.outcome)
            .join(Incident, ResponsePlan.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id, ResponsePlan.outcome.is_not(None))
        )
        .scalars()
        .all()
    )
    total = len(rows)
    contained = sum(1 for o in rows if o == OUTCOME_CONTAINED)
    return {"contained": contained, "total": total, "rate": (contained / total) if total else None}
