"""`GET /api/incidents/{id}/plan`, `POST /api/plans/{id}/approve`, `POST /api/plans/{id}/rollback`,
`GET /api/plans/{id}/state-diff` — docs/09's "Response plans" section, docs/08 Part 1 end to end.

**Tenant scoping.** `response_plans` (and `triage_verdicts`, `enforcement_journal`) carry no
`tenant_id` column (docs/02 — isolation is transitive through `incident_id` -> `incidents`, a
`TenantScopedMixin` table). Every lookup here therefore either starts from `Incident` directly
(the `GET .../plan` route) or joins through it (`_load_plan_or_404`, used by the other three) so
the structural tenant guard (`app.models.base`) applies transitively — a plan id from another
tenant's incident 404s exactly like one that doesn't exist, never a cross-tenant leak.

**Approval is the only state-mutating action in the product** (docs/09) — `POST .../approve`
requires the explicit `{"confirm": true}` body so a bare click/retry can never execute a plan by
accident. Both POSTs ride the same CSRF defense as every other mutating route in this app
(`app.core.csrf`, wired in `app.main`); nothing route-specific is needed here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.models.base import tenant_scope
from app.models.enforcement_journal import EnforcementJournal
from app.models.incident import Incident
from app.models.response_plan import ResponsePlan
from app.models.triage_verdict import TriageVerdict
from app.response import executor, outcome, preconditions, verification
from app.response import state as enforcement_state
from app.response.planner import (
    InvalidRecommendationError,
    PlanCycleError,
    PlanStep,
    UnknownActionError,
    derive_plan,
)
from app.schemas.plans import (
    ApproveRequest,
    ApproveResponse,
    JournalEntryOut,
    PlanOut,
    PlanStepOut,
    PreconditionCheckOut,
    RestoredResourceOut,
    RollbackResponse,
    StateDiffEntryOut,
    StateDiffResponse,
)

router = APIRouter()

_EXECUTABLE_STATUSES = {"approved", "halted"}


def _not_found(detail: str) -> ApiError:
    return ApiError(status_code=404, code="not_found", detail=detail)


def _incident_not_found() -> ApiError:
    return _not_found("Incident not found.")


def _plan_not_found() -> ApiError:
    return _not_found("Response plan not found.")


def _journal_entry_out(row: EnforcementJournal) -> JournalEntryOut:
    return JournalEntryOut(
        id=row.id,
        action_id=row.action_id,
        before_state=row.before_state,
        after_state=row.after_state,
        succeeded=row.succeeded,
        precondition_failure=row.precondition_failure,
        executed_at=row.executed_at,
    )


def _plan_step_out(db: Session, tenant_id: uuid.UUID, action: dict[str, Any]) -> PlanStepOut:
    precondition_ids = tuple(action["preconditions"])
    _all_ok, checks = preconditions.check_preconditions(
        db, tenant_id, action["action_id"], action["target"], precondition_ids=precondition_ids
    )
    return PlanStepOut(
        step=action["step"],
        action_id=action["action_id"],
        name=action["name"],
        target=action["target"],
        target_type=action["target_type"],
        preconditions=list(action["preconditions"]),
        blast_radius=action["blast_radius"],
        reversible=action["reversible"],
        rollback=action["rollback"],
        rollback_available=action["rollback_available"],
        depends_on=list(action["depends_on"]),
        mitre_mitigation=action["mitre_mitigation"],
        rationale=action.get("rationale"),
        implied=action["implied"],
        live_preconditions=[
            PreconditionCheckOut(id=c.id, satisfied=c.satisfied, reason=c.reason) for c in checks
        ],
    )


def _plan_out(db: Session, tenant_id: uuid.UUID, plan: ResponsePlan) -> PlanOut:
    return PlanOut(
        id=plan.id,
        incident_id=plan.incident_id,
        status=plan.status,
        actions=[_plan_step_out(db, tenant_id, action) for action in plan.actions],
        verification=plan.verification,
        approved_by=plan.approved_by,
        approved_at=plan.approved_at,
        execution_log=plan.execution_log,
        outcome=plan.outcome,
        outcome_detail=plan.outcome_detail,
    )


def _derive_and_persist_plan(db: Session, incident: Incident) -> ResponsePlan:
    verdict = db.execute(
        select(TriageVerdict)
        .where(TriageVerdict.incident_id == incident.id)
        .order_by(TriageVerdict.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if verdict is None:
        raise ApiError(
            status_code=409,
            code="no_verdict",
            detail="Incident has no triage verdict yet; a response plan cannot be derived.",
        )

    try:
        steps: list[PlanStep] = derive_plan(verdict.recommended_actions)
    except (UnknownActionError, InvalidRecommendationError) as exc:
        raise ApiError(status_code=422, code="invalid_recommended_action", detail=str(exc)) from exc
    except PlanCycleError as exc:
        # A cycle can only come from a broken action catalog (docs/08: "a config bug"), never
        # from the agent's output — a loud 500 with the offending cycle in `detail`, not a 4xx
        # that would imply the client did something wrong.
        raise ApiError(status_code=500, code="plan_cycle_error", detail=str(exc)) from exc

    for step in steps:
        enforcement_state.seed_for_step(db, incident.tenant_id, step.action_id, step.target)

    enforcement_snapshot = []
    for step in steps:
        resource_type, resource_id = enforcement_state.resolve_primary_resource(
            step.action_id, step.target
        )
        enforcement_snapshot.append(
            {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "state": enforcement_state.read_state(
                    db, incident.tenant_id, resource_type, resource_id
                ),
            }
        )

    verification_result = verification.run_llm_verification(
        plan_steps=[s.model_dump(mode="json") for s in steps],
        incident_summary=verdict.summary,
        enforcement_snapshot=enforcement_snapshot,
        settings=get_settings(),
    )

    plan = ResponsePlan(
        incident_id=incident.id,
        actions=[s.model_dump(mode="json") for s in steps],
        verification=verification_result,
        status="pending_approval",
        execution_log=[],
    )
    db.add(plan)
    db.flush()
    return plan


@router.get("/incidents/{incident_id}/plan", response_model=PlanOut)
def get_plan(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> PlanOut:
    with tenant_scope(db, current.tenant.id):
        incident = db.execute(
            select(Incident).where(Incident.id == incident_id)
        ).scalar_one_or_none()
        if incident is None:
            raise _incident_not_found()

        plan = db.execute(
            select(ResponsePlan).where(ResponsePlan.incident_id == incident_id).limit(1)
        ).scalar_one_or_none()
        if plan is None:
            plan = _derive_and_persist_plan(db, incident)

        return _plan_out(db, incident.tenant_id, plan)


def _load_plan_or_404(db: Session, plan_id: uuid.UUID) -> tuple[ResponsePlan, Incident]:
    """`response_plans` join `incidents` — see module docstring for why this, not `db.get`, is
    the tenant-safe way to look up a plan by its own id."""
    row = db.execute(
        select(ResponsePlan, Incident)
        .join(Incident, ResponsePlan.incident_id == Incident.id)
        .where(ResponsePlan.id == plan_id)
    ).one_or_none()
    if row is None:
        raise _plan_not_found()
    plan, incident = row
    return plan, incident


@router.post("/plans/{plan_id}/approve", response_model=ApproveResponse)
def approve_plan(
    plan_id: uuid.UUID,
    body: ApproveRequest,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> ApproveResponse:
    if not body.confirm:
        raise ApiError(
            status_code=400,
            code="confirmation_required",
            detail="Approving a plan requires an explicit {'confirm': true}.",
        )

    with tenant_scope(db, current.tenant.id):
        plan, incident = _load_plan_or_404(db, plan_id)
        if plan.status != "pending_approval":
            raise ApiError(
                status_code=409,
                code="invalid_status",
                detail=f"Plan {plan_id} is {plan.status!r}, not pending_approval.",
            )

        steps = [PlanStep.model_validate(action) for action in plan.actions]
        result = executor.execute_plan(db, incident.tenant_id, plan.id, steps)

        plan.execution_log = [
            _journal_entry_out(row).model_dump(mode="json") for row in result.journal
        ]
        plan.status = "halted" if result.halted else "approved"
        plan.approved_by = current.user.id
        plan.approved_at = datetime.now(UTC)

        signals = outcome.fetch_incident_signals(db, incident)
        outcome_result = outcome.evaluate_outcome(
            db, incident.tenant_id, signals, halted=result.halted
        )
        plan.outcome = outcome_result.outcome
        plan.outcome_detail = outcome.outcome_detail(outcome_result)
        db.add(plan)
        db.flush()

        return ApproveResponse(
            plan_id=plan.id,
            status=plan.status,
            halted=result.halted,
            journal=[_journal_entry_out(row) for row in result.journal],
            outcome=plan.outcome,
            outcome_detail=plan.outcome_detail,
        )


@router.post("/plans/{plan_id}/rollback", response_model=RollbackResponse)
def rollback_plan(
    plan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> RollbackResponse:
    with tenant_scope(db, current.tenant.id):
        plan, incident = _load_plan_or_404(db, plan_id)
        if plan.status not in _EXECUTABLE_STATUSES:
            raise ApiError(
                status_code=409,
                code="invalid_status",
                detail=f"Plan {plan_id} is {plan.status!r}; nothing to roll back.",
            )

        rows = executor.rollback_plan(db, incident.tenant_id, plan.id, plan.actions)

        restored = []
        for row, action in zip(rows, plan.actions[: len(rows)], strict=True):
            resource_type, resource_id = enforcement_state.resolve_primary_resource(
                row.action_id, action["target"]
            )
            restored.append(
                RestoredResourceOut(
                    action_id=row.action_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    restored_state=row.before_state or {},
                )
            )

        plan.status = "rolled_back"
        db.add(plan)
        db.flush()

        return RollbackResponse(plan_id=plan.id, status=plan.status, restored=restored)


@router.get("/plans/{plan_id}/state-diff", response_model=StateDiffResponse)
def get_state_diff(
    plan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> StateDiffResponse:
    with tenant_scope(db, current.tenant.id):
        plan, incident = _load_plan_or_404(db, plan_id)

        journal_rows = (
            db.execute(
                select(EnforcementJournal)
                .where(EnforcementJournal.plan_id == plan.id)
                .order_by(EnforcementJournal.id.asc())
            )
            .scalars()
            .all()
        )

        diff = []
        for row, action in zip(journal_rows, plan.actions[: len(journal_rows)], strict=True):
            resource_type, resource_id = enforcement_state.resolve_primary_resource(
                row.action_id, action["target"]
            )
            current_state = enforcement_state.read_state(
                db, incident.tenant_id, resource_type, resource_id
            )
            diff.append(
                StateDiffEntryOut(
                    step=action.get("step"),
                    action_id=row.action_id,
                    target=action["target"],
                    resource_type=resource_type,
                    resource_id=resource_id,
                    before=row.before_state,
                    after=row.after_state,
                    current=current_state,
                    succeeded=row.succeeded,
                    precondition_failure=row.precondition_failure,
                    executed_at=row.executed_at,
                )
            )

        return StateDiffResponse(plan_id=plan.id, status=plan.status, diff=diff)
