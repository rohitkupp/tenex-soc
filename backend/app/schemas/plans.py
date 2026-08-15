"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's "Response plans" section."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class PreconditionCheckOut(BaseModel):
    id: str
    satisfied: bool
    reason: str


class PlanStepOut(BaseModel):
    step: int
    action_id: str
    name: str
    target: str
    target_type: str
    preconditions: list[str]
    blast_radius: str
    reversible: bool
    rollback: str | None
    rollback_available: bool
    depends_on: list[str]
    mitre_mitigation: str
    rationale: str | None
    implied: bool
    live_preconditions: list[PreconditionCheckOut]
    """Precondition status evaluated fresh against current `enforcement_state` at request time
    — never persisted, so it can never go stale the way a cached value could. See
    `app.response.preconditions.check_preconditions`, the same function the executor uses as
    the real gate on approval."""


class PlanOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    actions: list[PlanStepOut]
    verification: dict[str, Any]
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    execution_log: list[dict[str, Any]]
    outcome: str | None
    outcome_detail: dict[str, Any] | None


class ApproveRequest(BaseModel):
    confirm: bool


class JournalEntryOut(BaseModel):
    id: int
    action_id: str
    before_state: dict[str, Any] | None
    after_state: dict[str, Any] | None
    succeeded: bool
    precondition_failure: str | None
    executed_at: datetime


class ApproveResponse(BaseModel):
    plan_id: uuid.UUID
    status: str
    halted: bool
    journal: list[JournalEntryOut]
    outcome: str | None
    outcome_detail: dict[str, Any] | None


class RestoredResourceOut(BaseModel):
    action_id: str
    resource_type: str
    resource_id: str
    restored_state: dict[str, Any]


class RollbackResponse(BaseModel):
    plan_id: uuid.UUID
    status: str
    restored: list[RestoredResourceOut]


class StateDiffEntryOut(BaseModel):
    step: int | None
    action_id: str
    target: str
    resource_type: str
    resource_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    current: dict[str, Any] | None
    succeeded: bool
    precondition_failure: str | None
    executed_at: datetime


class StateDiffResponse(BaseModel):
    plan_id: uuid.UUID
    status: str
    diff: list[StateDiffEntryOut]
