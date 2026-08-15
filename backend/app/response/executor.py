"""The enforcement plane's execution engine — docs/08 "Simulated enforcement plane", the
`execute_plan`/rollback pair. This is the module CLAUDE.md's "do not mock what should be real"
rule is about: the *resources* in `enforcement_state` are simulated, but every line below —
reading state, checking preconditions against it, applying effects, journaling, halting, and
reversing — runs for real against the live Postgres row, with no shortcuts for tests.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enforcement_journal import EnforcementJournal
from app.response import effects as effects_module
from app.response import state as enforcement_state
from app.response.planner import PlanStep
from app.response.preconditions import check_preconditions


@dataclass(frozen=True)
class ExecutionResult:
    journal: list[EnforcementJournal]
    halted: bool
    halted_step: int | None


def execute_plan(
    db: Session, tenant_id: uuid.UUID, plan_id: uuid.UUID, steps: list[PlanStep]
) -> ExecutionResult:
    """docs/08's executor loop, implemented verbatim:

        for action in plan.actions:
            before = read_state(action.target)
            if not check_preconditions(action, before):
                journal(action, failed, precondition_failure=...)
                halt()                      # plan stops; partial execution is recorded honestly
            after = apply_effects(action, before)
            journal(action, before, after, succeeded=True)

    Each resource is seeded on first touch (`state.seed_for_step`, idempotent) so this function
    is self-sufficient — callable directly in a test without going through the API layer's own
    seeding step first. Runs inside the caller's transaction; `db.flush()` after each journal row
    materializes `EnforcementJournal.id`/`executed_at` (insertion order is later relied on by
    `rollback_plan`) but the caller is responsible for `db.commit()`.
    """
    journal_rows: list[EnforcementJournal] = []
    halted = False
    halted_step: int | None = None

    for step in steps:
        enforcement_state.seed_for_step(db, tenant_id, step.action_id, step.target)
        resource_type, resource_id = enforcement_state.resolve_primary_resource(
            step.action_id, step.target
        )
        before = enforcement_state.read_state(db, tenant_id, resource_type, resource_id)

        ok, checks = check_preconditions(
            db, tenant_id, step.action_id, step.target, precondition_ids=step.preconditions
        )
        if not ok:
            failure_reason = "; ".join(f"{c.id}: {c.reason}" for c in checks if not c.satisfied)
            entry = EnforcementJournal(
                plan_id=plan_id,
                action_id=step.action_id,
                before_state=before,
                after_state=None,
                succeeded=False,
                precondition_failure=failure_reason,
            )
            db.add(entry)
            db.flush()
            journal_rows.append(entry)
            halted = True
            halted_step = step.step
            break

        after = effects_module.apply_effects(step.action_id, step.target, before or {})
        enforcement_state.write_state(db, tenant_id, resource_type, resource_id, after)
        entry = EnforcementJournal(
            plan_id=plan_id,
            action_id=step.action_id,
            before_state=before,
            after_state=after,
            succeeded=True,
            precondition_failure=None,
        )
        db.add(entry)
        db.flush()
        journal_rows.append(entry)

    return ExecutionResult(journal=journal_rows, halted=halted, halted_step=halted_step)


def rollback_plan(
    db: Session, tenant_id: uuid.UUID, plan_id: uuid.UUID, plan_actions: list[dict[str, Any]]
) -> list[EnforcementJournal]:
    """Reverse-iterates `enforcement_journal` for this plan, restoring `before_state` for every
    action that actually succeeded — a halted action's journal row has `after_state=None` (it
    never mutated anything), so there is nothing to undo for it. docs/08: "Rollback reverse-
    iterates enforcement_journal restoring before_state" — implemented literally: every succeeded
    row's `before_state` is written back byte-for-byte, regardless of the catalog's
    `reversible`/`rollback` fields. Those fields describe *real-world* reversibility (a revoked
    session genuinely requires re-authentication in production and would not cleanly undo there)
    — this simulated plane can always be replayed backward from the journal, which is what makes
    "rollback restores exactly" checkable at all.

    **Recovering which resource each row touched.** `enforcement_journal` has no
    resource_type/resource_id column (docs/02, matched exactly) — only `action_id`. Journal rows
    are inserted by `execute_plan` in strict step order and stop at the first failure, so the
    n-th succeeded row corresponds positionally to the n-th entry of `plan_actions` (the ordered
    list persisted on `response_plans.actions`). Zipping succeeded rows (ordered by `id ASC`,
    i.e. insertion order) against `plan_actions` recovers each row's `target`, from which
    `resolve_primary_resource` recovers `(resource_type, resource_id)` the same way
    `execute_plan` did. `action_id` is cross-checked at each position as a guard against the
    journal and the persisted plan ever silently drifting out of sync.
    """
    rows = list(
        db.execute(
            select(EnforcementJournal)
            .where(EnforcementJournal.plan_id == plan_id, EnforcementJournal.succeeded.is_(True))
            .order_by(EnforcementJournal.id.asc())
        )
        .scalars()
        .all()
    )
    if len(rows) > len(plan_actions):
        raise ValueError(
            f"plan {plan_id} has {len(rows)} succeeded journal rows but only "
            f"{len(plan_actions)} planned actions — journal/plan are out of sync"
        )

    paired = list(zip(rows, plan_actions[: len(rows)], strict=True))
    for row, action in paired:
        if row.action_id != action["action_id"]:
            raise ValueError(
                f"journal row {row.id} action_id={row.action_id!r} does not match plan "
                f"position's action_id={action['action_id']!r} — journal/plan are out of sync"
            )

    for row, action in reversed(paired):
        resource_type, resource_id = enforcement_state.resolve_primary_resource(
            row.action_id, action["target"]
        )
        enforcement_state.write_state(
            db, tenant_id, resource_type, resource_id, row.before_state or {}
        )

    return list(rows)
