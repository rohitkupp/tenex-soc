"use client";

/**
 * 8. Response plan — docs/10: "ordered steps with preconditions, blast-radius warnings,
 * verification result, approve button. After execution: state diff and containment outcome."
 * Approval is the only state-mutating action in the product (docs/09) — the button below
 * requires a second, explicit confirm click before the `{confirm: true}` POST fires, so the
 * API's own confirmation requirement has a UI-level "no accidental clicks" counterpart, not
 * just a payload the button always sends.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { ApproveResponse, PlanOut, PlanStepOut, RollbackResponse, StateDiffResponse } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { StateDiff } from "./StateDiff";

const EXECUTABLE = new Set(["approved", "halted"]);

function readVerification(verification: Record<string, unknown>) {
  return {
    approved: typeof verification.approved === "boolean" ? verification.approved : null,
    concerns: Array.isArray(verification.concerns) ? (verification.concerns as string[]) : [],
    suggestedReordering: Array.isArray(verification.suggested_reordering)
      ? (verification.suggested_reordering as string[])
      : [],
    escalate:
      typeof verification.escalate_to_human === "boolean" ? verification.escalate_to_human : false,
  };
}

function PlanStep({ step }: { step: PlanStepOut }) {
  return (
    <li className="rounded-md border border-[var(--color-border)] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm text-[var(--color-text-hi)]">
          {step.step}. {step.name}
        </span>
        <div className="flex items-center gap-1.5">
          {step.blast_radius === "org" && <Badge>blast radius: org-wide</Badge>}
          {step.blast_radius !== "org" && <Badge variant="outline">blast radius: {step.blast_radius}</Badge>}
          {!step.reversible && <Badge variant="outline">irreversible</Badge>}
          {step.implied && <Badge variant="outline">implied dependency</Badge>}
        </div>
      </div>
      <p className="mt-1 text-xs text-[var(--color-text-mid)]">
        {step.target_type} <span className="font-mono text-[var(--color-text-hi)]">{step.target}</span> · mitigates{" "}
        <span className="font-mono">{step.mitre_mitigation}</span>
      </p>
      {step.rationale && <p className="mt-1 text-xs text-[var(--color-text-mid)]">{step.rationale}</p>}
      {step.live_preconditions.length > 0 && (
        <ul className="mt-2 flex flex-col gap-1">
          {step.live_preconditions.map((p) => (
            <li key={p.id} className="flex items-start gap-2 text-xs">
              <span
                aria-hidden="true"
                style={{ color: p.satisfied ? "var(--color-accent-verified)" : "var(--color-severity-high)" }}
              >
                {p.satisfied ? "✓" : "✗"}
              </span>
              <span className="text-[var(--color-text-mid)]">
                {p.id} — {p.reason}
              </span>
            </li>
          ))}
        </ul>
      )}
      {step.depends_on.length > 0 && (
        <p className="mt-2 text-xs text-[var(--color-text-lo)]">depends on {step.depends_on.join(", ")}</p>
      )}
    </li>
  );
}

export function ResponsePlanStepper({ initialPlan }: { initialPlan: PlanOut | null }) {
  const [plan, setPlan] = useState(initialPlan);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [stateDiff, setStateDiff] = useState<StateDiffResponse | null>(null);

  if (!plan) {
    return <p className="text-sm text-[var(--color-text-mid)]">No response plan yet — this incident has not been triaged.</p>;
  }

  const verification = readVerification(plan.verification);
  const orgWide = plan.actions.some((a) => a.blast_radius === "org");

  async function approve() {
    if (!plan) return;
    if (!confirming) {
      setConfirming(true);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch<ApproveResponse>(`/api/plans/${plan.id}/approve`, {
        method: "POST",
        body: JSON.stringify({ confirm: true }),
      });
      setPlan({ ...plan, status: res.status, outcome: res.outcome, outcome_detail: res.outcome_detail });
      setStatusMessage(res.halted ? "Plan halted on a failing precondition." : "Plan approved and executed.");
      setConfirming(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  async function rollback() {
    if (!plan) return;
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch<RollbackResponse>(`/api/plans/${plan.id}/rollback`, { method: "POST" });
      setPlan({ ...plan, status: res.status });
      setStatusMessage(`Rolled back ${res.restored.length} resource${res.restored.length === 1 ? "" : "s"}.`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  async function viewStateDiff() {
    if (!plan) return;
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch<StateDiffResponse>(`/api/plans/${plan.id}/state-diff`);
      setStateDiff(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{plan.status.replace(/_/g, " ")}</Badge>
        {plan.outcome && <Badge>{plan.outcome.replace(/_/g, " ")}</Badge>}
        {verification.approved !== null && (
          <Badge variant={verification.approved ? "neutral" : "outline"}>
            verification: {verification.approved ? "approved" : "not approved"}
          </Badge>
        )}
      </div>

      {verification.escalate && (
        <p role="alert" className="rounded-md border border-[var(--color-severity-high)] p-3 text-xs text-[var(--color-severity-high)]">
          The verification pass flagged this plan for human review before approval.
        </p>
      )}
      {orgWide && (
        <p className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-xs text-[var(--color-text-hi)]">
          One or more steps affect every user in the tenant (org-wide blast radius) — reviewed this closely.
        </p>
      )}
      {(verification.concerns.length > 0 || verification.suggestedReordering.length > 0) && (
        <div className="text-xs text-[var(--color-text-mid)]">
          {verification.concerns.length > 0 && (
            <p>Concerns: {verification.concerns.join("; ")}</p>
          )}
          {verification.suggestedReordering.length > 0 && (
            <p>Suggested reordering: {verification.suggestedReordering.join(" → ")}</p>
          )}
        </div>
      )}

      <ol className="flex flex-col gap-2">
        {plan.actions.map((step) => (
          <PlanStep key={step.action_id} step={step} />
        ))}
      </ol>

      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}
      {statusMessage && <p className="text-xs text-[var(--color-text-mid)]">{statusMessage}</p>}

      <div className="flex flex-wrap items-center gap-2">
        {plan.status === "pending_approval" && (
          <>
            <button
              type="button"
              onClick={approve}
              disabled={busy}
              className="rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {confirming ? "Confirm approval" : "Approve plan"}
            </button>
            {confirming && (
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="text-sm text-[var(--color-text-mid)] hover:text-[var(--color-text-hi)]"
              >
                Cancel
              </button>
            )}
          </>
        )}
        {EXECUTABLE.has(plan.status) && (
          <button
            type="button"
            onClick={rollback}
            disabled={busy}
            className="rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
          >
            Roll back
          </button>
        )}
        <button
          type="button"
          onClick={viewStateDiff}
          disabled={busy}
          className="rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
        >
          View state diff
        </button>
      </div>

      {stateDiff && <StateDiff diff={stateDiff.diff} />}
    </div>
  );
}
