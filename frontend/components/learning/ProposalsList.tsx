"use client";

/**
 * docs/10 /learning section 6: "what your feedback changed" — docs/v2_migration change 21's
 * gated-mechanism review queue (6, 7, 8, 10, 11, 12, 14, 15). Accept runs the mechanism's own
 * golden-set (or support) gate and, on pass, applies the change for real; Reject declines without
 * running it. Both land on `STATUS_REJECTED`/`STATUS_APPROVED` and keep the row — "keep the
 * rejection history" (change 21) is a property of the backend, not this component, but the
 * before/after metric delta rendered here is exactly that evidence.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { LearningProposalDecisionResponse, LearningProposalOut } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";

function summarizePayload(payload: Record<string, unknown>): string {
  const entries = Object.entries(payload).filter(([k]) => k !== "windows" && k !== "assignments");
  return entries
    .slice(0, 4)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export function ProposalsList({ proposals }: { proposals: LearningProposalOut[] }) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<Record<string, LearningProposalDecisionResponse>>({});

  async function decide(id: string, action: "accept" | "reject") {
    setBusyId(id);
    setError(null);
    try {
      const res = await apiFetch<LearningProposalDecisionResponse>(
        `/api/learning/proposals/${id}/${action}`,
        { method: "POST" },
      );
      setDecisions((prev) => ({ ...prev, [id]: res }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusyId(null);
    }
  }

  if (proposals.length === 0) {
    return (
      <p className="text-sm text-[var(--color-text-mid)]">
        No proposals awaiting review — a gated mechanism (6, 7, 8, 10, 11, 12, 14, 15) will stage
        one here once enough feedback accumulates.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}
      {proposals.map((p) => {
        const decision = decisions[p.id];
        return (
          <div key={p.id} className="rounded-md border border-[var(--color-border)] p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs text-[var(--color-text-hi)]">
                #{p.mechanism} {p.mechanism_name}
              </span>
              {decision ? (
                <Badge variant={decision.passed ? undefined : "outline"}>
                  {decision.passed ? "approved" : "rejected — gate did not pass"}
                </Badge>
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busyId === p.id}
                    onClick={() => void decide(p.id, "reject")}
                    className="rounded-md border border-[var(--color-border)] px-3 py-1 text-xs text-[var(--color-text-hi)] hover:bg-[var(--color-surface-2)] disabled:opacity-50"
                  >
                    Reject
                  </button>
                  <button
                    type="button"
                    disabled={busyId === p.id}
                    onClick={() => void decide(p.id, "accept")}
                    className="rounded-md bg-[var(--color-text-hi)] px-3 py-1 text-xs font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
                  >
                    {busyId === p.id ? "Deciding…" : "Accept"}
                  </button>
                </div>
              )}
            </div>
            <p className="mt-1 text-xs text-[var(--color-text-mid)]">{summarizePayload(p.payload)}</p>
            {decision && (
              <p className="mt-1 text-xs text-[var(--color-text-lo)]">
                {decision.reason ||
                  (decision.passed
                    ? "Applied — see the learning events feed above for the resulting state change."
                    : "No metric regression detected; declined by analyst review.")}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
