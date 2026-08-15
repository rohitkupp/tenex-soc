"use client";

/**
 * docs/10 /learning: "pending suppressions." docs/08: "Never auto-apply — analyst review is
 * the gate." Accepting here is that gate: `POST /api/learning/suppressions/{id}/accept`.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { SuppressionAcceptResponse, SuppressionCandidateOut } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";

export function SuppressionsList({ candidates: items }: { candidates: SuppressionCandidateOut[] }) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [written, setWritten] = useState<Record<string, string>>({});

  async function accept(id: string) {
    setBusyId(id);
    setError(null);
    try {
      const res = await apiFetch<SuppressionAcceptResponse>(`/api/learning/suppressions/${id}/accept`, {
        method: "POST",
      });
      setWritten((prev) => ({ ...prev, [id]: res.written_path }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusyId(null);
    }
  }

  if (items.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No pending suppression candidates.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}
      {items.map((c) => (
        <div key={c.id} className="rounded-md border border-[var(--color-border)] p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-xs text-[var(--color-text-hi)]">{c.detector_key}</span>
            <div className="flex items-center gap-2">
              {c.synthetic && <Badge variant="outline">seeded</Badge>}
              {written[c.id] ? (
                <Badge>written to {written[c.id]}</Badge>
              ) : (
                <button
                  type="button"
                  disabled={busyId === c.id}
                  onClick={() => void accept(c.id)}
                  className="rounded-md bg-[var(--color-text-hi)] px-3 py-1 text-xs font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
                >
                  {busyId === c.id ? "Accepting…" : "Accept"}
                </button>
              )}
            </div>
          </div>
          <p className="mt-1 text-xs text-[var(--color-text-mid)]">
            {c.entity_type} <span className="font-mono">{c.entity_value}</span> — {c.reason}
          </p>
          <details className="mt-2">
            <summary className="cursor-pointer text-xs text-[var(--color-text-lo)]">Rule YAML</summary>
            <pre className="mt-1 overflow-x-auto rounded bg-[var(--color-surface-0)] p-2 font-mono text-xs text-[var(--color-text-hi)]">
              {c.rule_yaml}
            </pre>
          </details>
        </div>
      ))}
    </div>
  );
}
