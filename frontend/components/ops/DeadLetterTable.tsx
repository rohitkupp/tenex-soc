"use client";

import { useState } from "react";
import type { DeadLetter } from "@/lib/api/types";
import { ApiError } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

interface DeadLetterTableProps {
  items: DeadLetter[] | null;
  unreachable: boolean;
  onRetry: (id: string) => Promise<void>;
}

type RowState = { status: "idle" } | { status: "retrying" } | { status: "error"; message: string };

const IDLE_ROW: RowState = { status: "idle" };

export function DeadLetterTable({ items, unreachable, onRetry }: DeadLetterTableProps) {
  const [rowState, setRowState] = useState<Record<string, RowState>>({});

  async function handleRetry(id: string) {
    setRowState((prev) => ({ ...prev, [id]: { status: "retrying" } }));
    try {
      await onRetry(id);
      // On success the item drops out of the list on the next refresh —
      // nothing to hold locally.
      setRowState((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Retry failed — try again.";
      setRowState((prev) => ({ ...prev, [id]: { status: "error", message } }));
    }
  }

  if (unreachable) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-5 py-8 text-center">
        <p className="text-sm text-[var(--color-severity-high)]">
          Could not load dead letters — the API is unreachable.
        </p>
      </div>
    );
  }

  if (!items || items.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-1)] px-5 py-8 text-center">
        <p className="text-sm text-[var(--color-text-mid)]">
          No dead letters — the pipeline is healthy.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)] text-xs text-[var(--color-text-lo)]">
            <th scope="col" className="px-4 py-2.5 font-medium">
              Queue
            </th>
            <th scope="col" className="px-4 py-2.5 font-medium">
              Error
            </th>
            <th scope="col" className="px-4 py-2.5 font-medium">
              Attempts
            </th>
            <th scope="col" className="px-4 py-2.5 font-medium">
              Failed at
            </th>
            <th scope="col" className="px-4 py-2.5 font-medium">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {items.map((item) => {
            const state = rowState[item.id] ?? IDLE_ROW;
            return (
              <tr key={item.id}>
                <td className="px-4 py-2.5 font-mono text-[var(--color-text-hi)]">
                  {item.queue}
                </td>
                <td
                  className="max-w-xs truncate px-4 py-2.5 text-[var(--color-text-mid)]"
                  title={item.error}
                >
                  {item.error}
                </td>
                <td className="px-4 py-2.5 font-mono text-[var(--color-text-hi)]">
                  {item.attempts}
                </td>
                <td className="px-4 py-2.5 text-[var(--color-text-mid)]">
                  {formatDate(item.failed_at)}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-col items-end gap-1">
                    <button
                      type="button"
                      onClick={() => handleRetry(item.id)}
                      disabled={state.status === "retrying"}
                      className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs text-[var(--color-text-mid)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)] disabled:opacity-50"
                    >
                      {state.status === "retrying" ? "Retrying…" : "Retry"}
                    </button>
                    {state.status === "error" && (
                      <span role="alert" className="text-xs text-[var(--color-severity-critical)]">
                        {state.message}
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
