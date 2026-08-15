import type { QueueDepth } from "@/lib/api/types";

// Presentational only — no hooks, so no "use client" directive (matches the
// rest of this codebase's convention: the directive marks interactivity,
// not merely "rendered inside a client tree").
interface QueueDepthTableProps {
  queues: QueueDepth[] | null;
  unreachable: boolean;
}

export function QueueDepthTable({ queues, unreachable }: QueueDepthTableProps) {
  if (unreachable) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-5 py-8 text-center">
        <p className="text-sm text-[var(--color-severity-high)]">
          Could not load queue depths — the API is unreachable.
        </p>
      </div>
    );
  }

  if (!queues || queues.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-1)] px-5 py-8 text-center">
        <p className="text-sm text-[var(--color-text-mid)]">No queues reporting.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]">
      <table className="w-full min-w-[420px] text-left text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)] text-xs text-[var(--color-text-lo)]">
            <th scope="col" className="px-4 py-2.5 font-medium">
              Queue
            </th>
            {/* Depth and dead-letter counts are volumes, not severities —
                docs/10: don't colour them for drama. Neutral mono, same as
                any other count in the app. */}
            <th scope="col" className="px-4 py-2.5 font-medium">
              Depth
            </th>
            <th scope="col" className="px-4 py-2.5 font-medium">
              Consumers
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {queues.map((queue) => (
            <tr key={queue.name}>
              <td className="px-4 py-2.5 font-mono text-[var(--color-text-hi)]">{queue.name}</td>
              <td className="px-4 py-2.5 font-mono text-[var(--color-text-hi)]">
                {queue.depth.toLocaleString("en-US")}
              </td>
              <td className="px-4 py-2.5 font-mono text-[var(--color-text-mid)]">
                {queue.consumers ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
