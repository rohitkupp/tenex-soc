import type { StateDiffEntryOut } from "@/lib/api/types";
import { flattenForDisplay } from "@/lib/flatten";
import { Badge } from "@/components/ui/Badge";

function MiniState({ label, state }: { label: string; state: Record<string, unknown> | null }) {
  const entries = state ? flattenForDisplay(state) : [];
  return (
    <div className="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-2">
      <p className="text-[10px] uppercase tracking-wide text-[var(--color-text-lo)]">{label}</p>
      {entries.length === 0 ? (
        <p className="mt-1 text-xs text-[var(--color-text-lo)]">—</p>
      ) : (
        <dl className="mt-1 flex flex-col gap-0.5">
          {entries.map((e, i) => (
            <div key={i} className="flex justify-between gap-2 text-xs">
              <dt className="text-[var(--color-text-lo)]">{e.key}</dt>
              <dd className="font-mono text-[var(--color-text-hi)]">{e.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

// After execution: state diff and containment outcome (docs/10 §Response plan).
export function StateDiff({ diff }: { diff: StateDiffEntryOut[] }) {
  if (diff.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No enforcement journal entries yet.</p>;
  }
  return (
    <div className="flex flex-col gap-3">
      {diff.map((entry, i) => (
        <div key={i} className="rounded-md border border-[var(--color-border)] p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-xs text-[var(--color-text-hi)]">{entry.action_id}</span>
            <span className="text-xs text-[var(--color-text-mid)]">
              {entry.resource_type} <span className="font-mono">{entry.resource_id}</span>
            </span>
            <Badge variant={entry.succeeded ? "neutral" : "outline"}>
              {entry.succeeded ? "succeeded" : entry.precondition_failure ? "precondition failed" : "failed"}
            </Badge>
          </div>
          {entry.precondition_failure && (
            <p className="mb-2 text-xs text-[var(--color-text-mid)]">{entry.precondition_failure}</p>
          )}
          <div className="flex flex-col gap-2 sm:flex-row">
            <MiniState label="Before" state={entry.before} />
            <MiniState label="After" state={entry.after} />
            <MiniState label="Current" state={entry.current} />
          </div>
        </div>
      ))}
    </div>
  );
}
