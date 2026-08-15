import type { ModelVersionOut } from "@/lib/api/types";
import { formatDate } from "@/lib/format";
import { flattenForDisplay } from "@/lib/flatten";
import { Badge } from "@/components/ui/Badge";

// docs/10: "version history with the eval scores that gated each promotion." docs/08's
// retrain gate: "Record every attempt, promoted or not — the rejection history is the
// evidence the gate works" — every row here is real, including rejected candidates.
export function VersionHistoryTable({ versions }: { versions: ModelVersionOut[] }) {
  if (versions.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No trained model versions recorded yet.</p>;
  }

  const byModel = new Map<string, ModelVersionOut[]>();
  for (const v of versions) {
    const list = byModel.get(v.model_key) ?? [];
    list.push(v);
    byModel.set(v.model_key, list);
  }

  return (
    <div className="flex flex-col gap-6">
      {[...byModel.entries()].map(([modelKey, rows]) => (
        <div key={modelKey}>
          <h3 className="mb-2 font-mono text-sm text-[var(--color-text-hi)]">{modelKey}</h3>
          <ul className="flex flex-col gap-2">
            {rows.map((v) => (
              <li key={v.id} className="rounded-md border border-[var(--color-border)] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm text-[var(--color-text-hi)]">version {v.version}</span>
                  <div className="flex items-center gap-2">
                    {v.promoted ? <Badge>promoted</Badge> : <Badge variant="outline">not promoted</Badge>}
                    <span className="text-xs text-[var(--color-text-lo)]">{formatDate(v.trained_at)}</span>
                  </div>
                </div>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
                  {flattenForDisplay(v.eval_scores).map((e, i) => (
                    <div key={i} className="flex items-baseline justify-between gap-2 text-xs">
                      <dt className="text-[var(--color-text-lo)]">{e.key}</dt>
                      <dd className="font-mono text-[var(--color-text-hi)]">{e.value}</dd>
                    </div>
                  ))}
                </dl>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
