import type { HypothesisOutcome } from "@/lib/staticEvalResults";
import { Badge } from "@/components/ui/Badge";

// docs/v2_migration change 27, `/learning` section 2 — "the table from docs/12, with
// predictions recorded before the run." Real data (`lib/staticEvalResults.ts`), reported
// plainly including the falsified predictions — CLAUDE.md: "losing is a valid,
// reportable outcome."
export function HypothesisOutcomesTable({ outcomes }: { outcomes: HypothesisOutcome[] }) {
  if (outcomes.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No pre-registered predictions recorded yet.</p>;
  }
  return (
    <ul className="flex flex-col gap-3">
      {outcomes.map((o) => (
        <li key={o.n} className="rounded-md border border-[var(--color-border)] p-3">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <p className="text-sm text-[var(--color-text-hi)]">
              <span className="text-[var(--color-text-lo)]">#{o.n}</span> {o.prediction}
            </p>
            <Badge variant={o.outcome === "confirmed" ? "neutral" : "outline"}>{o.outcome}</Badge>
          </div>
          <p className="mt-1.5 text-xs text-[var(--color-text-mid)]">{o.measured}</p>
        </li>
      ))}
    </ul>
  );
}
