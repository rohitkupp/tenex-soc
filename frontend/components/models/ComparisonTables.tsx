import type { ModelComparisonTable, ModelsOverviewResponse } from "@/lib/api/types";
import { FALSE_POSITIVE_RATES, L3_COMPARISON, L3_READING_NOTE, L4_RETROSPECTIVE, STATIC_RESULTS_SOURCE } from "@/lib/staticEvalResults";
import { Badge } from "@/components/ui/Badge";
import { Panel } from "@/components/ui/Panel";

function ComparisonTable({ table }: { table: ModelComparisonTable }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-lo)]">
            <th className="py-2 pr-4 font-normal">Model</th>
            <th className="py-2 pr-4 text-right font-normal">Mean F1</th>
            <th className="py-2 pr-4 text-right font-normal">Mean AUC-PR</th>
            <th className="py-2 pr-4 text-right font-normal">Mean recall</th>
            <th className="py-2 pr-4 text-right font-normal">Mean precision</th>
            <th className="py-2 text-right font-normal">Scenarios detected</th>
          </tr>
        </thead>
        <tbody>
          {table.contenders.map((row) => (
            <tr key={row.model_key} className="border-b border-[var(--color-border)] last:border-b-0">
              <td className="py-2 pr-4 font-mono text-[var(--color-text-hi)]">
                {row.model_key} {row.is_winner && <Badge>winner</Badge>}
              </td>
              <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.mean_f1.toFixed(3)}</td>
              <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.mean_auc_pr.toFixed(3)}</td>
              <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.mean_recall.toFixed(3)}</td>
              <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.mean_precision.toFixed(3)}</td>
              <td className="py-2 text-right font-mono text-[var(--color-text-hi)]">
                {row.scenarios_detected} / {row.scenarios_total}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {table.metric_note && <p className="mt-2 text-xs text-[var(--color-text-mid)]">{table.metric_note}</p>}
    </div>
  );
}

// docs/10: "Comparison tables per layer with the winner marked... including the LOSSES."
export function ComparisonTables({ live }: { live: ModelsOverviewResponse | null }) {
  if (live && live.tables.length > 0) {
    return (
      <div className="flex flex-col gap-8">
        {live.tables.map((t) => (
          <div key={t.layer}>
            <h3 className="mb-2 text-sm text-[var(--color-text-hi)]">{t.layer}</h3>
            <ComparisonTable table={t} />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <p className="rounded-md border border-dashed border-[var(--color-border)] p-3 text-xs text-[var(--color-text-mid)]">
        <code className="font-mono">GET /api/models</code> (the live comparison endpoint) is M16&apos;s job and is not
        running against this backend yet. What follows is the real benchmark from{" "}
        <code className="font-mono">{STATIC_RESULTS_SOURCE}</code> — a static, checked-in report, not a live call.
        It will be replaced the day that endpoint ships.
      </p>

      <div>
        <h3 className="mb-2 text-sm text-[var(--color-text-hi)]">{L3_COMPARISON.layer}</h3>
        <ComparisonTable table={L3_COMPARISON} />
        <p className="mt-3 max-w-[68ch] text-xs leading-relaxed text-[var(--color-text-mid)]">{L3_READING_NOTE}</p>
      </div>

      <div>
        <h3 className="mb-2 text-sm text-[var(--color-text-hi)]">False-positive rate</h3>
        <table className="w-full max-w-md border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-lo)]">
              <th className="py-2 pr-4 font-normal">Model</th>
              <th className="py-2 pr-4 text-right font-normal">All benign background</th>
              <th className="py-2 text-right font-normal">benign_but_weird only</th>
            </tr>
          </thead>
          <tbody>
            {FALSE_POSITIVE_RATES.map((row) => (
              <tr key={row.model_key} className="border-b border-[var(--color-border)] last:border-b-0">
                <td className="py-2 pr-4 font-mono text-[var(--color-text-hi)]">{row.model_key}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">
                  {(row.fp_all_benign * 100).toFixed(1)}%
                </td>
                <td className="py-2 text-right font-mono text-[var(--color-text-hi)]">
                  {(row.fp_benign_but_weird * 100).toFixed(1)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Panel title="L2 detectors, Classification (LightGBM vs. Claude zero-shot)" padding="tight">
        <p className="text-xs text-[var(--color-text-mid)]">
          No recorded comparison run for these layers exists in <code className="font-mono">evals/results.md</code> yet
          — shown honestly as not-yet-benchmarked rather than fabricated.
        </p>
      </Panel>

      <Panel title="L4 sequence models — historical, cut layer" padding="tight" right={<Badge variant="outline">retired</Badge>}>
        <p className="mb-2 text-xs text-[var(--color-text-mid)]">{L4_RETROSPECTIVE.note}</p>
        <table className="w-full max-w-xs border-collapse text-sm">
          <tbody>
            {L4_RETROSPECTIVE.rows.map((row) => (
              <tr key={row.model_key} className="border-b border-[var(--color-border)] last:border-b-0">
                <td className="py-1.5 pr-4 font-mono text-[var(--color-text-hi)]">
                  {row.model_key} {row.winner && <Badge>winner</Badge>}
                </td>
                <td className="py-1.5 text-right font-mono text-[var(--color-text-hi)]">
                  pooled F1 {row.pooled_f1.toFixed(3)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
