import type { TriageVerdictOut } from "@/lib/api/types";
import { flattenForDisplay } from "@/lib/flatten";
import { formatUsd } from "@/lib/format";
import { StatGrid } from "@/components/ui/StatGrid";

// 9. Agent trace — docs/10: "collapsed by default. Tool calls, arguments, results, tokens,
// cost, latency." Native <details> — no client JS needed for a plain collapse.
export function AgentTrace({ verdict }: { verdict: TriageVerdictOut | null }) {
  if (!verdict) {
    return <p className="text-sm text-[var(--color-text-mid)]">No agent run yet — this incident has not been triaged.</p>;
  }
  return (
    <details className="group rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-4 marker:content-none">
        <span className="text-sm text-[var(--color-text-hi)]">
          {verdict.tool_trace.length} tool call{verdict.tool_trace.length === 1 ? "" : "s"} · {verdict.model}
        </span>
        <span aria-hidden="true" className="text-[var(--color-text-lo)] transition-transform group-open:rotate-90">
          ›
        </span>
      </summary>
      <div className="flex flex-col gap-4 border-t border-[var(--color-border)] p-4">
        <StatGrid
          columns={4}
          stats={[
            { label: "Tokens in", value: verdict.tokens_in?.toLocaleString() ?? "—", mono: true },
            { label: "Tokens out", value: verdict.tokens_out?.toLocaleString() ?? "—", mono: true },
            { label: "Cost", value: formatUsd(verdict.cost_usd), mono: true },
            { label: "Latency", value: verdict.latency_ms !== null ? `${verdict.latency_ms} ms` : "—", mono: true },
          ]}
        />
        <div className="flex flex-col gap-2.5">
          {verdict.tool_trace.map((entry, i) => (
            <div key={i} className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3">
              <p className="font-mono text-xs text-[var(--color-text-hi)]">{entry.tool}</p>
              <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-[var(--color-text-lo)]">Arguments</p>
                  <dl className="mt-1 flex flex-col gap-0.5">
                    {flattenForDisplay(entry.arguments).map((e, j) => (
                      <div key={j} className="flex justify-between gap-2 text-xs">
                        <dt className="text-[var(--color-text-lo)]">{e.key}</dt>
                        <dd className="truncate font-mono text-[var(--color-text-hi)]">{e.value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-[var(--color-text-lo)]">Result</p>
                  <dl className="mt-1 flex flex-col gap-0.5">
                    {flattenForDisplay(entry.result).map((e, j) => (
                      <div key={j} className="flex justify-between gap-2 text-xs">
                        <dt className="text-[var(--color-text-lo)]">{e.key}</dt>
                        <dd className="truncate font-mono text-[var(--color-text-hi)]">{e.value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              </div>
            </div>
          ))}
          {verdict.tool_trace.length === 0 && (
            <p className="text-xs text-[var(--color-text-lo)]">No tool calls recorded for this run.</p>
          )}
        </div>
      </div>
    </details>
  );
}
