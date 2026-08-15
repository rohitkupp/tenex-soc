import type { SignalOut } from "@/lib/api/types";
import { formatDate, formatScore } from "@/lib/format";
import { ExplanationRenderer } from "@/components/explanations/ExplanationRenderer";

// 6. Signals — docs/10: each signal's structured explanation "rendered by detector type ...
// Never render raw JSON." Native <details> gives per-signal collapse with zero client JS.
export function SignalsSection({ signals }: { signals: SignalOut[] }) {
  if (signals.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No signals attached to this incident.</p>;
  }
  return (
    <div className="flex flex-col gap-2.5">
      {signals.map((signal) => (
        <details
          key={signal.id}
          className="group rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] open:bg-[var(--color-surface-1)]"
        >
          <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 p-4 marker:content-none">
            <span className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-sm text-[var(--color-text-hi)]">{signal.detector_key}</span>
              <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-xs text-[var(--color-text-lo)]">
                {signal.detector_layer}
              </span>
              <span className="text-xs text-[var(--color-text-mid)]">
                {signal.entity_type} <span className="font-mono">{signal.entity_value}</span>
              </span>
            </span>
            <span className="flex items-center gap-3 text-xs text-[var(--color-text-mid)]">
              <span>confidence {formatScore(signal.confidence)}</span>
              {signal.window_start && <span>{formatDate(signal.window_start)}</span>}
              <span aria-hidden="true" className="text-[var(--color-text-lo)] transition-transform group-open:rotate-90">
                ›
              </span>
            </span>
          </summary>
          <div className="border-t border-[var(--color-border)] p-4">
            <ExplanationRenderer signal={signal} />
          </div>
        </details>
      ))}
    </div>
  );
}
