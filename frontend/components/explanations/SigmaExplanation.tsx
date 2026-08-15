import type { SigmaExplanationPayload } from "@/lib/api/types";
import { humanizeKey } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";
import { ExplanationNote, ExplanationSection } from "./primitives";

// L1 — Sigma rule match: the matched condition, its metadata, and the specific field values
// that satisfied it (docs/10: "Sigma rules -> the matched condition").
export function SigmaExplanation({ explanation }: { explanation: SigmaExplanationPayload }) {
  const matchEntries = Object.entries(explanation.match ?? {});
  return (
    <ExplanationSection title="Matched rule">
      <div className="flex flex-col gap-1">
        <p className="text-sm text-[var(--color-text-hi)]">{explanation.title}</p>
        <p className="text-xs text-[var(--color-text-mid)]">{explanation.description}</p>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Badge variant="outline">{explanation.level}</Badge>
        <Badge variant="outline">{explanation.logsource.product}</Badge>
        <Badge variant="outline">{explanation.logsource.service}</Badge>
        {explanation.tags.map((tag) => (
          <Badge key={tag}>{tag}</Badge>
        ))}
      </div>

      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3">
        <p className="text-xs text-[var(--color-text-lo)]">Condition</p>
        <code className="mt-1 block whitespace-pre-wrap break-all font-mono text-xs text-[var(--color-text-hi)]">
          {explanation.condition}
        </code>
      </div>

      {matchEntries.length > 0 && (
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-2">
          {matchEntries.map(([key, value]) => (
            <div key={key} className="flex items-baseline justify-between gap-3 text-xs">
              <dt className="text-[var(--color-text-lo)]">{humanizeKey(key)}</dt>
              <dd className="truncate font-mono text-[var(--color-text-hi)]">{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}

      {!explanation.calibrated && (
        <ExplanationNote>
          Score is an uncalibrated, rule-level heuristic — isotonic calibration for L1 lands with fusion (M10).
        </ExplanationNote>
      )}
    </ExplanationSection>
  );
}
