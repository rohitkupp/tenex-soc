import { flattenForDisplay } from "@/lib/flatten";
import { humanizeKey } from "@/lib/format";
import { ExplanationNote, ExplanationSection } from "./primitives";

/**
 * A detector whose `explanation` shape this renderer does not recognize still needs a
 * legible view — docs/10: "if a shape is missing, render a labelled fallback, never a JSON
 * dump." This flattens the payload into `key: value` rows in the same mono style as the
 * citation-expanded raw event, rather than pretty-printing the object as text.
 */
export function FallbackExplanation({ explanation, detectorKey }: { explanation: unknown; detectorKey: string }) {
  const entries = flattenForDisplay(explanation);
  return (
    <ExplanationSection title="Explanation">
      <ExplanationNote>
        No dedicated view is registered for detector <code className="font-mono">{detectorKey}</code>. Every
        field this detector reported, labelled:
      </ExplanationNote>
      {entries.length === 0 ? (
        <p className="text-xs text-[var(--color-text-lo)]">No explanation data.</p>
      ) : (
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3 sm:grid-cols-2">
          {entries.map((entry, i) => (
            <div key={`${entry.key}-${i}`} className="flex items-baseline justify-between gap-3 text-xs">
              <dt className="shrink-0 text-[var(--color-text-lo)]" title={entry.key}>
                {humanizeKey(entry.key)}
              </dt>
              <dd className="truncate font-mono text-[var(--color-text-hi)]" title={entry.value}>
                {entry.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </ExplanationSection>
  );
}
