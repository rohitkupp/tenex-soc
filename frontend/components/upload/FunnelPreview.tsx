// Static layout placeholder for the pipeline funnel — stage names come from
// docs/01's stage-contracts table (ingest through triage; response/tier2
// run after triage and aren't part of this funnel). This is deliberately
// inert: no counters, no progress, no animation. The live version, driven
// by `GET /api/analyses/{id}/stream`, is M4 — wiring fake numbers in here
// now would be worse than leaving it static.
const STAGES = [
  { key: "ingest", label: "Ingest" },
  { key: "parse", label: "Parse" },
  { key: "enrich", label: "Enrich" },
  { key: "anonymize", label: "Anonymize" },
  { key: "detect", label: "Detect" },
  { key: "correlate", label: "Correlate" },
  { key: "triage", label: "Triage" },
] as const;

export function FunnelPreview() {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-[var(--color-text-hi)]">Pipeline</h2>
        <span className="text-xs text-[var(--color-text-lo)]">
          Live stage progress streams here starting at milestone M4.
        </span>
      </div>
      <ol className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-3">
        {STAGES.map((stage, index) => (
          <li key={stage.key} className="flex items-center gap-2">
            <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1 text-xs text-[var(--color-text-mid)]">
              {stage.label}
            </span>
            {index < STAGES.length - 1 && (
              <span aria-hidden="true" className="text-[var(--color-text-lo)]">
                →
              </span>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
