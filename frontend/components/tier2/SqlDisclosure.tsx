/**
 * docs/06 / docs/09: "`/api/tier2/query` always returns the generated SQL, and the UI always
 * displays it before results" — "especially" when the query was rejected. This component has
 * exactly one job: never let a caller hide the SQL, rejected or not.
 */
export function SqlDisclosure({ sql, rejected }: { sql: string; rejected: boolean }) {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3">
      <p className="text-[10px] uppercase tracking-wide text-[var(--color-text-lo)]">
        Generated SQL{rejected ? " (rejected — shown anyway)" : ""}
      </p>
      <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-[var(--color-text-hi)]">
        {sql || "(no SQL generated)"}
      </pre>
    </div>
  );
}
