import Link from "next/link";
import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { AnalysesListResponse } from "@/lib/api/types";
import { formatDate } from "@/lib/format";

export const metadata: Metadata = { title: "Analyses — Tenex SOC Analyst" };

const primaryButton =
  "rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90";

// The aggregate funnel (docs/10) needs pipeline data that doesn't exist
// until M4 — this milestone renders the list itself plus the empty state.
export default async function AnalysesPage() {
  const data = await fetchServer<AnalysesListResponse>("/api/analyses");
  const analyses = data?.items ?? [];
  // fetchServer collapses "API unreachable" and "zero rows" to the same
  // null/empty result — middleware already gates auth, so a null response
  // here almost always means the API is down, not that the tenant has no
  // analyses. Say so rather than showing the same copy for both.
  const unreachable = data === null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">
          Analyses
        </h1>
        <Link href="/upload" className={primaryButton}>
          Upload a log file
        </Link>
      </div>

      {unreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">
            Could not load analyses — the API is unreachable.
          </p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : analyses.length === 0 ? (
        <div className="flex flex-col items-center gap-4 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-text-mid)]">
            No incidents yet — upload a log file to start.
          </p>
          <Link href="/upload" className={primaryButton}>
            Upload a log file
          </Link>
        </div>
      ) : (
        <ul className="divide-y divide-[var(--color-border)] rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]">
          {analyses.map((analysis) => (
            <li key={analysis.id}>
              <Link
                href={`/analyses/${analysis.id}`}
                className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 transition-colors hover:bg-[var(--color-surface-2)]"
              >
                <div className="flex flex-col gap-1">
                  <span className="font-mono text-sm text-[var(--color-text-hi)]">
                    {analysis.id}
                  </span>
                  <span className="text-xs text-[var(--color-text-lo)]">
                    {analysis.created_at ? formatDate(analysis.created_at) : "—"}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {analysis.detected_sources?.map((source) => (
                    <span
                      key={source}
                      className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs text-[var(--color-text-mid)]"
                    >
                      {source}
                    </span>
                  ))}
                  <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs text-[var(--color-text-mid)]">
                    {analysis.status ?? "queued"}
                  </span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
