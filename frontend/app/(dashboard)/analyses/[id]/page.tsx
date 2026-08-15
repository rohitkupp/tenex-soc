import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { AnalysisDetail } from "@/lib/api/types";
import { formatDate, formatPercent, formatUsd } from "@/lib/format";
import { FunnelProgress } from "@/components/pipeline/FunnelProgress";

export const metadata: Metadata = { title: "Analysis — Tenex SOC Analyst" };

// docs/10-FRONTEND.md scopes this route to funnel state + counters for a
// completed or running analysis; the rich overview (event volume chart, top
// entities, severity distribution) lands at M15 — deliberately not built here.
export default async function AnalysisDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const analysis = await fetchServer<AnalysisDetail>(`/api/analyses/${id}`);

  // fetchServer collapses "not found" and "API unreachable" to the same
  // null result (see lib/api/server.ts) — say something true of both rather
  // than guessing which one happened.
  if (analysis === null) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
        <p className="text-sm text-[var(--color-text-mid)]">
          Analysis not found, or the API is unreachable.
        </p>
        <Link
          href="/"
          className="text-sm text-[var(--color-text-hi)] underline underline-offset-2"
        >
          Back to analyses
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <Link
            href="/"
            className="text-xs text-[var(--color-text-lo)] transition-colors hover:text-[var(--color-text-mid)]"
          >
            ← Analyses
          </Link>
          <h1 className="mt-1 font-mono text-lg font-semibold tracking-tight text-[var(--color-text-hi)]">
            {analysis.id}
          </h1>
        </div>
        <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs text-[var(--color-text-mid)]">
          {analysis.status}
        </span>
      </div>

      <nav className="flex items-center gap-4 border-b border-[var(--color-border)] text-sm">
        <Link
          href={`/analyses/${analysis.id}/incidents`}
          className="border-b-2 border-transparent pb-2 text-[var(--color-text-mid)] transition-colors hover:border-[var(--color-text-hi)] hover:text-[var(--color-text-hi)]"
        >
          Incidents
        </Link>
        <Link
          href={`/analyses/${analysis.id}/events`}
          className="border-b-2 border-transparent pb-2 text-[var(--color-text-mid)] transition-colors hover:border-[var(--color-text-hi)] hover:text-[var(--color-text-hi)]"
        >
          Events
        </Link>
      </nav>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-[var(--color-text-lo)]">Started</dt>
          <dd className="mt-0.5 text-[var(--color-text-hi)]">
            {analysis.started_at ? formatDate(analysis.started_at) : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-[var(--color-text-lo)]">Finished</dt>
          <dd className="mt-0.5 text-[var(--color-text-hi)]">
            {analysis.finished_at ? formatDate(analysis.finished_at) : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-[var(--color-text-lo)]">Parse failure rate</dt>
          <dd className="mt-0.5 font-mono text-[var(--color-text-hi)]">
            {formatPercent(analysis.parse_failure_rate)}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-[var(--color-text-lo)]">LLM cost</dt>
          <dd className="mt-0.5 font-mono text-[var(--color-text-hi)]">
            {formatUsd(analysis.llm_cost_usd)}
          </dd>
        </div>
      </dl>

      {analysis.error && (
        <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
          {analysis.error}
        </p>
      )}

      <FunnelProgress analysisId={analysis.id} initial={analysis} />
    </div>
  );
}
