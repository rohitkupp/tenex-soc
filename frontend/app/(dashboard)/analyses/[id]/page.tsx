import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { AnalysisDetail, AnalysisOverviewResponse, AnalysisTimelineResponse } from "@/lib/api/types";
import { formatDate, formatNumber, formatPercent, formatUsd } from "@/lib/format";
import { FunnelProgress } from "@/components/pipeline/FunnelProgress";
import { AnalysisTimeline } from "@/components/analyses/AnalysisTimeline";
import { RetryButton } from "@/components/analyses/RetryButton";
import { ExecutiveSummary } from "@/components/analyses/ExecutiveSummary";
import { NotableUsersPanel } from "@/components/analyses/NotableUsersPanel";
import { NotableDestinationsPanel } from "@/components/analyses/NotableDestinationsPanel";
import { SemanticFindingsPanel } from "@/components/analyses/SemanticFindingsPanel";
import { TrafficStatsPanel } from "@/components/analyses/TrafficStatsPanel";
import { Panel } from "@/components/ui/Panel";

export const metadata: Metadata = { title: "Analysis — Tenex SOC Analyst" };

// docs/v2_migration change 27: this page now covers three states of one analysis, not
// just "the overview" — "while `analyses.status` is `queued` or `running`, the page
// renders the live SSE stage funnel... When the pipeline completes, the same page
// becomes the overview. No separate page, no navigation." A failed analysis is a third
// state layered on top: the funnel renders with the failing stage marked (`FunnelProgress`
// itself does this), and a retry action sits right next to the error rather than on a
// deleted `/ops` console. Section order below follows what the analyst most needs to see
// first for each state — funnel first while there's nothing else yet, overview first once
// there is.
export default async function AnalysisDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [analysis, timeline, overview] = await Promise.all([
    fetchServer<AnalysisDetail>(`/api/analyses/${id}`),
    fetchServer<AnalysisTimelineResponse>(`/api/analyses/${id}/timeline`),
    // change 9: deterministic, always produced — safe to fetch on every render, unlike the
    // Narrator (`ExecutiveSummary`), which is an explicit, cost-bearing click.
    fetchServer<AnalysisOverviewResponse>(`/api/analyses/${id}/overview`),
  ]);

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

  const isFailed = analysis.status === "failed";
  const isRunning = analysis.status === "queued" || analysis.status === "running";

  const funnel = <FunnelProgress analysisId={analysis.id} initial={analysis} />;

  // docs/v2_migration change 10: "Summary · Timeline · Anomalies · Notable users · Notable
  // destinations · Traffic statistics" — this page's section order below, extending the funnel
  // page rather than replacing it (change 27). `overview` (change 9) is deterministic and safe
  // to render on every load; the executive summary (`ExecutiveSummary`, change 14 Path A) is a
  // separate, explicit, cost-bearing click within the Summary section.
  const overviewSections = (
    <>
      <Panel title="Summary" padding="tight">
        <div className="flex flex-col gap-3 p-1">
          {overview ? (
            <>
              <ExecutiveSummary analysisId={analysis.id} />
              <Link
                href={`/analyses/${analysis.id}/incidents`}
                className="w-fit text-xs text-[var(--color-text-mid)] underline underline-offset-2 hover:text-[var(--color-text-hi)]"
              >
                {formatNumber(overview.anomaly_count)} anomal{overview.anomaly_count === 1 ? "y" : "ies"} found →
              </Link>
            </>
          ) : (
            <p className="text-sm text-[var(--color-text-mid)]">
              Overview not available — the API is unreachable.
            </p>
          )}
        </div>
      </Panel>

      <AnalysisTimeline data={timeline} />

      {overview && (
        <>
          <NotableUsersPanel users={overview.notable_users} />
          <NotableDestinationsPanel destinations={overview.notable_destinations} />
          <SemanticFindingsPanel findings={overview.domain_semantic_findings} />
          <TrafficStatsPanel overview={overview.overview} />
        </>
      )}

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
    </>
  );

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
        <span
          className={
            isFailed
              ? "rounded-full border border-[var(--color-severity-critical)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-medium text-[var(--color-severity-critical)]"
              : "rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs text-[var(--color-text-mid)]"
          }
        >
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
        <Link
          href={`/analyses/${analysis.id}/evidence`}
          className="border-b-2 border-transparent pb-2 text-[var(--color-text-mid)] transition-colors hover:border-[var(--color-text-hi)] hover:text-[var(--color-text-hi)]"
        >
          Evidence
        </Link>
      </nav>

      {isFailed && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[var(--color-severity-critical)] bg-[var(--color-surface-1)] px-5 py-4">
          <div>
            <p className="text-sm font-medium text-[var(--color-severity-critical)]">
              Analysis failed{analysis.stage ? ` at the ${analysis.stage} stage` : ""}
            </p>
            {analysis.error && (
              <p className="mt-1 text-xs text-[var(--color-text-mid)]">{analysis.error}</p>
            )}
          </div>
          <RetryButton analysisId={analysis.id} />
        </div>
      )}

      {isRunning || isFailed ? (
        <>
          {funnel}
          {overviewSections}
        </>
      ) : (
        <>
          {overviewSections}
          {funnel}
        </>
      )}
    </div>
  );
}
