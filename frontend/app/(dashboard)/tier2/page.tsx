import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { IndicatorOverlapResponse, Tier2OverviewResponse } from "@/lib/api/types";
import { Panel } from "@/components/ui/Panel";
import { OverviewStats } from "@/components/tier2/OverviewStats";
import { IndicatorOverlapTable } from "@/components/tier2/IndicatorOverlapTable";
import { NLQueryBox } from "@/components/tier2/NLQueryBox";

export const metadata: Metadata = { title: "Tier 2 — Tenex SOC Analyst" };

// docs/10: "/tier2 — overview, indicator overlap, and the NL query box that ALWAYS displays
// the generated SQL before results."
export default async function Tier2Page() {
  const [overview, overlap] = await Promise.all([
    fetchServer<Tier2OverviewResponse>("/api/tier2/overview"),
    fetchServer<IndicatorOverlapResponse>("/api/tier2/indicator-overlap"),
  ]);

  if (overview === null && overlap === null) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
        <p className="text-sm text-[var(--color-severity-high)]">Could not reach the API.</p>
        <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Tier 2</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          Cross-tenant aggregates over anonymized indicators — never another tenant&apos;s raw data.
        </p>
      </div>

      <Panel title="Overview">
        {overview ? <OverviewStats overview={overview} /> : <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>}
      </Panel>

      <Panel title="Indicator overlap">
        {overlap ? (
          <IndicatorOverlapTable items={overlap.items} />
        ) : (
          <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>
        )}
      </Panel>

      <Panel title="Ask a question">
        <NLQueryBox />
      </Panel>
    </div>
  );
}
