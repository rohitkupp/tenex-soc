import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { IndicatorOverlapResponse, Tier2OverviewResponse } from "@/lib/api/types";
import type {
  DetectorReliabilityResponse,
  FirstSeenResponse,
  OverlapDistributionResponse,
  TechniquePrevalenceResponse,
} from "@/lib/api/tier2-charts";
import { Panel } from "@/components/ui/Panel";
import { OverviewStats } from "@/components/tier2/OverviewStats";
import { IndicatorOverlapTable } from "@/components/tier2/IndicatorOverlapTable";
import { OverlapDistributionChart } from "@/components/tier2/charts/OverlapDistributionChart";
import { TechniquePrevalenceChart } from "@/components/tier2/charts/TechniquePrevalenceChart";
import { DetectorReliabilityChart } from "@/components/tier2/charts/DetectorReliabilityChart";
import { FirstSeenChart } from "@/components/tier2/charts/FirstSeenChart";

export const metadata: Metadata = { title: "Tier 2 — Tenex SOC Analyst" };

function CouldNotLoad() {
  return <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>;
}

// docs/10: "/tier2 — cross-tenant analytics: overview, indicator overlap, and four
// cross-tenant learning charts." The NL→SQL chatbot that used to live here is removed under
// a hard cost constraint (docs/06's "Text-to-SQL safety" section, "removed" note) — every
// panel on this page today is a deterministic, non-LLM query.
export default async function Tier2Page() {
  const [overview, overlap, overlapDistribution, techniquePrevalence, detectorReliability, firstSeen] =
    await Promise.all([
      fetchServer<Tier2OverviewResponse>("/api/tier2/overview"),
      fetchServer<IndicatorOverlapResponse>("/api/tier2/indicator-overlap"),
      fetchServer<OverlapDistributionResponse>("/api/tier2/overlap-distribution"),
      fetchServer<TechniquePrevalenceResponse>("/api/tier2/technique-prevalence"),
      fetchServer<DetectorReliabilityResponse>("/api/tier2/detector-reliability"),
      fetchServer<FirstSeenResponse>("/api/tier2/first-seen"),
    ]);

  const allFailed =
    overview === null &&
    overlap === null &&
    overlapDistribution === null &&
    techniquePrevalence === null &&
    detectorReliability === null &&
    firstSeen === null;

  if (allFailed) {
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

      <Panel title="Overview">{overview ? <OverviewStats overview={overview} /> : <CouldNotLoad />}</Panel>

      <Panel title="Indicator overlap">
        {overlap ? <IndicatorOverlapTable items={overlap.items} /> : <CouldNotLoad />}
      </Panel>

      <Panel
        title="Indicator overlap distribution"
        right={<span className="text-xs text-[var(--color-text-lo)]">Chart 1</span>}
      >
        {overlapDistribution ? <OverlapDistributionChart data={overlapDistribution} /> : <CouldNotLoad />}
      </Panel>

      <Panel
        title="Cross-tenant technique prevalence"
        right={<span className="text-xs text-[var(--color-text-lo)]">Chart 2</span>}
      >
        {techniquePrevalence ? <TechniquePrevalenceChart data={techniquePrevalence} /> : <CouldNotLoad />}
      </Panel>

      <Panel
        title="Detector reliability, pooled analyst feedback"
        right={<span className="text-xs text-[var(--color-text-lo)]">Chart 3</span>}
      >
        {detectorReliability ? <DetectorReliabilityChart data={detectorReliability} /> : <CouldNotLoad />}
      </Panel>

      <Panel
        title="First-seen propagation"
        right={<span className="text-xs text-[var(--color-text-lo)]">Chart 4</span>}
      >
        {firstSeen ? <FirstSeenChart data={firstSeen} /> : <CouldNotLoad />}
      </Panel>
    </div>
  );
}
