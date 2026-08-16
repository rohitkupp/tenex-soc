import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { LearningMetricsResponse, SuppressionListResponse } from "@/lib/api/types";
import { Panel } from "@/components/ui/Panel";
import { AlignmentTrendChart } from "@/components/learning/AlignmentTrendChart";
import { DetectorPrecisionTable } from "@/components/learning/DetectorPrecisionTable";
import { SuppressionsList } from "@/components/learning/SuppressionsList";

export const metadata: Metadata = { title: "Learning — Tenex SOC Analyst" };

// docs/10: "/learning — Alignment trend, per-detector precision, pending suppressions."
// Containment rate was removed along with the response action graph and enforcement plane
// (docs/v2_migration change 20 — "autonomous containment rate is gone as a metric").
export default async function LearningPage() {
  const [metrics, suppressions] = await Promise.all([
    fetchServer<LearningMetricsResponse>("/api/learning/metrics"),
    fetchServer<SuppressionListResponse>("/api/learning/suppressions"),
  ]);

  if (metrics === null && suppressions === null) {
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
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Learning</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          How analyst feedback measurably shifts calibration, detector weights, and suppression rules.
        </p>
      </div>

      <Panel title="Human–AI alignment">
        {metrics ? <AlignmentTrendChart points={metrics.alignment_trend} /> : <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>}
      </Panel>

      <Panel title="Per-detector precision">
        {metrics ? <DetectorPrecisionTable points={metrics.detector_precision_trend} /> : <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>}
      </Panel>

      <Panel title="Pending suppressions">
        {suppressions ? (
          <SuppressionsList candidates={suppressions.items} />
        ) : (
          <p className="text-sm text-[var(--color-severity-high)]">Could not load.</p>
        )}
      </Panel>
    </div>
  );
}
