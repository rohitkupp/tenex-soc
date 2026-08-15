import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { CalibrationResponse, ModelsOverviewResponse, ModelVersionsResponse } from "@/lib/api/types";
import { Panel } from "@/components/ui/Panel";
import { ComparisonTables } from "@/components/models/ComparisonTables";
import { CalibrationSection } from "@/components/models/CalibrationSection";
import { VersionHistoryTable } from "@/components/models/VersionHistoryTable";

export const metadata: Metadata = { title: "Models — Tenex SOC Analyst" };

// docs/10: "/models — where the benchmarking discipline becomes visible." Comparison tables,
// reliability diagram, version history with the eval scores that gated each promotion.
export default async function ModelsPage() {
  const [modelsOverview, calibration, versions] = await Promise.all([
    fetchServer<ModelsOverviewResponse>("/api/models"),
    fetchServer<CalibrationResponse>("/api/models/calibration"),
    fetchServer<ModelVersionsResponse>("/api/models/versions"),
  ]);

  const allUnreachable = modelsOverview === null && calibration === null && versions === null;

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Models</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          Every model has a simpler baseline it must beat. Losing is a valid, reportable outcome.
        </p>
      </div>

      {allUnreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">Could not reach the API.</p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : (
        <>
          <Panel title="Benchmark comparison">
            <ComparisonTables live={modelsOverview} />
          </Panel>

          <Panel title="Calibration">
            {calibration ? (
              <CalibrationSection calibration={calibration} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load calibration data.</p>
            )}
          </Panel>

          <Panel title="Version history">
            {versions ? (
              <VersionHistoryTable versions={versions.items} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load version history.</p>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
