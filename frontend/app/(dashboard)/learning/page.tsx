import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type {
  CalibrationResponse,
  LearningEventsResponse,
  LearningMetricsResponse,
  LearningProposalsResponse,
  ModelsOverviewResponse,
  ModelVersionsResponse,
  SuppressionListResponse,
} from "@/lib/api/types";
import { HYPOTHESIS_OUTCOMES } from "@/lib/staticEvalResults";
import { Panel } from "@/components/ui/Panel";
import { ComparisonTables } from "@/components/models/ComparisonTables";
import { HypothesisOutcomesTable } from "@/components/models/HypothesisOutcomesTable";
import { CalibrationSection } from "@/components/models/CalibrationSection";
import { VersionHistoryTable } from "@/components/models/VersionHistoryTable";
import { AlignmentTrendChart } from "@/components/learning/AlignmentTrendChart";
import { DetectorPrecisionTable } from "@/components/learning/DetectorPrecisionTable";
import { SuppressionsList } from "@/components/learning/SuppressionsList";
import { LearningEventsFeed } from "@/components/learning/LearningEventsFeed";
import { ProposalsList } from "@/components/learning/ProposalsList";

export const metadata: Metadata = { title: "Learning — Tenex SOC Analyst" };

/**
 * docs/v2_migration change 27 merged `/models` into `/learning`; change 21/22 (this milestone)
 * wire the two sections change 27 left as honest placeholders, and restore three sections change
 * 27's own six-section list dropped without being asked to remove: change 27 documents what
 * *moved in* from `/models`, it is not a whitelist of everything `/learning` may contain, and
 * these three had live backends and working UI before that change landed.
 *
 * 1. Model performance   2. Hypothesis outcomes   3. Calibration   4. Model versions
 * 5. Human–AI alignment (restored)      6. Per-detector precision (restored)
 * 7. Learning events — the change-21 feed, wired
 * 8. What your feedback changed — gated-mechanism proposals, review + accept/reject, wired
 * 9. Pending suppressions (restored), with its working Accept action
 */
export default async function LearningPage() {
  const [modelsOverview, calibration, versions, metrics, suppressions, events, proposals] =
    await Promise.all([
      fetchServer<ModelsOverviewResponse>("/api/models"),
      fetchServer<CalibrationResponse>("/api/models/calibration"),
      fetchServer<ModelVersionsResponse>("/api/models/versions"),
      fetchServer<LearningMetricsResponse>("/api/learning/metrics"),
      fetchServer<SuppressionListResponse>("/api/learning/suppressions"),
      fetchServer<LearningEventsResponse>("/api/learning/events?limit=30"),
      fetchServer<LearningProposalsResponse>("/api/learning/proposals"),
    ]);

  const allUnreachable =
    modelsOverview === null &&
    calibration === null &&
    versions === null &&
    metrics === null &&
    suppressions === null;

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Learning</h1>
        <p className="mt-1 max-w-prose text-sm text-[var(--color-text-mid)]">
          How good the models are, and them getting better: benchmarks, calibration, and version
          history above; the feedback-driven improvement loop below.
        </p>
      </div>

      {allUnreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">Could not reach the API.</p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : (
        <>
          <Panel title="1. Model performance">
            <ComparisonTables live={modelsOverview} />
          </Panel>

          <Panel title="2. Hypothesis outcomes">
            <HypothesisOutcomesTable outcomes={HYPOTHESIS_OUTCOMES} />
          </Panel>

          <Panel title="3. Calibration">
            {calibration ? (
              <CalibrationSection calibration={calibration} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load calibration data.</p>
            )}
          </Panel>

          <Panel title="4. Model versions">
            {versions ? (
              <VersionHistoryTable versions={versions.items} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load version history.</p>
            )}
          </Panel>

          <Panel title="5. Human–AI alignment">
            {metrics ? (
              <AlignmentTrendChart points={metrics.alignment_trend} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load alignment data.</p>
            )}
          </Panel>

          <Panel title="6. Per-detector precision">
            {metrics ? (
              <DetectorPrecisionTable points={metrics.detector_precision_trend} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load precision data.</p>
            )}
          </Panel>

          <Panel title="7. Learning events">
            {events ? (
              <LearningEventsFeed events={events.items} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load learning events.</p>
            )}
          </Panel>

          <Panel title="8. What your feedback changed">
            {proposals ? (
              <ProposalsList proposals={proposals.items} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load pending proposals.</p>
            )}
          </Panel>

          <Panel title="9. Pending suppressions">
            {suppressions ? (
              <SuppressionsList candidates={suppressions.items} />
            ) : (
              <p className="text-sm text-[var(--color-severity-high)]">Could not load suppression candidates.</p>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
