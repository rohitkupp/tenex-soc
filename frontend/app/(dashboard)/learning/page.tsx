import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { CalibrationResponse, ModelsOverviewResponse, ModelVersionsResponse } from "@/lib/api/types";
import { HYPOTHESIS_OUTCOMES } from "@/lib/staticEvalResults";
import { Panel } from "@/components/ui/Panel";
import { ComparisonTables } from "@/components/models/ComparisonTables";
import { HypothesisOutcomesTable } from "@/components/models/HypothesisOutcomesTable";
import { CalibrationSection } from "@/components/models/CalibrationSection";
import { VersionHistoryTable } from "@/components/models/VersionHistoryTable";

export const metadata: Metadata = { title: "Learning — Tenex SOC Analyst" };

/**
 * docs/v2_migration change 27: "/models" is deleted whole — its content (a differentiator
 * that "must not be reduced to a README table") merges into "/learning", which becomes the
 * single page about model quality, static benchmarks directly above the improvement curve.
 * Six sections, in this order:
 *
 * 1. Model performance — benchmark comparison table, full-space vs. PCA for the distance
 *    methods (`GET /api/models`, unchanged — only the route it lived on moved)
 * 2. Hypothesis outcomes — predictions recorded before the run (docs/12's table)
 * 3. Calibration — reliability diagram, Brier score (`GET /api/models/calibration`)
 * 4. Model versions — history with the eval scores that gated each promotion
 *    (`GET /api/models/versions`)
 * 5. Learning events — the continuous-learning feed (docs/v2_migration change 21)
 * 6. What your feedback changed — before/after metrics per adaptation (change 22)
 *
 * Sections 5 and 6 render honest empty states, not fabricated content: changes 21
 * (learning loop) and 22 (feedback UI) are later phases in the migration's own
 * application order (change 27 — this page — applies *before* them specifically so the
 * routes that will eventually host that content are already settled). Nothing in this
 * checkout computes a "learning event" or a "before/after" delta yet.
 */
export default async function LearningPage() {
  const [modelsOverview, calibration, versions] = await Promise.all([
    fetchServer<ModelsOverviewResponse>("/api/models"),
    fetchServer<CalibrationResponse>("/api/models/calibration"),
    fetchServer<ModelVersionsResponse>("/api/models/versions"),
  ]);

  const allUnreachable = modelsOverview === null && calibration === null && versions === null;

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

          <Panel title="5. Learning events">
            <p className="text-sm text-[var(--color-text-mid)]">
              Not wired yet — this section lists individual continuous-learning events (detector
              reweighting, calibration refits, suppression rules written, retrain gate
              decisions) once docs/v2_migration change 21 lands. Honest empty state, not
              fabricated content.
            </p>
          </Panel>

          <Panel title="6. What your feedback changed">
            <p className="text-sm text-[var(--color-text-mid)]">
              Not wired yet — this section shows recent adaptations with before/after metrics,
              tied to the analyst feedback that triggered them, once docs/v2_migration change 22
              lands. Honest empty state, not fabricated content.
            </p>
          </Panel>
        </>
      )}
    </div>
  );
}
