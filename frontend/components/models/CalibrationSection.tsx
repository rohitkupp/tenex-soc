"use client";

import { useState } from "react";
import type { CalibrationResponse } from "@/lib/api/types";
import { StatGrid } from "@/components/ui/StatGrid";
import { Badge } from "@/components/ui/Badge";
import { ReliabilityDiagram } from "./ReliabilityDiagram";

// docs/10: "the reliability diagram." All data server-fetched once (`GET
// /api/models/calibration` refits live, per that route's own docstring) — the detector picker
// below is pure client-side re-render over data already in hand, no re-fetch on switch.
export function CalibrationSection({ calibration }: { calibration: CalibrationResponse }) {
  const fitted = calibration.detectors.filter((d) => d.fitted);
  const [selectedKey, setSelectedKey] = useState(fitted[0]?.detector_key ?? calibration.detectors[0]?.detector_key);
  const selected = calibration.detectors.find((d) => d.detector_key === selectedKey) ?? calibration.detectors[0];

  if (calibration.detectors.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No calibration data yet — no labeled feedback to fit against.</p>;
  }

  return (
    <div className="flex flex-col gap-5">
      {calibration.synthetic && (
        <p className="text-xs text-[var(--color-text-lo)]">
          Includes {calibration.n_synthetic_feedback_events} seeded feedback event
          {calibration.n_synthetic_feedback_events === 1 ? "" : "s"} — demo data, not real analyst decisions.
        </p>
      )}
      <StatGrid
        columns={3}
        stats={[
          { label: "Feedback events", value: String(calibration.n_feedback_events), mono: true },
          {
            label: "Overall Brier (before)",
            value: calibration.overall_brier_before?.toFixed(4) ?? "—",
            mono: true,
          },
          {
            label: "Overall Brier (after)",
            value: calibration.overall_brier_after?.toFixed(4) ?? "—",
            mono: true,
          },
        ]}
      />

      <div className="flex flex-wrap gap-1.5">
        {calibration.detectors.map((d) => (
          <button
            key={d.detector_key}
            type="button"
            onClick={() => setSelectedKey(d.detector_key)}
            className={`rounded-full border px-2.5 py-1 font-mono text-xs transition-colors ${
              d.detector_key === selected?.detector_key
                ? "border-[var(--color-text-hi)] text-[var(--color-text-hi)]"
                : "border-[var(--color-border)] text-[var(--color-text-mid)] hover:text-[var(--color-text-hi)]"
            }`}
          >
            {d.detector_key}
            {!d.fitted && " ·"}
          </button>
        ))}
      </div>

      {selected && (
        <div className="flex flex-wrap items-start gap-6">
          <ReliabilityDiagram before={selected.reliability_before} after={selected.reliability_after} />
          <div className="flex flex-col gap-3">
            <StatGrid
              columns={2}
              stats={[
                { label: "Samples", value: String(selected.n_samples), mono: true },
                { label: "Positives", value: String(selected.n_positive), mono: true },
                { label: "Brier before", value: selected.brier_before?.toFixed(4) ?? "—", mono: true },
                { label: "Brier after", value: selected.brier_after?.toFixed(4) ?? "—", mono: true },
              ]}
            />
            {!selected.fitted && (
              <Badge variant="outline">not fitted{selected.skip_reason ? ` — ${selected.skip_reason}` : ""}</Badge>
            )}
            {selected.brier_improvement !== null && (
              <p className="text-xs text-[var(--color-text-mid)]">
                Brier improvement: {selected.brier_improvement >= 0 ? "+" : ""}
                {selected.brier_improvement.toFixed(4)}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
