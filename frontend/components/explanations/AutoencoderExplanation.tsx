import type { AutoencoderExplanationPayload } from "@/lib/api/types";
import { humanizeKey } from "@/lib/format";
import { BarRow, ExplanationNote, ExplanationSection } from "./primitives";

// L3 — autoencoder: per-feature reconstruction error against its own fitted threshold
// (docs/10: "per-feature reconstruction bars with thresholds").
export function AutoencoderExplanation({ explanation }: { explanation: AutoencoderExplanationPayload }) {
  const maxError = Math.max(1e-9, ...explanation.per_feature.map((f) => Math.max(f.error, f.threshold)));
  return (
    <ExplanationSection title="Reconstruction error by feature">
      <ExplanationNote>
        Total squared reconstruction error {explanation.total_recon_error.toFixed(2)}. Each bar is one feature&apos;s
        error against the 99.5th-percentile threshold fitted on benign traffic (the tick mark) — a bar that
        clears its tick is what pushed this window past the operating point.
      </ExplanationNote>
      <div className="flex flex-col gap-3">
        {explanation.per_feature.map((f) => (
          <BarRow
            key={f.feature}
            label={humanizeKey(f.feature)}
            valueLabel={f.error.toFixed(3)}
            fraction={f.error / maxError}
            emphasized={f.exceeded}
            markerFraction={f.threshold / maxError}
            markerLabel={`Threshold ${f.threshold.toFixed(3)}`}
          />
        ))}
      </div>
    </ExplanationSection>
  );
}
