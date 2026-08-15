import type { BeaconingExplanationPayload } from "@/lib/api/types";
import { formatDurationHours } from "@/lib/format";
import { StatGrid } from "@/components/ui/StatGrid";
import { Badge } from "@/components/ui/Badge";
import { BarRow, ExplanationNote, ExplanationSection } from "./primitives";

// L2 — beaconing: interval statistics plus the FFT periodicity cross-check (docs/10:
// "interval statistics (mean interval, CV, MAD jitter, dominant lag)").
export function BeaconingExplanation({ explanation: e }: { explanation: BeaconingExplanationPayload }) {
  return (
    <ExplanationSection title="Interval statistics">
      <StatGrid
        columns={4}
        stats={[
          { label: "Mean interval", value: `${e.mean_interval.toFixed(1)}s`, mono: true },
          { label: "Coefficient of variation", value: e.cv.toFixed(3), mono: true },
          { label: "MAD jitter", value: e.mad_jitter.toFixed(3), mono: true },
          { label: "Events", value: String(e.n_events), mono: true },
          { label: "Duration", value: formatDurationHours(e.duration_h), mono: true },
          { label: "Source IP", value: e.src_ip, mono: true },
          { label: "Domain", value: e.domain, mono: true },
          { label: "Regularity", value: e.regularity.toFixed(3), mono: true },
        ]}
      />
      <BarRow
        label="Regularity (1 − CV, clamped)"
        valueLabel={e.regularity.toFixed(3)}
        fraction={e.regularity}
        emphasized
      />

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Badge variant={e.fft_has_dominant_peak ? "neutral" : "outline"}>
          {e.fft_has_dominant_peak ? "Dominant FFT peak found" : "No dominant FFT peak"}
        </Badge>
        <span className="text-xs text-[var(--color-text-mid)]">
          Dominant lag {e.dominant_period_s > 0 ? `${e.dominant_period_s.toFixed(0)}s` : "—"} · peak/mean power
          ratio {e.fft_peak_power_ratio.toFixed(1)}× (threshold {e.fft_power_ratio_threshold}×)
        </span>
      </div>
      <ExplanationNote>
        The FFT scan is a cross-check reported alongside the CV/duration/volume score above, not a second gate —
        the two can disagree, and that disagreement is itself useful to a human triaging the signal.
      </ExplanationNote>
    </ExplanationSection>
  );
}
