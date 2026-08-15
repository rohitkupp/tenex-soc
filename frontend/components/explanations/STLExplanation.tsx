import type { STLExplanationPayload } from "@/lib/api/types";
import { StatGrid } from "@/components/ui/StatGrid";
import { Badge } from "@/components/ui/Badge";
import { ExplanationNote, ExplanationSection } from "./primitives";

const MODEL_LABEL: Record<STLExplanationPayload["model"], string> = {
  stl_daily_weekly: "STL — daily + weekly seasonal",
  stl_daily_only: "STL — daily seasonal only",
  fallback_robust_z: "Fallback — robust z (not enough history for a seasonal fit)",
};

// L2 — STL seasonal residuals: the decomposition of this one flagged hour's volume into
// trend + seasonal + residual (docs/10: "the seasonal decomposition"). The payload is a
// single hour's scalars, not a time series, so this renders as a stacked composition of that
// hour rather than a fabricated multi-point chart.
export function STLExplanation({ explanation: e }: { explanation: STLExplanationPayload }) {
  const isFallback = e.model === "fallback_robust_z";
  const parts = [
    { label: "Trend", value: e.trend },
    { label: "Daily seasonal", value: e.seasonal_daily },
    { label: "Weekly seasonal", value: e.seasonal_weekly },
    { label: "Residual", value: e.residual },
  ].filter((p): p is { label: string; value: number } => p.value !== null);

  const maxAbs = Math.max(1e-9, ...parts.map((p) => Math.abs(p.value)));

  return (
    <ExplanationSection title="Seasonal decomposition — this hour's volume">
      <Badge variant="outline">{MODEL_LABEL[e.model]}</Badge>

      {isFallback ? (
        <ExplanationNote>{e.reason ?? "Not enough history for a seasonal profile."}</ExplanationNote>
      ) : (
        <div className="flex h-6 w-full overflow-hidden rounded-md border border-[var(--color-border)]">
          {parts.map((p) => {
            const fraction = Math.abs(p.value) / (parts.reduce((s, x) => s + Math.abs(x.value), 0) || 1);
            return (
              <div
                key={p.label}
                className="flex items-center justify-center border-r border-[var(--color-surface-0)] last:border-r-0"
                style={{
                  width: `${Math.max(fraction * 100, 4)}%`,
                  backgroundColor:
                    p.value >= 0
                      ? `color-mix(in srgb, var(--color-text-hi) ${Math.round((Math.abs(p.value) / maxAbs) * 60 + 20)}%, var(--color-surface-2))`
                      : "var(--color-surface-2)",
                }}
                title={`${p.label}: ${p.value.toFixed(2)}`}
              />
            );
          })}
        </div>
      )}

      <StatGrid
        columns={4}
        stats={[
          { label: "Hourly count", value: String(e.hourly_count), mono: true },
          {
            label: "Residual z",
            value: e.residual_z_is_infinite ? "∞" : e.residual_z !== null ? e.residual_z.toFixed(2) : "—",
            mono: true,
          },
          { label: "Period(s) used", value: e.period_used.length ? e.period_used.join(", ") : "none", mono: true },
          { label: "Entity", value: `${e.entity_type} ${e.entity_value}`, mono: true },
        ]}
      />
      <ExplanationNote>
        This entity&apos;s own learned daily/weekly rhythm defines &quot;normal&quot; here — the flag is a deviation from its
        own history, not a fixed off-hours rule.
      </ExplanationNote>
    </ExplanationSection>
  );
}
