import type { BurstExplanationPayload } from "@/lib/api/types";
import { formatCompactDate } from "@/lib/format";
import { StatGrid } from "@/components/ui/StatGrid";
import { BarRow, ExplanationNote, ExplanationSection } from "./primitives";

// L2 — volumetric burst: this bucket's count against the entity's own robust-z population.
export function BurstExplanation({ explanation: e }: { explanation: BurstExplanationPayload }) {
  const max = Math.max(e.count, e.median + e.mad * 4, 1);
  return (
    <ExplanationSection title="Volume vs. this entity's own active buckets">
      <BarRow
        label={`${e.entity_type} ${e.entity_value} — this bucket`}
        valueLabel={String(e.count)}
        fraction={e.count / max}
        emphasized
        markerFraction={e.median / max}
        markerLabel={`Median ${e.median}`}
      />
      <StatGrid
        columns={4}
        stats={[
          { label: "Bucket", value: `${formatCompactDate(e.bucket_start)} – ${formatCompactDate(e.bucket_end)}` },
          { label: "Median (active buckets)", value: e.median.toFixed(1), mono: true },
          { label: "MAD", value: e.mad.toFixed(2), mono: true },
          {
            label: "Robust z",
            value: e.z_is_infinite ? "∞" : e.z !== null ? e.z.toFixed(2) : "—",
            mono: true,
          },
          { label: "Threshold", value: `|z| > ${e.threshold}`, mono: true },
          { label: "Active buckets", value: String(e.n_active_buckets), mono: true },
        ]}
      />
      <ExplanationNote>
        Scored only against this entity&apos;s own nonzero-count buckets — idle time never defines &quot;normal&quot; here.
      </ExplanationNote>
    </ExplanationSection>
  );
}
