import type { ContainmentSummaryOut } from "@/lib/api/types";
import { formatPercent } from "@/lib/format";
import { StatGrid } from "@/components/ui/StatGrid";

// docs/08: "Headline metric: autonomous containment rate."
export function ContainmentSummary({ containment }: { containment: ContainmentSummaryOut }) {
  if (containment.total_with_outcome === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No plans executed yet.</p>;
  }
  return (
    <StatGrid
      columns={4}
      stats={[
        { label: "Containment rate", value: formatPercent(containment.rate), mono: true },
        { label: "Contained", value: String(containment.contained), mono: true },
        { label: "Partially contained", value: String(containment.partially_contained), mono: true },
        { label: "Failed", value: String(containment.failed), mono: true },
      ]}
    />
  );
}
