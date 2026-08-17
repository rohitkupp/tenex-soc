import type { OverlapDistributionResponse } from "@/lib/api/tier2-charts";
import { MeterRow } from "./MeterRow";
import { InsufficientCrossTenantData } from "./InsufficientCrossTenantData";

const BUCKET_LABEL: Record<string, string> = {
  "1": "Seen by 1 tenant",
  "2": "Seen by 2 tenants",
  "3+": "Seen by 3+ tenants",
};

// docs/09/CLAUDE.md: for each indicator signature, how many distinct tenants have seen it.
// The 2+ buckets ARE the cross-tenant signal — chart 1 in the brief, and the one this whole
// dashboard's premise rests on: an indicator seen in more than one tenant is evidence of
// shared campaign infrastructure.
export function OverlapDistributionChart({ data }: { data: OverlapDistributionResponse }) {
  if (data.total_indicators === 0) {
    return (
      <InsufficientCrossTenantData
        tenantCount={0}
        needs={1}
        detail="No indicator signatures with a comparable domain/dst-IP hash exist yet — upload analyses that produce triaged incidents to populate this chart."
      />
    );
  }

  const maxValue = Math.max(...data.buckets.map((b) => b.indicator_count), 1);
  const crossTenantCount = data.buckets
    .filter((b) => b.bucket !== "1")
    .reduce((sum, b) => sum + b.indicator_count, 0);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3">
        {data.buckets.map((bucket) => (
          <MeterRow
            key={bucket.bucket}
            label={BUCKET_LABEL[bucket.bucket] ?? bucket.bucket}
            value={bucket.indicator_count}
            maxValue={maxValue}
            emphasized={bucket.bucket !== "1"}
          />
        ))}
      </div>
      <p className="text-xs text-[var(--color-text-lo)]">
        {data.total_indicators} distinct indicator{data.total_indicators === 1 ? "" : "s"} observed across the
        fleet — {crossTenantCount} of them seen by more than one tenant.
      </p>
    </div>
  );
}
