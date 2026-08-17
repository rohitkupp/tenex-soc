import type { DetectorReliabilityResponse } from "@/lib/api/tier2-charts";
import { MeterRow } from "./MeterRow";
import { InsufficientCrossTenantData } from "./InsufficientCrossTenantData";

const MAX_DETECTORS_SHOWN = 15;

// docs/09/CLAUDE.md: per-detector confirm/dismiss counts pooled across every tenant's analyst
// feedback (`app.tier2.detector_reliability` — a deliberate, reviewed exception to tenant
// scoping). The highest-value cross-tenant learning signal for an MDR: a detector that is
// noisy everywhere, not just for one customer.
export function DetectorReliabilityChart({ data }: { data: DetectorReliabilityResponse }) {
  if (data.total_tenants < 2) {
    return (
      <InsufficientCrossTenantData
        tenantCount={data.total_tenants}
        detail="Detector reliability pooled across tenants only means something once more than one tenant has given analysts feedback on a verdict."
      />
    );
  }

  const shown = data.items.slice(0, MAX_DETECTORS_SHOWN);
  const hiddenCount = data.items.length - shown.length;
  const maxValue = Math.max(...data.items.flatMap((item) => [item.confirmed, item.dismissed]), 1);

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-4 text-xs text-[var(--color-text-lo)]">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--color-text-hi)" }} />
          Confirmed
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full border border-[var(--color-text-lo)]" />
          Dismissed
        </span>
      </div>
      <div className="flex flex-col gap-4">
        {shown.map((item) => (
          <div key={item.detector_key} className="flex flex-col gap-1.5">
            <p className="truncate font-mono text-xs text-[var(--color-text-hi)]" title={item.detector_key}>
              {item.detector_key}
              <span className="ml-2 text-[var(--color-text-lo)]">{item.detector_layer}</span>
            </p>
            <MeterRow
              label="Confirmed"
              value={item.confirmed}
              maxValue={maxValue}
              emphasized
              tooltip={`${item.detector_key}: ${item.confirmed} confirmed`}
              labelWidthClassName="w-20"
            />
            <MeterRow
              label="Dismissed"
              value={item.dismissed}
              maxValue={maxValue}
              tooltip={`${item.detector_key}: ${item.dismissed} dismissed`}
              labelWidthClassName="w-20"
            />
          </div>
        ))}
      </div>
      {hiddenCount > 0 && (
        <p className="text-xs text-[var(--color-text-lo)]">
          +{hiddenCount} more detector{hiddenCount === 1 ? "" : "s"} with feedback, not shown.
        </p>
      )}
      <p className="text-xs text-[var(--color-text-lo)]">Pooled across {data.total_tenants} tenants.</p>
    </div>
  );
}
