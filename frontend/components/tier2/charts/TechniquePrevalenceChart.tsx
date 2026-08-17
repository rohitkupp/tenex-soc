import type { TechniquePrevalenceResponse } from "@/lib/api/tier2-charts";
import { MeterRow } from "./MeterRow";
import { InsufficientCrossTenantData } from "./InsufficientCrossTenantData";

// docs/09/CLAUDE.md: which of the 13 proxy-observable ATT&CK techniques (`data/kb/mitre/
// allowlist.yml` — never a fabricated id) appear in how many tenants. Always renders all 13,
// including ones observed in zero tenants so far — the absence is itself the finding
// ("11 of 13 knowable techniques have never been seen more than once"), not something to hide.
export function TechniquePrevalenceChart({ data }: { data: TechniquePrevalenceResponse }) {
  if (data.total_tenants_with_signatures < 2) {
    return (
      <InsufficientCrossTenantData
        tenantCount={data.total_tenants_with_signatures}
        detail="Technique prevalence can only distinguish systemic techniques from tenant-specific ones once more than one tenant has synced signatures."
      />
    );
  }

  const maxValue = Math.max(...data.items.map((item) => item.tenant_count), 1);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2.5">
        {data.items.map((item) => (
          <MeterRow
            key={item.technique_id}
            label={`${item.technique_id} — ${item.technique_name}`}
            value={item.tenant_count}
            maxValue={maxValue}
            displayValue={`${item.tenant_count}`}
            emphasized={item.tenant_count >= 2}
            tooltip={`${item.technique_id} — ${item.technique_name}: ${item.tenant_count} tenant${
              item.tenant_count === 1 ? "" : "s"
            }, ${item.signature_count} signature${item.signature_count === 1 ? "" : "s"}`}
          />
        ))}
      </div>
      <p className="text-xs text-[var(--color-text-lo)]">
        Bar length is tenant count, out of {data.total_tenants_with_signatures} tenants with any signature.
        Techniques seen by 2+ tenants are highlighted.
      </p>
    </div>
  );
}
