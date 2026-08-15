import type { Tier2OverviewResponse } from "@/lib/api/types";
import { StatGrid } from "@/components/ui/StatGrid";
import { formatPercent } from "@/lib/format";

export function OverviewStats({ overview }: { overview: Tier2OverviewResponse }) {
  return (
    <div className="flex flex-col gap-4">
      <StatGrid
        columns={3}
        stats={[
          { label: "Signatures", value: String(overview.total_signatures), mono: true },
          { label: "Tenants", value: String(overview.total_tenants), mono: true },
          { label: "Overlapping indicators", value: String(overview.total_overlapping_indicators), mono: true },
        ]}
      />
      {overview.by_incident_type.length > 0 && (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-lo)]">
              <th className="py-2 pr-4 font-normal">Incident type</th>
              <th className="py-2 pr-4 text-right font-normal">Signatures</th>
              <th className="py-2 pr-4 text-right font-normal">Tenants</th>
              <th className="py-2 text-right font-normal">Avg confidence</th>
            </tr>
          </thead>
          <tbody>
            {overview.by_incident_type.map((row) => (
              <tr key={row.incident_type} className="border-b border-[var(--color-border)] last:border-b-0">
                <td className="py-2 pr-4 text-[var(--color-text-hi)]">{row.incident_type}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.signature_count}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.tenant_count}</td>
                <td className="py-2 text-right font-mono text-[var(--color-text-hi)]">{formatPercent(row.avg_confidence)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
