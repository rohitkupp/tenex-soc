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
              <th className="py-2 pr-4 text-right font-normal" title="Calibrated detector fusion — how unusual the traffic was">
                Avg anomaly
              </th>
              {/* The cross-tenant version of the queue's Evidence column. Side by side these two
                  answer a question neither can alone: an incident type every tenant scores high
                  on but whose triages rest on thin evidence is a fleet-wide detection-quality
                  problem, not a fleet-wide threat. */}
              <th className="py-2 text-right font-normal" title="Judge rubric scored in code — how well the evidence supported the conclusion">
                Avg evidence
              </th>
            </tr>
          </thead>
          <tbody>
            {overview.by_incident_type.map((row) => (
              <tr key={row.incident_type} className="border-b border-[var(--color-border)] last:border-b-0">
                <td className="py-2 pr-4 text-[var(--color-text-hi)]">{row.incident_type}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.signature_count}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.tenant_count}</td>
                <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{formatPercent(row.avg_confidence)}</td>
                {/* Greyed when the mean rests on only a handful of graded signatures — AVG skips
                    NULLs, so without this a type where one signature of eighty was assessed would
                    present that single sample with the same authority as a full column. */}
                <td
                  className="py-2 text-right font-mono"
                  style={{
                    color:
                      row.evidence_confidence_count >= 5
                        ? "var(--color-text-hi)"
                        : "var(--color-text-lo)",
                  }}
                  title={
                    row.avg_evidence_confidence === null
                      ? "No signature of this type carries an evidence assessment yet"
                      : `Mean over ${row.evidence_confidence_count} assessed signature${row.evidence_confidence_count === 1 ? "" : "s"}`
                  }
                >
                  {row.avg_evidence_confidence === null ? "—" : formatPercent(row.avg_evidence_confidence)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
