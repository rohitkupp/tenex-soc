import type { IndicatorOverlapEntryOut } from "@/lib/api/types";
import { formatCompactDate } from "@/lib/format";

// docs/13 M14: "Indicator overlap surfaces across two simulated tenants." Never a raw
// domain/IP — `indicator_hash` is an HMAC (docs/02), which is the entire privacy property
// this table depends on.
export function IndicatorOverlapTable({ items }: { items: IndicatorOverlapEntryOut[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No indicators seen across multiple tenants yet.</p>;
  }
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-lo)]">
          <th className="py-2 pr-4 font-normal">Indicator (HMAC)</th>
          <th className="py-2 pr-4 text-right font-normal">Tenants</th>
          <th className="py-2 pr-4 text-right font-normal">Signatures</th>
          <th className="py-2 pr-4 font-normal">Incident types</th>
          <th className="py-2 text-right font-normal">Last observed</th>
        </tr>
      </thead>
      <tbody>
        {items.map((row) => (
          <tr key={row.indicator_hash} className="border-b border-[var(--color-border)] last:border-b-0">
            <td className="py-2 pr-4 font-mono text-xs text-[var(--color-text-hi)]" title={row.indicator_hash}>
              {row.indicator_hash.slice(0, 16)}…
            </td>
            <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.tenant_count}</td>
            <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-hi)]">{row.signature_count}</td>
            <td className="py-2 pr-4 text-xs text-[var(--color-text-mid)]">{row.incident_types.join(", ")}</td>
            <td className="py-2 text-right font-mono text-xs text-[var(--color-text-hi)]">
              {formatCompactDate(row.last_observed_at)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
