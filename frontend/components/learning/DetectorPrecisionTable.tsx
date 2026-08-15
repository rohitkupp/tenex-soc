import type { DetectorPrecisionPointOut } from "@/lib/api/types";
import { formatPercent } from "@/lib/format";
import { Sparkline } from "@/components/ui/Sparkline";

// docs/10 /learning: "per-detector precision" trend.
export function DetectorPrecisionTable({ points }: { points: DetectorPrecisionPointOut[] }) {
  if (points.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No per-detector precision history yet.</p>;
  }

  const byDetector = new Map<string, DetectorPrecisionPointOut[]>();
  for (const p of points) {
    const list = byDetector.get(p.detector_key) ?? [];
    list.push(p);
    byDetector.set(p.detector_key, list);
  }

  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-lo)]">
          <th className="py-2 pr-4 font-normal">Detector</th>
          <th className="py-2 pr-4 font-normal">Trend</th>
          <th className="py-2 text-right font-normal">Latest precision</th>
        </tr>
      </thead>
      <tbody>
        {[...byDetector.entries()].map(([key, series]) => {
          const latest = series[series.length - 1];
          return (
            <tr key={key} className="border-b border-[var(--color-border)] last:border-b-0">
              <td className="py-2 pr-4 font-mono text-xs text-[var(--color-text-hi)]">{key}</td>
              <td className="py-2 pr-4">
                <Sparkline values={series.map((s) => s.precision ?? 0)} domain={[0, 1]} />
              </td>
              <td className="py-2 text-right font-mono text-xs text-[var(--color-text-hi)]">
                {formatPercent(latest?.precision)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
