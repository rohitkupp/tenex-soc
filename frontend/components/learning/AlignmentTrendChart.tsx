import type { AlignmentPointOut } from "@/lib/api/types";
import { formatCompactDate, formatPercent } from "@/lib/format";
import { Sparkline } from "@/components/ui/Sparkline";

// docs/10 /learning: "Alignment trend" — human/AI agreement rate over time.
export function AlignmentTrendChart({ points }: { points: AlignmentPointOut[] }) {
  if (points.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No feedback history yet.</p>;
  }
  const values = points.map((p) => p.alignment_pct);
  return (
    <div className="flex flex-wrap items-center gap-4">
      <Sparkline values={values} width={200} height={48} domain={[0, 1]} />
      <div className="flex flex-col gap-0.5 text-xs text-[var(--color-text-mid)]">
        <span>
          {formatCompactDate(points[0]?.period_start)} → {formatCompactDate(points[points.length - 1]?.period_end)}
        </span>
        <span>
          {formatPercent(values[0])} → <span className="text-[var(--color-text-hi)]">{formatPercent(values[values.length - 1])}</span>
        </span>
        {points.some((p) => p.synthetic) && <span className="text-[var(--color-text-lo)]">includes seeded demo data</span>}
      </div>
    </div>
  );
}
