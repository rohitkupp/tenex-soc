import type { ReliabilityBinOut } from "@/lib/api/types";

const SIZE = 280;
const PAD = 28;
const PLOT = SIZE - PAD * 2;

function toXY(bin: ReliabilityBinOut): [number, number] | null {
  if (bin.predicted_mean === null || bin.observed_precision === null) return null;
  return [PAD + bin.predicted_mean * PLOT, PAD + (1 - bin.observed_precision) * PLOT];
}

/**
 * Predicted confidence vs. observed precision, 10 calibration bins (docs/12), plotted against
 * the perfect-calibration diagonal. Two series share one chart: "before" (hollow, faint) is
 * the raw detector score; "after" (filled) is the same bins post isotonic refit — the visual
 * point of the whole page is watching "after" points move toward the diagonal.
 */
export function ReliabilityDiagram({
  before,
  after,
}: {
  before: ReliabilityBinOut[];
  after: ReliabilityBinOut[];
}) {
  const beforePoints = before.map(toXY).filter((p): p is [number, number] => p !== null);
  const afterPoints = after.map(toXY).filter((p): p is [number, number] => p !== null);

  return (
    <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="h-64 w-64" role="img" aria-label="Reliability diagram">
      <line x1={PAD} y1={PAD + PLOT} x2={PAD + PLOT} y2={PAD} stroke="var(--color-border)" strokeDasharray="3 3" />
      <line x1={PAD} y1={PAD + PLOT} x2={PAD + PLOT} y2={PAD + PLOT} stroke="var(--color-border)" />
      <line x1={PAD} y1={PAD + PLOT} x2={PAD} y2={PAD} stroke="var(--color-border)" />
      <text x={PAD + PLOT / 2} y={SIZE - 6} textAnchor="middle" fontSize={9} fill="var(--color-text-lo)">
        predicted confidence
      </text>
      <text
        x={10}
        y={PAD + PLOT / 2}
        textAnchor="middle"
        fontSize={9}
        fill="var(--color-text-lo)"
        transform={`rotate(-90 10 ${PAD + PLOT / 2})`}
      >
        observed precision
      </text>

      {beforePoints.map(([x, y], i) => (
        <circle key={`b${i}`} cx={x} cy={y} r={3.5} fill="none" stroke="var(--color-text-lo)" strokeWidth={1.5} />
      ))}
      {afterPoints.map(([x, y], i) => (
        <circle key={`a${i}`} cx={x} cy={y} r={3.5} fill="var(--color-text-hi)" />
      ))}

      {beforePoints.length === 0 && afterPoints.length === 0 && (
        <text x={SIZE / 2} y={SIZE / 2} textAnchor="middle" fontSize={10} fill="var(--color-text-lo)">
          Not enough labeled feedback to fit yet.
        </text>
      )}
    </svg>
  );
}
