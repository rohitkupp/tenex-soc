interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  /** Fixed 0..1 domain (percentages/rates) vs. auto-scaled to the data's own min/max. */
  domain?: [number, number];
}

// A minimal trend line — neutral (never severity color; trend direction is read from shape,
// not from color), used for alignment and per-detector precision over time.
export function Sparkline({ values, width = 120, height = 28, domain }: SparklineProps) {
  if (values.length === 0) {
    return <span className="text-xs text-[var(--color-text-lo)]">—</span>;
  }
  if (values.length === 1) {
    return (
      <svg width={width} height={height} role="img" aria-label="Single data point">
        <circle cx={width / 2} cy={height / 2} r={2} fill="var(--color-text-mid)" />
      </svg>
    );
  }

  const [lo, hi] = domain ?? [Math.min(...values), Math.max(...values)];
  const span = hi - lo || 1;
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * (width - 4) + 2;
      const y = height - 2 - ((v - lo) / span) * (height - 4);
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg width={width} height={height} role="img" aria-label="Trend">
      <polyline points={points} fill="none" stroke="var(--color-text-mid)" strokeWidth={1.5} />
    </svg>
  );
}
