/**
 * The one bar-mark primitive every Tier 2 chart in this folder draws with — hand-rolled SVG,
 * no charting library (CLAUDE.md's stack table). A single normalized-coordinate `<svg
 * viewBox="0 0 100 10">` per row: a full-width track and a value rect anchored to the left,
 * both rounded (`rx`), matching the app's existing bar-meter language (the old NL query box's
 * bar chart used the same "surface-2 track, filled value bar" shape in plain HTML divs — this
 * is that same visual idea, drawn in SVG instead).
 *
 * docs/10's design law — "color is reserved exclusively for severity encoding" — means these
 * charts cannot reach for a new hue to mark "the interesting bucket." `emphasized` instead
 * raises *contrast*: a bright `text-hi` fill + bold label for the row the chart wants to draw
 * the eye to, a dim `text-lo` fill + muted label otherwise. Never color alone, and never a
 * severity color repurposed to mean something it doesn't (severity colors stay reserved for
 * incident severity elsewhere in the app).
 */
export function MeterRow({
  label,
  value,
  maxValue,
  displayValue,
  emphasized = false,
  tooltip,
  labelWidthClassName = "w-40 sm:w-48",
}: {
  label: string;
  value: number;
  maxValue: number;
  displayValue?: string;
  emphasized?: boolean;
  tooltip?: string;
  /** Overrides (not appends to) the label column's width — the default fits a technique/
   * bucket name; a chart with a shorter, fixed label vocabulary (e.g. "Confirmed"/"Dismissed")
   * passes a narrower width so the bar itself gets more room. */
  labelWidthClassName?: string;
}) {
  const pct = maxValue > 0 ? Math.max(0, Math.min(100, (value / maxValue) * 100)) : 0;
  const fill = emphasized ? "var(--color-text-hi)" : "var(--color-text-lo)";
  const shown = displayValue ?? String(value);
  const title = tooltip ?? `${label}: ${shown}`;

  return (
    <div className="flex items-center gap-3">
      <div
        className={`shrink-0 truncate text-xs ${labelWidthClassName} ${
          emphasized ? "font-medium text-[var(--color-text-hi)]" : "text-[var(--color-text-mid)]"
        }`}
        title={label}
      >
        {label}
      </div>
      <svg viewBox="0 0 100 10" preserveAspectRatio="none" className="h-2.5 flex-1" role="img" aria-label={title}>
        <title>{title}</title>
        <rect x="0" y="0" width="100" height="10" rx="4" fill="var(--color-surface-2)" />
        {pct > 0 && <rect x="0" y="0" width={pct} height="10" rx="4" fill={fill} />}
      </svg>
      <div className="w-14 shrink-0 text-right font-mono text-xs text-[var(--color-text-hi)]">{shown}</div>
    </div>
  );
}
