import { severityColor, severityLabel } from "@/lib/severity";
import type { Severity } from "@/lib/api/types";

interface SeverityBarProps {
  severity: Severity | string | null | undefined;
  /** "sm" is the queue's dense row marker; "md" is the case file header's badge. */
  size?: "sm" | "md";
  showLabel?: boolean;
}

// The severity bar: the queue's single reserved use of color as encoding (docs/10). Every
// other pixel on this screen is neutral — this component is the whole allowance.
export function SeverityBar({ severity, size = "sm", showLabel = false }: SeverityBarProps) {
  const color = severityColor(severity);
  const label = severityLabel(severity);

  if (size === "md") {
    return (
      <span
        className="inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-medium"
        style={{ borderColor: color, color }}
      >
        <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
        {label}
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5" title={label} aria-label={`Severity: ${label}`}>
      <span aria-hidden="true" className="h-3.5 w-1 rounded-sm" style={{ backgroundColor: color }} />
      {showLabel && <span className="text-xs text-[var(--color-text-mid)]">{label}</span>}
    </span>
  );
}
