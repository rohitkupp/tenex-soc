import type { ReactNode } from "react";

interface PanelProps {
  title?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Case-file sections are generous; the queue and dense dashboards are tight (docs/10's
   * "density contrast is structural"). Padding is the one thing that varies by context. */
  padding?: "tight" | "generous";
}

// The one shared card shell — every new panel in this milestone (signals, response plan,
// models tables, learning cards, tier2 blocks) renders through this rather than re-deriving
// the border/surface/radius combination independently.
export function Panel({ title, right, children, className = "", padding = "generous" }: PanelProps) {
  const pad = padding === "generous" ? "p-5 sm:p-6" : "p-4";
  return (
    <section
      className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] ${pad} ${className}`}
    >
      {(title || right) && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-sm font-medium text-[var(--color-text-hi)]">{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}
