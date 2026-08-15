import type { ReactNode } from "react";

/**
 * Shared building blocks for every detector-specific explanation view. Bars are neutral
 * (`text-hi`/`text-lo` fills, never severity color — docs/10's color discipline applies to
 * ML internals too, not just the incident-level severity mark) so "how strong is this
 * feature's contribution" reads as magnitude, not as a second severity signal competing with
 * the real one.
 */

interface BarRowProps {
  label: string;
  valueLabel: string;
  /** 0..1, already clamped by the caller against whatever that detector's own natural scale is. */
  fraction: number;
  emphasized?: boolean;
  /** A secondary marker on the track, e.g. a per-feature threshold. 0..1. */
  markerFraction?: number;
  markerLabel?: string;
}

export function BarRow({ label, valueLabel, fraction, emphasized, markerFraction, markerLabel }: BarRowProps) {
  const clamped = Math.max(0, Math.min(1, fraction));
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-3 text-xs">
        <span className="truncate text-[var(--color-text-mid)]" title={label}>
          {label}
        </span>
        <span className="shrink-0 font-mono text-[var(--color-text-hi)]">{valueLabel}</span>
      </div>
      <div className="relative h-1.5 w-full rounded-full bg-[var(--color-surface-2)]">
        <div
          className="h-1.5 rounded-full"
          style={{
            width: `${clamped * 100}%`,
            backgroundColor: emphasized ? "var(--color-text-hi)" : "var(--color-text-lo)",
          }}
        />
        {markerFraction !== undefined && (
          <div
            className="absolute top-[-2px] h-2.5 w-px bg-[var(--color-text-mid)]"
            style={{ left: `${Math.max(0, Math.min(1, markerFraction)) * 100}%` }}
            title={markerLabel}
          />
        )}
      </div>
    </div>
  );
}

export function ExplanationSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2.5">
      <h4 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">{title}</h4>
      {children}
    </div>
  );
}

export function ExplanationNote({ children }: { children: ReactNode }) {
  return <p className="text-xs leading-relaxed text-[var(--color-text-mid)]">{children}</p>;
}

/** Signed contribution bars — magnitude drives width, sign drives which side of center. Used
 * by every SHAP/quadratic/deviation "per_feature" shape (iforest, mahalanobis, ecod, lof, the
 * L5 tree classifier), which all share the same `{feature, contribution}` wire shape. */
export function SignedBarRow({ label, contribution, maxAbs }: { label: string; contribution: number; maxAbs: number }) {
  const magnitude = maxAbs > 0 ? Math.min(1, Math.abs(contribution) / maxAbs) : 0;
  const positive = contribution >= 0;
  return (
    <div className="flex items-center gap-3 text-xs">
      <span className="w-40 shrink-0 truncate text-[var(--color-text-mid)]" title={label}>
        {label}
      </span>
      <div className="relative h-4 flex-1">
        <div className="absolute inset-y-0 left-1/2 w-px bg-[var(--color-border)]" />
        <div
          className="absolute inset-y-0 flex items-center"
          style={{
            left: positive ? "50%" : `${50 - magnitude * 50}%`,
            right: positive ? `${50 - magnitude * 50}%` : "50%",
          }}
        >
          <div
            className="h-2.5 w-full rounded-sm"
            style={{ backgroundColor: positive ? "var(--color-text-hi)" : "var(--color-text-lo)" }}
          />
        </div>
      </div>
      <span className="w-16 shrink-0 text-right font-mono text-[var(--color-text-hi)]">
        {contribution >= 0 ? "+" : ""}
        {contribution.toFixed(3)}
      </span>
    </div>
  );
}
