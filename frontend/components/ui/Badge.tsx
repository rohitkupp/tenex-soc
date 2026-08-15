import type { ReactNode } from "react";

interface BadgeProps {
  children: ReactNode;
  variant?: "neutral" | "outline";
  className?: string;
}

// Every non-severity badge in the product (dispositions, tags, statuses) — deliberately one
// neutral treatment, since docs/10 reserves color for severity alone.
export function Badge({ children, variant = "neutral", className = "" }: BadgeProps) {
  const base = "inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs";
  const styles =
    variant === "outline"
      ? "border border-[var(--color-border)] text-[var(--color-text-mid)]"
      : "border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-text-mid)]";
  return <span className={`${base} ${styles} ${className}`}>{children}</span>;
}
