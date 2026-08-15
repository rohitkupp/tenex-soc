import type { Severity } from "./api/types";

/**
 * The one place severity maps to color (docs/10: "colour is reserved exclusively for
 * severity encoding" — every consumer of this module is spending that one allowance).
 * Values match `app/globals.css`'s `--color-severity-*` tokens exactly.
 */
export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function severityColor(severity: Severity | string | null | undefined): string {
  if (severity && severity in SEVERITY_VAR) return SEVERITY_VAR[severity as Severity];
  return "var(--color-text-lo)";
}

export function severityLabel(severity: Severity | string | null | undefined): string {
  if (severity && severity in SEVERITY_LABEL) return SEVERITY_LABEL[severity as Severity];
  return "Unknown";
}

export function isSeverity(value: string | null | undefined): value is Severity {
  return !!value && (SEVERITY_ORDER as readonly string[]).includes(value);
}

const DISPOSITION_LABEL: Record<string, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign: "Benign",
  needs_review: "Needs review",
};

export function dispositionLabel(disposition: string | null | undefined): string {
  if (!disposition) return "Untriaged";
  return DISPOSITION_LABEL[disposition] ?? disposition;
}
