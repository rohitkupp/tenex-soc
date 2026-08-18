import type { EvidenceConfidenceBand } from "@/lib/api/types";

/**
 * The Anomalies-queue cell for `app.agent.confidence`'s rubric-derived score.
 *
 * Deliberately a separate component from the `Score` cell beside it, because the two numbers
 * answer different questions and the queue is the one place they sit next to each other. Score
 * is calibrated detector fusion — how unusual the traffic was. This is how well the evidence
 * supported the conclusion the agent drew about it. The interesting row is the one where they
 * disagree: a high score with low evidence confidence is the incident most worth a human's
 * attention, and an analyst can only see that if the two are legible as separate axes.
 *
 * Rendered as a band-coloured number rather than a bar. A bar would read as "more is better" on
 * a row that already has a severity bar meaning exactly that, and these two would then compete;
 * the colour carries the judgement and the digits carry the precision.
 *
 * `null` is an em dash, never 0.00. An incident that was never triaged, or whose triage never
 * reached the Judge, has no evidence assessment at all — showing zero would assert that its
 * evidence was examined and found worthless, which is a different and much stronger claim.
 */

const BAND_COLOR: Record<EvidenceConfidenceBand, string> = {
  high: "var(--color-accent-verified)",
  moderate: "var(--color-text-hi)",
  low: "var(--color-severity-medium)",
  very_low: "var(--color-severity-high)",
};

const BAND_LABEL: Record<EvidenceConfidenceBand, string> = {
  high: "High",
  moderate: "Moderate",
  low: "Low",
  very_low: "Very low",
};

export function EvidenceConfidenceCell({
  value,
  band,
}: {
  value: number | null;
  band: EvidenceConfidenceBand | null;
}) {
  if (value === null || value === undefined) {
    return (
      <span
        className="text-center font-mono text-xs text-[var(--color-text-lo)]"
        title="Not assessed — this incident was not triaged, or triage did not reach the Judge"
      >
        —
      </span>
    );
  }

  const resolved: EvidenceConfidenceBand =
    band ?? (value >= 0.75 ? "high" : value >= 0.5 ? "moderate" : value >= 0.25 ? "low" : "very_low");

  return (
    <span
      className="text-center font-mono text-xs"
      style={{ color: BAND_COLOR[resolved] }}
      title={`${BAND_LABEL[resolved]} evidence confidence — computed from the Judge's ten-item rubric, not written by the model. Separate from Score, which measures how unusual the traffic was.`}
    >
      {value.toFixed(2)}
    </span>
  );
}
