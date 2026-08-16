/**
 * change 8: two labels, never interchangeable — "never let a semantic judgement inherit the
 * statistical backing of a calibrated classifier." Both render through this one component so
 * there is exactly one place in the UI that decides how each label looks; nothing else in the
 * app constructs this badge's text independently.
 *
 * docs/10 reserves color exclusively for severity, so the two labels are distinguished by shape
 * (filled vs. outline `Badge` variant) and an explicit glyph, the same "shape, not a second
 * color" discipline `NarrativeBlock`'s citation chips already hold for verified/unverified.
 */
import { Badge } from "@/components/ui/Badge";
import { ML_ANOMALY_LABEL, SEMANTIC_INSIGHT_LABEL } from "@/lib/api/types";

export function MLAnomalyBadge() {
  return (
    <Badge variant="neutral" className="whitespace-nowrap">
      <span aria-hidden="true">◆</span> {ML_ANOMALY_LABEL}
    </Badge>
  );
}

export function AnalystInsightBadge() {
  return (
    <span title="LLM semantic assessment — not statistically calibrated">
      <Badge variant="outline" className="whitespace-nowrap">
        <span aria-hidden="true">◇</span> {SEMANTIC_INSIGHT_LABEL}
      </Badge>
    </span>
  );
}
