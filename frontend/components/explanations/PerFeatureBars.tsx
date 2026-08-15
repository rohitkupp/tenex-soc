import type { PerFeatureContributionExplanation } from "@/lib/api/types";
import { humanizeKey } from "@/lib/format";
import { ExplanationNote, ExplanationSection, SignedBarRow } from "./primitives";

interface PerFeatureBarsProps {
  explanation: PerFeatureContributionExplanation;
  /** Same wire shape, different underlying math (docs/10 treats these as distinct detector
   * families even though the payload is byte-identical) — this is what tells them apart in
   * the UI: title, and the one sentence of "what a contribution here means." */
  flavor: "iforest" | "mahalanobis" | "ecod" | "lof" | "tree";
}

const FLAVOR_COPY: Record<PerFeatureBarsProps["flavor"], { title: string; note: string }> = {
  iforest: {
    title: "SHAP attribution — Isolation Forest",
    note: "TreeExplainer SHAP values on the isolation score, sign-corrected so positive means \"pushed toward flagged.\"",
  },
  mahalanobis: {
    title: "Per-feature contribution — Mahalanobis distance",
    note: "Each term is that feature's own additive share of the total squared distance from the robust benign center; terms sum to the total score.",
  },
  ecod: {
    title: "Per-dimension tail score — ECOD",
    note: "ECOD's own per-dimension empirical-CDF tail score, not a post-hoc approximation.",
  },
  lof: {
    title: "Neighbor-distance deviation — Local Outlier Factor",
    note: "This row's deviation from the mean of its own k nearest benign neighbors, per feature. Total score is LOF's own density ratio, not implied by summing these terms.",
  },
  tree: {
    title: "SHAP attribution — technique classifier",
    note: "TreeExplainer SHAP values for the predicted MITRE technique class.",
  },
};

// L3 (iforest/mahalanobis/ecod/lof) and L5 (tree classifier) — every one of these detectors
// returns the identical `{total_score, per_feature: [{feature, contribution}]}` shape on the
// wire; this is the one shared renderer for all of them (docs/10: "LOF/ECOD -> their own
// explanation shapes" / "tree models -> SHAP bars" — distinguished here by framing and
// wording, since the real payloads are structurally the same).
export function PerFeatureBars({ explanation, flavor }: PerFeatureBarsProps) {
  const copy = FLAVOR_COPY[flavor];
  const maxAbs = Math.max(1e-9, ...explanation.per_feature.map((f) => Math.abs(f.contribution)));
  return (
    <ExplanationSection title={copy.title}>
      <div className="flex flex-col gap-2">
        {explanation.per_feature.map((f) => (
          <SignedBarRow key={f.feature} label={humanizeKey(f.feature)} contribution={f.contribution} maxAbs={maxAbs} />
        ))}
      </div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-[var(--color-text-mid)]">Total score</span>
        <span className="font-mono text-[var(--color-text-hi)]">{explanation.total_score.toFixed(3)}</span>
      </div>
      <ExplanationNote>{copy.note}</ExplanationNote>
    </ExplanationSection>
  );
}
