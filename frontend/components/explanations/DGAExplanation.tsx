import type { DGAExplanationPayload } from "@/lib/api/types";
import { humanizeKey } from "@/lib/format";
import { BarRow, ExplanationNote, ExplanationSection } from "./primitives";

// L2 — domain entropy / DGA: the logistic feature contributions behind the score (docs/10:
// "the feature contributions").
export function DGAExplanation({ explanation: e }: { explanation: DGAExplanationPayload }) {
  const features: Array<{ key: keyof typeof e; label: string; value: number }> = [
    { key: "shannon_entropy", label: "Shannon entropy", value: e.shannon_entropy },
    { key: "neg_ngram_log_likelihood", label: "Negative n-gram log-likelihood", value: e.neg_ngram_log_likelihood },
    { key: "digit_ratio", label: "Digit ratio", value: e.digit_ratio },
    { key: "max_consonant_run", label: "Max consonant run", value: e.max_consonant_run },
    { key: "len_norm", label: "Length (normalized)", value: e.len_norm },
  ];
  const contributions = features.map((f) => ({ ...f, weighted: f.value * (e.weights[f.key] ?? 0) }));
  const maxAbs = Math.max(1e-9, ...contributions.map((f) => Math.abs(f.weighted)));

  return (
    <ExplanationSection title="Feature contributions">
      <div className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
        <span>
          Domain <span className="font-mono text-[var(--color-text-hi)]">{e.domain}</span> (label scored:{" "}
          <span className="font-mono text-[var(--color-text-hi)]">{e.second_level_label}</span>, .{e.tld})
        </span>
      </div>
      <div className="flex flex-col gap-3">
        {contributions.map((f) => (
          <BarRow
            key={f.key}
            label={`${humanizeKey(f.label)} × weight`}
            valueLabel={f.weighted.toFixed(3)}
            fraction={Math.abs(f.weighted) / maxAbs}
            emphasized={Math.abs(f.weighted) > maxAbs * 0.5}
          />
        ))}
      </div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-[var(--color-text-mid)]">
          score = sigmoid(Σ weight·feature + intercept {e.intercept.toFixed(2)})
        </span>
        <span className="font-mono text-[var(--color-text-hi)]">
          {e.score.toFixed(3)} / threshold {e.decision_threshold.toFixed(2)}
        </span>
      </div>
      {e.hostnames.length > 0 && (
        <ExplanationNote>
          Scored once for the registrable domain, pooled from {e.hostnames.length} hostname
          {e.hostnames.length === 1 ? "" : "s"}:{" "}
          <span className="font-mono text-[var(--color-text-hi)]">{e.hostnames.slice(0, 5).join(", ")}</span>
          {e.hostnames.length > 5 ? ` +${e.hostnames.length - 5} more` : ""}
        </ExplanationNote>
      )}
    </ExplanationSection>
  );
}
