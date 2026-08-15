import type { UrlPathExplanationPayload } from "@/lib/api/types";
import { StatGrid } from "@/components/ui/StatGrid";
import { Badge } from "@/components/ui/Badge";
import { BarRow, ExplanationSection } from "./primitives";

// L2 — URL path analysis: path entropy and token-randomness against the domain's own
// population.
export function UrlPathExplanation({ explanation: e }: { explanation: UrlPathExplanationPayload }) {
  return (
    <ExplanationSection title="Path structure vs. this domain's own traffic">
      <BarRow
        label="Mean path entropy"
        valueLabel={e.mean_path_entropy.toFixed(2)}
        fraction={e.mean_path_entropy / Math.max(e.entropy_cutoff_p995 * 1.5, e.mean_path_entropy, 1)}
        emphasized={e.flagged_on_entropy}
        markerFraction={e.entropy_cutoff_p995 / Math.max(e.entropy_cutoff_p995 * 1.5, e.mean_path_entropy, 1)}
        markerLabel={`p99.5 cutoff ${e.entropy_cutoff_p995.toFixed(2)}`}
      />
      <BarRow
        label="High-entropy segment ratio"
        valueLabel={e.segment_random_ratio.toFixed(2)}
        fraction={e.segment_random_ratio}
        emphasized={e.flagged_on_segment_random}
        markerFraction={e.segment_random_cutoff_p995}
        markerLabel={`p99.5 cutoff ${e.segment_random_cutoff_p995.toFixed(2)}`}
      />
      <div className="flex flex-wrap items-center gap-1.5">
        {e.flagged_on_entropy && <Badge>flagged on entropy</Badge>}
        {e.flagged_on_segment_random && <Badge>flagged on segment randomness</Badge>}
      </div>
      <StatGrid
        columns={3}
        stats={[
          { label: "Requests", value: String(e.n_requests), mono: true },
          { label: "Domain population size", value: String(e.n_pairs_in_domain_population), mono: true },
          { label: "Source IP", value: e.src_ip, mono: true },
        ]}
      />
      {e.sample_paths.length > 0 && (
        <div className="flex flex-col gap-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3">
          <p className="text-xs text-[var(--color-text-lo)]">Sample paths</p>
          {e.sample_paths.slice(0, 5).map((path, i) => (
            <code key={i} className="truncate font-mono text-xs text-[var(--color-text-hi)]">
              {path}
            </code>
          ))}
        </div>
      )}
    </ExplanationSection>
  );
}
