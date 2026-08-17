/**
 * change 10 Level 1 ("what happened"): the executive summary, over change 9's deterministic
 * overview stats — "an analyst should understand the file in ten seconds." Path A (change 14),
 * `app.agent.orchestrator.narrate_analysis`, one LLM call.
 *
 * Renders on load, with no button and no fetch of its own. The `triage` stage has always made
 * this call once per analysis; it now persists the result to `analyses.narrative*`, so the
 * summary the analyst reads is the one the pipeline already generated and paid for. This used
 * to be a "Generate executive summary" button precisely because that result was discarded —
 * the only way to see a narrative was to buy a second one, and it was lost again on reload.
 *
 * A server component: there is nothing to interact with, and the text arrives with the
 * overview payload the page already fetches.
 */
import type { StoredNarrative } from "@/lib/api/types";
import { formatDate, formatUsd } from "@/lib/format";

export function ExecutiveSummary({ narrative }: { narrative: StoredNarrative | null }) {
  if (!narrative) {
    return (
      <p className="text-sm text-[var(--color-text-mid)]">
        No executive summary — the Narrator has not run for this analysis yet. It runs
        automatically as part of the triage stage.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
        {narrative.executive_summary}
      </p>
      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-lo)]">
        {narrative.citation_valid === false && (
          // CLAUDE.md rule 6: an unverified claim is flagged, never silently rendered as fact.
          <span className="text-[var(--color-severity-high)]">
            {narrative.invalid_citation_count} claim
            {narrative.invalid_citation_count === 1 ? "" : "s"} failed citation verification
          </span>
        )}
        {narrative.model && <span>{narrative.model}</span>}
        {narrative.cost_usd !== null && <span>{formatUsd(narrative.cost_usd)}</span>}
        {narrative.generated_at && <span>generated {formatDate(narrative.generated_at)}</span>}
      </div>
    </div>
  );
}
