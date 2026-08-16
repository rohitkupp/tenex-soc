/**
 * change 8: the LLM semantic domain-analysis pass — brand impersonation, typosquatting intent,
 * contextual relevance for destinations flagged rare or first-seen. Labelled with
 * `AnalystInsightBadge`, never `MLAnomalyBadge` — "never let a semantic judgement inherit the
 * statistical backing of a calibrated classifier."
 *
 * `AnalysisOverviewResponse.domain_semantic_findings` has no producer yet (see
 * `backend/app/schemas/overview.py::DomainSemanticFinding`'s docstring — the LLM call belongs in
 * `app/agent`, out of this milestone's ownership boundary) — this renders `null` when the list
 * is empty rather than an empty panel, so the overview page doesn't carry a permanently-blank
 * section. The moment that pass exists, this section starts rendering with no further UI work.
 */
import type { DomainSemanticFinding } from "@/lib/api/types";
import { Panel } from "@/components/ui/Panel";
import { AnalystInsightBadge } from "@/components/ui/SemanticFindingBadge";

export function SemanticFindingsPanel({ findings }: { findings: DomainSemanticFinding[] }) {
  if (findings.length === 0) return null;

  return (
    <Panel title="Analyst insights — domain semantics" padding="tight">
      <div className="flex flex-col gap-3 p-1">
        {findings.map((finding) => (
          <div key={finding.domain} className="flex flex-col gap-1 rounded-md border border-[var(--color-border)] p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-[var(--color-text-hi)]">{finding.domain}</span>
              <AnalystInsightBadge />
            </div>
            <p className="text-sm text-[var(--color-text-hi)]">{finding.assessment}</p>
            <p className="text-xs text-[var(--color-text-mid)]">{finding.rationale}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
