/**
 * 6. Evidence — docs/v2_migration change 16 (primary view), sitting between Timeline and
 * Signals per that change's own placement instruction. Every `EvidencePayload` that contributed
 * to this incident (`GET /api/incidents/{id}/evidence`), rendered by the shared `EvidenceCard`.
 *
 * change 11's `highlight_lines` is surfaced here too: every contributing line across every card
 * is, by construction, a member of `highlight_lines` (the API derives one from the other) — this
 * component instead surfaces `highlight_line_violations`, the citations in the narrative above
 * that fell *outside* that attribution-derived set. A non-empty list means the presenter added a
 * line the evidence layer never nominated — a scope violation change 11 says must not be
 * silently rendered.
 */
import type { IncidentEvidenceResponse } from "@/lib/api/types";
import { EvidenceCard, evidenceCardAnchorId } from "@/components/evidence/EvidenceCard";

export { evidenceCardAnchorId };

export function EvidenceSection({
  data,
  analysisId,
  incidentId,
}: {
  data: IncidentEvidenceResponse | null;
  analysisId: string;
  incidentId: string;
}) {
  if (data === null) {
    return (
      <p className="text-sm text-[var(--color-text-mid)]">Evidence not available — the API is unreachable.</p>
    );
  }

  if (data.items.length === 0) {
    return (
      <p className="text-sm text-[var(--color-text-mid)]">
        No evidence extractor produced a payload in this incident&apos;s scope.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {data.highlight_line_violations.length > 0 && (
        <div className="rounded-md border border-[var(--color-severity-high)] bg-[var(--color-surface-1)] px-3 py-2 text-xs text-[var(--color-severity-high)]">
          Scope violation: the narrative cites line
          {data.highlight_line_violations.length === 1 ? "" : "s"}{" "}
          {data.highlight_line_violations.join(", ")} — outside the {data.highlight_lines.length}{" "}
          line{data.highlight_lines.length === 1 ? "" : "s"} this evidence actually attributes to
          this incident (docs/v2_migration change 11).
        </div>
      )}
      <div className="flex flex-col gap-3">
        {data.items.map((item) => (
          <EvidenceCard
            key={item.evidence_id}
            evidence={item}
            analysisId={analysisId}
            incidentId={incidentId}
            highlighted
          />
        ))}
      </div>
    </div>
  );
}
