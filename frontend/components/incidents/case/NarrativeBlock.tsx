"use client";

/**
 * 3. Narrative — the signature element (docs/10). Numbered claims set in serif — the one
 * place in the product that font appears — each followed by its citation chips.
 *
 * docs/v2_migration change 7: citations are strings in one of two namespaces (`EVIDENCE-14`/
 * `BASELINE-3`/`LOG-1291` for measurements, `MITRE-*`/`ZSCALER-KB-*` for retrieved knowledge),
 * not bare event ids — `NarrativeStep.evidence_ids` replaced the pre-migration
 * `evidence_event_ids: number[]`. Two citation prefixes are interactive:
 *
 * - `EVIDENCE-n` — change 16: "the narrative cites `[EVIDENCE-14]`; clicking the citation
 *   scrolls to that card" — a plain anchor link to the matching card in this incident's Evidence
 *   section (`EvidenceSection`, which gives each card `id={evidenceCardAnchorId(evidence_id)}`).
 * - `LOG-n` — expands that raw log row inline, in mono, beneath the claim (the same interaction
 *   docs/10 describes), via `LogLineInspector` (change 16's `by-line` lookup).
 *
 * `BASELINE-n`/`MITRE-*`/`ZSCALER-KB-*` render as plain, non-interactive chips — this component
 * has no card or raw record of its own to jump to for those namespaces.
 *
 * A verified citation gets a hairline `accent-verified` underline; an unverified one gets a
 * neutral warning glyph and stays fully visible — docs/10 reserves color exclusively for
 * severity, with `accent-verified` as the one named exception for a *positive* verification —
 * inventing a matching color for the negative case would spend a second exception the doc never
 * grants, so the unverified state is neutral shape (dashed border + glyph), not color.
 */
import { useState } from "react";
import type { InvalidCitation, NarrativeStep } from "@/lib/api/types";
import { evidenceCardAnchorId } from "@/components/incidents/case/EvidenceSection";
import { LogLineInspector } from "@/components/events/LogLineInspector";

/** `app/agent/verifier.py::ClaimCheck.as_dict()`'s real shape is per-*claim*, not per-citation
 * — an entry names every citation on one claim plus which of them specifically failed which
 * check (`missing_ids`/`out_of_scope_ids`). A citation counts as invalid here when it appears in
 * any of an entry's id arrays and that entry did not pass every check clean. */
function invalidReason(invalid: InvalidCitation[], citationId: string): string | null {
  for (const entry of invalid) {
    const allPassed =
      entry.existence_ok !== false &&
      entry.numeric_ok !== false &&
      entry.retrieval_ok !== false &&
      entry.scope_ok !== false;
    const named =
      entry.evidence_ids?.includes(citationId) ||
      entry.missing_ids?.includes(citationId) ||
      entry.out_of_scope_ids?.includes(citationId);
    if (named && !allPassed) {
      return entry.reason ?? entry.claim ?? "Flagged by the citation verifier.";
    }
  }
  return null;
}

function chipStyle(reason: string | null) {
  return reason
    ? { border: "1px dashed var(--color-border)", color: "var(--color-text-mid)" }
    : {
        border: "1px solid var(--color-border)",
        borderBottom: "2px solid var(--color-accent-verified)",
        color: "var(--color-text-mid)",
      };
}

const CHIP_CLASS =
  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] transition-colors";

function ChipLabel({ citationId, reason }: { citationId: string; reason: string | null }) {
  return (
    <>
      {reason && <span aria-hidden="true">⚠</span>}
      {citationId}
    </>
  );
}

function CitationChip({
  citationId,
  reason,
  expanded,
  onToggle,
}: {
  citationId: string;
  reason: string | null;
  expanded: boolean;
  onToggle: () => void;
}) {
  if (citationId.startsWith("EVIDENCE-")) {
    return (
      <a
        href={`#${evidenceCardAnchorId(citationId)}`}
        className={`${CHIP_CLASS} hover:bg-[var(--color-surface-2)]`}
        style={chipStyle(reason)}
        title={reason ?? "Verified — click to view this evidence card"}
      >
        <ChipLabel citationId={citationId} reason={reason} />
      </a>
    );
  }

  if (citationId.startsWith("LOG-")) {
    return (
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className={`${CHIP_CLASS} ${expanded ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-2)]"}`}
        style={chipStyle(reason)}
        title={reason ?? "Verified — click to expand this log row"}
      >
        <ChipLabel citationId={citationId} reason={reason} />
      </button>
    );
  }

  // BASELINE-n / MITRE-* / ZSCALER-KB-* — informational only.
  return (
    <span className={CHIP_CLASS} style={chipStyle(reason)} title={reason ?? "Verified"}>
      <ChipLabel citationId={citationId} reason={reason} />
    </span>
  );
}

export function NarrativeBlock({
  narrative,
  invalidCitations,
  analysisId,
}: {
  narrative: NarrativeStep[];
  invalidCitations: InvalidCitation[];
  analysisId: string;
  /** Change 22's per-claim thumbs need an incident to post feedback against; omit this prop
   * (e.g. a narrative preview with no case file behind it yet) and the thumbs simply don't
   * render. */
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  if (narrative.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No narrative yet — this incident has not been triaged.</p>;
  }

  return (
    <ol className="flex max-w-[68ch] flex-col gap-6">
      {narrative.map((step) => {
        const logCitations = step.evidence_ids.filter((c) => c.startsWith("LOG-"));
        return (
          <li key={step.step} className="group flex flex-col gap-2">
            <p className="flex items-baseline gap-2 font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
              <span>
                <span className="mr-2 font-sans text-xs align-super text-[var(--color-text-lo)]">{step.step}</span>
                {step.claim}
              </span>
            </p>
            {step.evidence_ids.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pl-1">
                {step.evidence_ids.map((citationId) => {
                  const key = `${step.step}-${citationId}`;
                  return (
                    <CitationChip
                      key={citationId}
                      citationId={citationId}
                      reason={invalidReason(invalidCitations, citationId)}
                      expanded={expanded.has(key)}
                      onToggle={() => toggle(key)}
                    />
                  );
                })}
              </div>
            )}
            {logCitations
              .filter((citationId) => expanded.has(`${step.step}-${citationId}`))
              .map((citationId) => {
                const rawLineNo = Number(citationId.slice("LOG-".length));
                return (
                  <div key={citationId} className="pl-1">
                    <LogLineInspector analysisId={analysisId} rawLineNo={rawLineNo} />
                  </div>
                );
              })}
          </li>
        );
      })}
    </ol>
  );
}
