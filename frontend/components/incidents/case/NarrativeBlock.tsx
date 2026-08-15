"use client";

/**
 * 3. Narrative — the signature element (docs/10). Numbered claims set in serif — the one
 * place in the product that font appears — each followed by its citation chips. Clicking a
 * chip expands that event inline, beneath the claim it supports, in mono, without navigating
 * away. A verified citation gets a hairline `accent-verified` underline; an unverified one
 * gets a neutral warning glyph and stays fully visible — the docstring in `lib/api/types.ts`
 * explains why this uses a glyph rather than a second color: docs/10 reserves color exclusively
 * for severity, with `accent-verified` as the one named exception for a *positive*
 * verification — inventing a matching color for the negative case would spend a second
 * exception the doc never grants, so the unverified state is neutral shape (dashed border +
 * glyph), not color.
 */
import { useState } from "react";
import type { InvalidCitation, NarrativeStep } from "@/lib/api/types";
import { EventInspector } from "@/components/events/EventInspector";

function isInvalid(invalid: InvalidCitation[], step: number, eventId: number): string | null {
  const hit = invalid.find(
    (c) => c.evidence_event_id === eventId && (c.step === undefined || c.step === step),
  );
  return hit?.reason ?? null;
}

export function NarrativeBlock({
  narrative,
  invalidCitations,
}: {
  narrative: NarrativeStep[];
  invalidCitations: InvalidCitation[];
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
      {narrative.map((step) => (
        <li key={step.step} className="flex flex-col gap-2">
          <p className="font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
            <span className="mr-2 font-sans text-xs align-super text-[var(--color-text-lo)]">{step.step}</span>
            {step.claim}
          </p>
          {step.evidence_event_ids.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 pl-1">
              {step.evidence_event_ids.map((eventId) => {
                const reason = isInvalid(invalidCitations, step.step, eventId);
                const key = `${step.step}-${eventId}`;
                const isOpen = expanded.has(key);
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => toggle(key)}
                    aria-expanded={isOpen}
                    title={reason ?? "Verified"}
                    className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] transition-colors ${
                      isOpen ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-2)]"
                    }`}
                    style={
                      reason
                        ? { border: "1px dashed var(--color-border)", color: "var(--color-text-mid)" }
                        : {
                            border: "1px solid var(--color-border)",
                            borderBottom: "2px solid var(--color-accent-verified)",
                            color: "var(--color-text-mid)",
                          }
                    }
                  >
                    {reason && <span aria-hidden="true">⚠</span>}#{eventId}
                  </button>
                );
              })}
            </div>
          )}
          {step.evidence_event_ids
            .filter((eventId) => expanded.has(`${step.step}-${eventId}`))
            .map((eventId) => (
              <div key={eventId} className="pl-1">
                <EventInspector eventId={eventId} />
              </div>
            ))}
        </li>
      ))}
    </ol>
  );
}
