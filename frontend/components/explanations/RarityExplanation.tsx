import type { RarityExplanationPayload } from "@/lib/api/types";
import { formatCompactDate } from "@/lib/format";
import { StatGrid } from "@/components/ui/StatGrid";
import { BarRow, ExplanationNote, ExplanationSection } from "./primitives";

// L2 — rarity / first-seen.
export function RarityExplanation({ explanation: e }: { explanation: RarityExplanationPayload }) {
  return (
    <ExplanationSection title="Domain rarity">
      <BarRow
        label={`${e.domain} — org-wide rarity`}
        valueLabel={e.domain_rarity.toFixed(3)}
        fraction={e.domain_rarity}
        emphasized
      />
      <StatGrid
        columns={3}
        stats={[
          { label: "Org-wide event count", value: String(e.org_wide_event_count), mono: true },
          { label: "Rare-count threshold", value: `≤ ${e.rare_count_threshold}`, mono: true },
          { label: "First seen", value: formatCompactDate(e.first_seen), mono: true },
          { label: "Principal", value: e.principal, mono: true },
          { label: "Events by principal", value: String(e.n_events_by_principal), mono: true },
          { label: "Novel pairing", value: e.user_novelty ? "yes" : "no", mono: true },
        ]}
      />
      <ExplanationNote>
        domain_rarity = 1 / (1 + org-wide event count) — a first-time visit to a domain almost nobody else in the
        org has ever reached is what actually decides this signal, not novelty alone.
      </ExplanationNote>
    </ExplanationSection>
  );
}
