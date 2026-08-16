// 8. Investigation guidance — docs/v2_migration change 20: the response action graph and
// enforcement plane were removed; `recommended_actions` is now free-text next-step guidance
// for the human analyst who picks this incident up, not action IDs from a catalog. Diagram 3
// calls this "Investigation guidance" — matched here verbatim. Same visual treatment as
// ContradictingEvidence (bordered block, explicit label) rather than the serif narrative
// typography, which stays reserved for the narrative alone.
export function InvestigationGuidance({ actions }: { actions: string[] | undefined }) {
  if (!actions || actions.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No guidance recorded for this incident.</p>;
  }
  return (
    <ul className="flex flex-col gap-2">
      {actions.map((action, i) => (
        <li
          key={i}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4 text-sm leading-relaxed text-[var(--color-text-hi)]"
        >
          {action}
        </li>
      ))}
    </ul>
  );
}
