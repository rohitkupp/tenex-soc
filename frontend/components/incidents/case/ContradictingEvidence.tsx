// 4. Contradicting evidence — docs/10: "visually distinct block. The devil's-advocate output
// belongs above the fold, not hidden; it is what makes the verdict credible." Stays sans (the
// serif treatment is reserved for the narrative alone, docs/10: "it appears in exactly one
// place") — distinctness here comes from a dedicated bordered block and an explicit label,
// not from typography or a second color.
export function ContradictingEvidence({ text }: { text: string | null | undefined }) {
  if (!text) return null;
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
        Contradicting evidence — the case against this verdict
      </p>
      <p className="mt-2 max-w-[68ch] text-sm leading-relaxed text-[var(--color-text-hi)]">{text}</p>
    </div>
  );
}
