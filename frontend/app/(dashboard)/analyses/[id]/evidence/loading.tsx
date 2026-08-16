// Loading skeleton, not a spinner — docs/10's quality floor.
export default function Loading() {
  return (
    <div className="flex flex-col gap-6">
      <div className="h-7 w-32 animate-pulse rounded bg-[var(--color-surface-2)]" />
      <div className="h-16 w-full animate-pulse rounded bg-[var(--color-surface-2)]" />
      <div className="flex flex-col gap-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-32 animate-pulse rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]" />
        ))}
      </div>
    </div>
  );
}
