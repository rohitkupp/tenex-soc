// Loading skeleton, not a spinner — docs/10's quality floor.
export default function Loading() {
  return (
    <div className="flex flex-col gap-6">
      <div className="h-7 w-40 animate-pulse rounded bg-[var(--color-surface-2)]" />
      <div className="h-8 w-full animate-pulse rounded bg-[var(--color-surface-2)]" />
      <div className="flex flex-col gap-px overflow-hidden rounded-lg border border-[var(--color-border)]">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-11 animate-pulse bg-[var(--color-surface-1)]" />
        ))}
      </div>
    </div>
  );
}
