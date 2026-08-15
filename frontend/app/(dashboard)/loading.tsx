// Loading skeleton, not a spinner — docs/10's quality floor.
export default function Loading() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="h-7 w-32 animate-pulse rounded bg-[var(--color-surface-2)]" />
        <div className="h-9 w-40 animate-pulse rounded-md bg-[var(--color-surface-2)]" />
      </div>
      <div className="flex flex-col gap-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-16 animate-pulse rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)]"
          />
        ))}
      </div>
    </div>
  );
}
