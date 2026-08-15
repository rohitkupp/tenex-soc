// Loading skeleton, not a spinner — docs/10's quality floor.
export default function Loading() {
  return (
    <div className="flex flex-col gap-8">
      <div className="h-4 w-20 animate-pulse rounded bg-[var(--color-surface-2)]" />
      <div className="flex flex-col gap-3 border-b border-[var(--color-border)] pb-6">
        <div className="h-8 w-2/3 animate-pulse rounded bg-[var(--color-surface-2)]" />
        <div className="h-5 w-40 animate-pulse rounded bg-[var(--color-surface-2)]" />
      </div>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex flex-col gap-2">
          <div className="h-3 w-24 animate-pulse rounded bg-[var(--color-surface-2)]" />
          <div className="h-16 w-full animate-pulse rounded bg-[var(--color-surface-1)]" />
        </div>
      ))}
    </div>
  );
}
