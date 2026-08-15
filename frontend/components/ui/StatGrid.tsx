interface Stat {
  label: string;
  value: string;
  mono?: boolean;
}

// Label/value grid — the same `dl` pattern `/analyses/[id]` already established for pipeline
// stats, generalized so every stat block in the case file and dashboards shares it.
export function StatGrid({ stats, columns = 4 }: { stats: Stat[]; columns?: 2 | 3 | 4 }) {
  const colClass = columns === 2 ? "sm:grid-cols-2" : columns === 3 ? "sm:grid-cols-3" : "sm:grid-cols-4";
  return (
    <dl className={`grid grid-cols-2 gap-x-6 gap-y-3 text-sm ${colClass}`}>
      {stats.map((stat) => (
        <div key={stat.label}>
          <dt className="text-xs text-[var(--color-text-lo)]">{stat.label}</dt>
          <dd className={`mt-0.5 text-[var(--color-text-hi)] ${stat.mono ? "font-mono" : ""}`}>
            {stat.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
