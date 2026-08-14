/**
 * M0 placeholder. Replaced by the analysis list + aggregate funnel at M15.
 * Server Component — no interactivity here yet, so no "use client".
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Health = {
  status: string;
  version: string;
  demo_mode: boolean;
  llm_enabled: boolean;
  dependencies: { name: string; ok: boolean }[];
};

async function fetchHealth(): Promise<Health | null> {
  try {
    const res = await fetch(`${API_URL}/api/health`, { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as Health;
  } catch {
    return null;
  }
}

export default async function Home() {
  const health = await fetchHealth();

  return (
    <main className="mx-auto max-w-2xl px-6 py-24">
      <h1 className="text-2xl font-semibold tracking-tight">Tenex SOC Analyst</h1>
      <p className="mt-3 max-w-prose text-[var(--color-text-mid)]">
        Raw security telemetry reduces through a layered funnel — rules, signal processing,
        entity-window models, sequence models, and a graph — into a handful of incidents an
        analyst can actually read.
      </p>

      <section className="mt-10 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
        <h2 className="text-sm font-medium text-[var(--color-text-mid)]">Backend</h2>
        {health === null ? (
          <p className="mt-2 font-mono text-sm text-[var(--color-severity-high)]">
            unreachable at {API_URL} — run <code>make up</code>
          </p>
        ) : (
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 font-mono text-sm">
            <dt className="text-[var(--color-text-lo)]">status</dt>
            <dd>{health.status}</dd>
            <dt className="text-[var(--color-text-lo)]">version</dt>
            <dd>{health.version}</dd>
            <dt className="text-[var(--color-text-lo)]">llm</dt>
            <dd>{health.llm_enabled ? "enabled" : "disabled (no API key or demo mode)"}</dd>
            {health.dependencies.map((d) => (
              <div key={d.name} className="contents">
                <dt className="text-[var(--color-text-lo)]">{d.name}</dt>
                <dd className={d.ok ? "text-[var(--color-accent-verified)]" : "text-[var(--color-severity-critical)]"}>
                  {d.ok ? "ok" : "down"}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>
    </main>
  );
}
