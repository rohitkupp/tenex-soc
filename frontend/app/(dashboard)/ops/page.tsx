import type { Metadata } from "next";
import { fetchServer } from "@/lib/api/server";
import type { DeadLettersResponse, QueuesResponse } from "@/lib/api/types";
import { OpsDashboard } from "@/components/ops/OpsDashboard";

export const metadata: Metadata = { title: "Ops — Tenex SOC Analyst" };

// Server-fetched initial data means the first paint is real content, not a
// loading skeleton (docs/10's quality floor) — the client component below
// only needs a skeleton-free polling loop on top of it.
export default async function OpsPage() {
  const [queues, deadLetters] = await Promise.all([
    fetchServer<QueuesResponse>("/api/ops/queues"),
    fetchServer<DeadLettersResponse>("/api/ops/dead-letters"),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Ops</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          Queue depths and dead-lettered messages across every worker.
        </p>
      </div>
      <OpsDashboard initialQueues={queues} initialDeadLetters={deadLetters} />
    </div>
  );
}
