"use client";

/**
 * `/ops` — docs/09's ops endpoints, docs/10: "Dense and functional, not
 * decorative — this is an operator view." Polls both lists on an interval
 * so queue depth and dead-letter counts stay current without a manual
 * reload; retry is the one mutating action here, so it goes through
 * `apiFetch`, which already attaches the CSRF header for POST
 * (`lib/api/client.ts`) — no special-casing needed here.
 */
import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api/client";
import type { DeadLettersResponse, QueuesResponse } from "@/lib/api/types";
import { QueueDepthTable } from "./QueueDepthTable";
import { DeadLetterTable } from "./DeadLetterTable";

const POLL_MS = 5000;

interface OpsDashboardProps {
  initialQueues: QueuesResponse | null;
  initialDeadLetters: DeadLettersResponse | null;
}

export function OpsDashboard({ initialQueues, initialDeadLetters }: OpsDashboardProps) {
  const [queues, setQueues] = useState(initialQueues);
  const [deadLetters, setDeadLetters] = useState(initialDeadLetters);
  const [queuesUnreachable, setQueuesUnreachable] = useState(initialQueues === null);
  const [deadLettersUnreachable, setDeadLettersUnreachable] = useState(
    initialDeadLetters === null,
  );
  const [lastUpdated, setLastUpdated] = useState<Date | null>(
    initialQueues || initialDeadLetters ? new Date() : null,
  );

  const refresh = useCallback(async () => {
    const [queuesResult, deadLettersResult] = await Promise.allSettled([
      apiFetch<QueuesResponse>("/api/ops/queues"),
      apiFetch<DeadLettersResponse>("/api/ops/dead-letters"),
    ]);

    if (queuesResult.status === "fulfilled") {
      setQueues(queuesResult.value);
      setQueuesUnreachable(false);
    } else {
      setQueuesUnreachable(true);
    }

    if (deadLettersResult.status === "fulfilled") {
      setDeadLetters(deadLettersResult.value);
      setDeadLettersUnreachable(false);
    } else {
      setDeadLettersUnreachable(true);
    }

    setLastUpdated(new Date());
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      void refresh();
    }, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const retryDeadLetter = useCallback(
    async (id: string) => {
      await apiFetch<unknown>(`/api/ops/dead-letters/${id}/retry`, { method: "POST" });
      await refresh();
    },
    [refresh],
  );

  return (
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium text-[var(--color-text-hi)]">Queue depth</h2>
          {lastUpdated && (
            <span className="text-xs text-[var(--color-text-lo)]">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
        <QueueDepthTable queues={queues?.queues ?? null} unreachable={queuesUnreachable} />
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-[var(--color-text-hi)]">Dead letters</h2>
        <DeadLetterTable
          items={deadLetters?.items ?? null}
          unreachable={deadLettersUnreachable}
          onRetry={retryDeadLetter}
        />
      </section>
    </div>
  );
}
