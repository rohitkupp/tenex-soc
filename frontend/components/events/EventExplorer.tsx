"use client";

/**
 * `/analyses/[id]/events` — docs/10: "Raw event explorer, filterable, signal-bearing rows
 * marked." Filterable and paginated per docs/09's `GET /api/analyses/{id}/events` (keyset
 * cursor, hot-column filters). "Signal-bearing rows marked" is not implemented as a per-row
 * visual: `EventListItem` (`backend/app/schemas/event.py`) carries no such flag, and
 * `has_signal` in the API is a query *filter*, not a response field — `events.py`'s own
 * module docstring calls this "a documented stub" (the `signals` table doesn't exist from
 * this route's perspective yet). The filter itself is still wired below, honestly: toggling
 * it sends `has_signal=true` and will currently return zero rows against the live backend,
 * which is the real, current behavior, not a fabricated marker.
 */
import { Fragment, useCallback, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { EventListItem, EventListResponse } from "@/lib/api/types";
import { formatDate } from "@/lib/format";
import { EventInspector } from "./EventInspector";

interface Filters {
  principal: string;
  domain: string;
  src_ip: string;
  action: string;
  has_signal: boolean;
}

const EMPTY_FILTERS: Filters = { principal: "", domain: "", src_ip: "", action: "", has_signal: false };

function buildQuery(analysisId: string, filters: Filters, cursor: string | null): string {
  const params = new URLSearchParams();
  if (filters.principal) params.set("principal", filters.principal);
  if (filters.domain) params.set("domain", filters.domain);
  if (filters.src_ip) params.set("src_ip", filters.src_ip);
  if (filters.action) params.set("action", filters.action);
  if (filters.has_signal) params.set("has_signal", "true");
  if (cursor) params.set("cursor", cursor);
  params.set("limit", "100");
  return `/api/analyses/${analysisId}/events?${params.toString()}`;
}

export function EventExplorer({
  analysisId,
  initial,
}: {
  analysisId: string;
  initial: EventListResponse | null;
}) {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [events, setEvents] = useState<EventListItem[]>(initial?.items ?? []);
  const [cursor, setCursor] = useState<string | null>(initial?.next_cursor ?? null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runQuery = useCallback(
    async (nextFilters: Filters, append: boolean) => {
      setLoading(true);
      setError(null);
      try {
        const res = await apiFetch<EventListResponse>(
          buildQuery(analysisId, nextFilters, append ? cursor : null),
        );
        setEvents((prev) => (append ? [...prev, ...res.items] : res.items));
        setCursor(res.next_cursor);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : "Could not reach the API.");
      } finally {
        setLoading(false);
      }
    },
    [analysisId, cursor],
  );

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    void runQuery(filters, false);
  }

  const inputClass =
    "rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-xs text-[var(--color-text-hi)]";

  return (
    <div className="flex flex-col gap-4">
      <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-lo)]">
          Principal
          <input
            className={inputClass}
            value={filters.principal}
            onChange={(e) => setFilters((f) => ({ ...f, principal: e.target.value }))}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-lo)]">
          Domain
          <input
            className={inputClass}
            value={filters.domain}
            onChange={(e) => setFilters((f) => ({ ...f, domain: e.target.value }))}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-lo)]">
          Source IP
          <input
            className={inputClass}
            value={filters.src_ip}
            onChange={(e) => setFilters((f) => ({ ...f, src_ip: e.target.value }))}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-lo)]">
          Action
          <input
            className={inputClass}
            value={filters.action}
            onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
          />
        </label>
        <label className="flex items-center gap-1.5 pb-2 text-xs text-[var(--color-text-lo)]" title="Documented stub — currently returns zero rows against the live backend.">
          <input
            type="checkbox"
            checked={filters.has_signal}
            onChange={(e) => setFilters((f) => ({ ...f, has_signal: e.target.checked }))}
          />
          Signal-bearing only
        </label>
        <button
          type="submit"
          disabled={loading}
          className="rounded-md bg-[var(--color-text-hi)] px-3 py-1.5 text-xs font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
        >
          Apply filters
        </button>
      </form>

      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}

      {events.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-14 text-center">
          <p className="text-sm text-[var(--color-text-mid)]">No events match these filters.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
          <table className="w-full min-w-[720px] border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)] text-left text-[var(--color-text-lo)]">
                <th className="px-3 py-2 font-normal">Time</th>
                <th className="px-3 py-2 font-normal">Principal</th>
                <th className="px-3 py-2 font-normal">Domain</th>
                <th className="px-3 py-2 font-normal">Src IP</th>
                <th className="px-3 py-2 font-normal">Action</th>
                <th className="px-3 py-2 font-normal">Status</th>
                <th className="px-3 py-2 font-normal">Bytes out</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <Fragment key={event.id}>
                  <tr
                    onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
                    className="cursor-pointer border-b border-[var(--color-border)] bg-[var(--color-surface-1)] transition-colors last:border-b-0 hover:bg-[var(--color-surface-2)]"
                  >
                    <td className="px-3 py-2 font-mono text-[var(--color-text-hi)]">{formatDate(event.ts)}</td>
                    <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.principal ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.domain ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.src_ip ?? "—"}</td>
                    <td className="px-3 py-2 text-[var(--color-text-mid)]">{event.action ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.status_code ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.bytes_out ?? "—"}</td>
                  </tr>
                  {expandedId === event.id && (
                    <tr>
                      <td colSpan={7} className="bg-[var(--color-surface-0)] p-3">
                        <EventInspector eventId={event.id} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {cursor && (
        <button
          type="button"
          disabled={loading}
          onClick={() => void runQuery(filters, true)}
          className="w-fit rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
        >
          {loading ? "Loading…" : "Load more"}
        </button>
      )}
    </div>
  );
}
