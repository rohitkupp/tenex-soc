"use client";

/**
 * `/analyses/[id]/events` — docs/10: "Raw event explorer, filterable, signal-bearing rows
 * marked." Filterable and paginated per docs/09's `GET /api/analyses/{id}/events` (keyset
 * cursor, hot-column filters).
 *
 * M15: signal-bearing rows are now a real per-row visual (`EventListItem` gained
 * `signal_count`/`max_confidence`/`detectors` — see `lib/api/types.ts`), and `has_signal`
 * genuinely filters instead of always returning zero rows. Highlighting never relies on
 * colour alone: a flagged row gets a `severity-high` left-edge accent (the same token the
 * app already uses for "this needs attention" outside strict incident severity, e.g. this
 * file's own error text below) *plus* a labelled "Flagged" badge and bolder time text, so a
 * colour-blind reader or a screen reader gets the same signal a sighted scan does. Clicking
 * a row expands `EventInspector`, which now renders each attached signal's `explanation`
 * through the shared `ExplanationRenderer` — the "why" the brief asks for.
 */
import { Fragment, useCallback, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { EventListItem, EventListResponse } from "@/lib/api/types";
import { formatDate, formatScore } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";
import { EventInspector } from "./EventInspector";

type SignalFilter = "all" | "signal" | "no_signal";

interface Filters {
  principal: string;
  domain: string;
  src_ip: string;
  action: string;
  signal: SignalFilter;
}

const EMPTY_FILTERS: Filters = { principal: "", domain: "", src_ip: "", action: "", signal: "all" };

function buildQuery(analysisId: string, filters: Filters, cursor: string | null): string {
  const params = new URLSearchParams();
  if (filters.principal) params.set("principal", filters.principal);
  if (filters.domain) params.set("domain", filters.domain);
  if (filters.src_ip) params.set("src_ip", filters.src_ip);
  if (filters.action) params.set("action", filters.action);
  if (filters.signal === "signal") params.set("has_signal", "true");
  if (filters.signal === "no_signal") params.set("has_signal", "false");
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
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-lo)]">
          Signals
          <select
            className={inputClass}
            value={filters.signal}
            onChange={(e) => setFilters((f) => ({ ...f, signal: e.target.value as SignalFilter }))}
          >
            <option value="all">All events</option>
            <option value="signal">Signal-bearing only</option>
            <option value="no_signal">No signal only</option>
          </select>
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
          <table className="w-full min-w-[900px] border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)] text-left text-[var(--color-text-lo)]">
                <th className="px-3 py-2 font-normal">Time</th>
                <th className="px-3 py-2 font-normal">Principal</th>
                <th className="px-3 py-2 font-normal">Domain</th>
                <th className="px-3 py-2 font-normal">Src IP</th>
                <th className="px-3 py-2 font-normal">Action</th>
                <th className="px-3 py-2 font-normal">Status</th>
                <th className="px-3 py-2 font-normal">Bytes out</th>
                <th className="px-3 py-2 font-normal">Confidence</th>
                <th className="px-3 py-2 font-normal">Flagged by</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const flagged = event.signal_count > 0;
                return (
                  <Fragment key={event.id}>
                    <tr
                      onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
                      aria-expanded={expandedId === event.id}
                      className="cursor-pointer border-b border-[var(--color-border)] bg-[var(--color-surface-1)] transition-colors last:border-b-0 hover:bg-[var(--color-surface-2)]"
                      style={flagged ? { borderLeft: "3px solid var(--color-severity-high)" } : undefined}
                    >
                      <td
                        className={`px-3 py-2 font-mono ${flagged ? "font-semibold text-[var(--color-text-hi)]" : "text-[var(--color-text-hi)]"}`}
                      >
                        {formatDate(event.ts)}
                      </td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.principal ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.domain ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.src_ip ?? "—"}</td>
                      <td className="px-3 py-2 text-[var(--color-text-mid)]">{event.action ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.status_code ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-mid)]">{event.bytes_out ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-[var(--color-text-hi)]">
                        {flagged ? formatScore(event.max_confidence) : "—"}
                      </td>
                      <td className="px-3 py-2">
                        {flagged ? (
                          <span className="flex flex-wrap items-center gap-1.5">
                            <Badge variant="outline">
                              <span aria-hidden="true" style={{ color: "var(--color-severity-high)" }}>
                                ▲
                              </span>
                              flagged
                            </Badge>
                            {event.detectors.slice(0, 2).map((d) => (
                              <span
                                key={d}
                                className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-[var(--color-text-mid)]"
                              >
                                {d}
                              </span>
                            ))}
                            {event.detectors.length > 2 && (
                              <span className="text-[var(--color-text-lo)]">+{event.detectors.length - 2}</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-[var(--color-text-lo)]">—</span>
                        )}
                      </td>
                    </tr>
                    {expandedId === event.id && (
                      <tr>
                        <td colSpan={9} className="bg-[var(--color-surface-0)] p-3">
                          <EventInspector eventId={event.id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
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
