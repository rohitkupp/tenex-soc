"use client";

/**
 * Live pipeline progress — `GET /api/analyses/{id}/stream` (docs/01, docs/09).
 *
 * Uses the browser's native `EventSource`, not a hand-rolled fetch/reader
 * loop, specifically so "reconnect on drop" is real reconnection behavior
 * rather than something we simulate: EventSource retries automatically on a
 * dropped connection (per spec) unless the initial handshake itself fails
 * with a non-2xx response, in which case the browser gives up and leaves
 * `readyState` at `CLOSED` without retrying. `onerror` below distinguishes
 * those two cases so the UI can say "reconnecting" only when that is true.
 *
 * `withCredentials: true` is required — docs/06's SameSite decision record
 * means the session cookie is cross-site in every deployed environment, and
 * EventSource (unlike `fetch`) does not send cookies by default.
 *
 * Terminal detection: docs/01-ARCHITECTURE.md's "Terminal contract" — every event
 * carries `status: queued | running | complete | failed`, mirroring `analyses.status`,
 * specified precisely so a client never has to *infer* terminality by guessing which
 * `stage` name is last. `status === "complete" || status === "failed"` is therefore the
 * terminal check, not a stage/progress heuristic — the latter would also silently miss
 * a `failed` analysis entirely (a dead-lettered stage never reaches `triage` at
 * `progress >= 1`), which is exactly the case docs/v2_migration change 27's "failures
 * surface on the analysis" needs this hook to report correctly. When terminal is
 * observed, the connection is closed from the client side — a stream left open past
 * terminal state is a leaked connection, and the server ending its HTTP response on its
 * own would otherwise just trigger the browser's automatic-reconnect behavior described
 * above.
 */
import { useEffect, useState } from "react";
import { API_URL } from "./client";
import { isAnalysisStreamEvent, type AnalysisStreamEvent } from "./types";

export type StreamConnectionState = "connecting" | "open" | "reconnecting" | "closed";

const TERMINAL_STATUSES = new Set(["complete", "failed"]);

interface AnalysisStreamState {
  event: AnalysisStreamEvent | null;
  connection: StreamConnectionState;
  /** True once a terminal event (`status` `complete` or `failed`, see module
   * docstring) has been observed and the connection has been closed from this side. */
  done: boolean;
}

/**
 * Subscribes to an analysis's progress stream while `analysisId` is
 * non-null. Pass `null` to skip connecting entirely — the caller
 * (`FunnelProgress`) does this for analyses a server-fetched snapshot
 * already reports as finished, so a completed run never opens a stream that
 * will never emit again.
 */
export function useAnalysisStream(analysisId: string | null): AnalysisStreamState {
  const [event, setEvent] = useState<AnalysisStreamEvent | null>(null);
  const [connection, setConnection] = useState<StreamConnectionState>("connecting");
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!analysisId) return;

    setEvent(null);
    setConnection("connecting");
    setDone(false);

    const source = new EventSource(`${API_URL}/api/analyses/${analysisId}/stream`, {
      withCredentials: true,
    });

    source.onopen = () => setConnection("open");

    source.onmessage = (message: MessageEvent<string>) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(message.data);
      } catch {
        return; // malformed payload — ignore rather than crash the funnel
      }
      if (!isAnalysisStreamEvent(parsed)) return;

      setEvent(parsed);

      if (TERMINAL_STATUSES.has(parsed.status)) {
        setDone(true);
        setConnection("closed");
        source.close(); // terminate cleanly — do not rely on unmount for this
      } else {
        setConnection("open");
      }
    };

    source.onerror = () => {
      // readyState CLOSED here (and we didn't call .close() ourselves above)
      // means the browser already gave up — e.g. the initial handshake
      // failed with a non-2xx. Anything else is a mid-stream drop the
      // browser is about to retry on its own.
      setConnection(source.readyState === EventSource.CLOSED ? "closed" : "reconnecting");
    };

    return () => {
      source.close();
    };
  }, [analysisId]);

  return { event, connection, done };
}
