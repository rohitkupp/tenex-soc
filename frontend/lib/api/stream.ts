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
 * Terminal detection: the documented SSE payload is verbatim
 * `{ stage, progress, message, counters }` with no explicit "done" flag. The
 * funnel this hook drives covers ingest→triage only — docs/01's stage
 * contracts table lists `respond` and `tier2` as stages after `triage`, and
 * the funnel UI (this hook's only consumer) was already scoped to
 * ingest..triage before SSE existed (see the former inert placeholder this
 * replaced). So "terminal" is inferred as: the last funnel stage (`triage`)
 * reported at `progress >= 1`. When that's observed, the connection is
 * closed from the client side — a stream left open past terminal state is a
 * leaked connection, and the server ending its HTTP response on its own
 * would otherwise just trigger the browser's automatic-reconnect behavior
 * described above.
 */
import { useEffect, useState } from "react";
import { API_URL } from "./client";
import { isAnalysisStreamEvent, type AnalysisStreamEvent } from "./types";

export type StreamConnectionState = "connecting" | "open" | "reconnecting" | "closed";

const TERMINAL_STAGE = "triage";

interface AnalysisStreamState {
  event: AnalysisStreamEvent | null;
  connection: StreamConnectionState;
  /** True once the terminal event (see module docstring) has been observed
   * and the connection has been closed from this side. */
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

      if (parsed.stage === TERMINAL_STAGE && parsed.progress >= 1) {
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
