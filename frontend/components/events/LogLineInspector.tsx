"use client";

/**
 * Expands one raw log row inline, by *file line number* rather than `events.id` — change 16's
 * "contributing line numbers, click-to-expand into the raw log rows" (Evidence section cards)
 * and the `LOG-n` half of the narrative's citation chips (`NarrativeBlock`). Fetches
 * `GET /api/analyses/{analysis_id}/events/by-line/{raw_line_no}` (change 16: nothing before it
 * could resolve a raw line number back to an event without already knowing its database id,
 * which the evidence layer never hands out — `EvidencePayload.contributing_line_numbers` and a
 * narrative's `LOG-n` citations are both file line numbers, `Event.raw_line_no`).
 *
 * Renders through the exact same `EventDetailView` `EventInspector` uses, so a citation
 * expanded from a `LOG-n` chip and one expanded from a numeric event id look identical.
 */
import { EventFetchFrame } from "@/components/events/EventInspector";

export function LogLineInspector({
  analysisId,
  rawLineNo,
}: {
  analysisId: string;
  rawLineNo: number;
}) {
  return (
    <EventFetchFrame
      path={`/api/analyses/${analysisId}/events/by-line/${rawLineNo}`}
      notFoundMessage={`No event found at line ${rawLineNo}.`}
    />
  );
}
