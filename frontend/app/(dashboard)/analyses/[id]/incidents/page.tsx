import { redirect } from "next/navigation";

// The incident queue is now a tab on the analysis page, not a route of its own — see
// `components/analyses/AnalysisTabs.tsx` for why. This redirect keeps existing links
// (bookmarks, the incident case file's "back to queue", anything already shared) landing on
// the queue rather than 404ing.
export default async function IncidentsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  redirect(`/analyses/${id}?tab=incidents`);
}
