import { redirect } from "next/navigation";

// Events is now a tab on the analysis page — see `components/analyses/AnalysisTabs.tsx`.
// Kept as a redirect so existing links still land on the events view.
export default async function EventsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  redirect(`/analyses/${id}?tab=events`);
}
