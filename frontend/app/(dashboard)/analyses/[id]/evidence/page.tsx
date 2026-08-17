import { redirect } from "next/navigation";

// Evidence is now a tab on the analysis page — see `components/analyses/AnalysisTabs.tsx`.
// Kept as a redirect so existing links still land on the evidence view.
export default async function AnalysisEvidencePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  redirect(`/analyses/${id}?tab=evidence`);
}
