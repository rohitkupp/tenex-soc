import type { ReactNode } from "react";
import { AppNav } from "@/components/nav/AppNav";

// Shell for the authenticated routes (`/`, `/analyses/[id]`, `/learning`, `/tier2`).
// `/login` and `/signup` sit outside this route group and get no nav — "nothing else
// on the page".
export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <AppNav />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">{children}</main>
    </div>
  );
}
