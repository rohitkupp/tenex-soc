import type { Metadata } from "next";
import { LoginForm } from "@/components/auth/LoginForm";

export const metadata: Metadata = { title: "Log in — Tenex SOC Analyst" };

// Credentials only. Nothing else on the page — docs/10.
export default function LoginPage() {
  return (
    <main className="flex min-h-dvh items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-hi)]">
          Tenex SOC Analyst
        </h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">Sign in to review incidents.</p>
        <LoginForm />
      </div>
    </main>
  );
}
