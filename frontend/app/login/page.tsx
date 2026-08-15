import type { Metadata } from "next";
import Link from "next/link";
import { LoginForm } from "@/components/auth/LoginForm";

export const metadata: Metadata = { title: "Log in — Tenex SOC Analyst" };

// Credentials, plus the signup entry point and the post-verification banner
// that Supabase's email link redirects to (`/login?verified=1`) — docs/10's
// "nothing else on the page" still holds for the form itself.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ verified?: string }>;
}) {
  const { verified } = await searchParams;

  return (
    <main className="flex min-h-dvh items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-hi)]">
          Tenex SOC Analyst
        </h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">Sign in to review incidents.</p>

        {verified === "1" && (
          <p className="mt-4 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)]">
            Email verified — you can sign in now.
          </p>
        )}

        <LoginForm />

        <p className="mt-6 text-sm text-[var(--color-text-mid)]">
          Need an account?{" "}
          <Link href="/signup" className="text-[var(--color-text-hi)] underline underline-offset-2">
            Create an account
          </Link>
        </p>
      </div>
    </main>
  );
}
