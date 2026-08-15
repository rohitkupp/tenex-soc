import type { Metadata } from "next";
import Link from "next/link";
import { SignupForm } from "@/components/auth/SignupForm";

export const metadata: Metadata = { title: "Create an account — Tenex SOC Analyst" };

// Signup, mirroring /login's scope and shell — nothing else on the page.
export default function SignupPage() {
  return (
    <main className="flex min-h-dvh items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-hi)]">
          Tenex SOC Analyst
        </h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          Create an account to start reviewing incidents.
        </p>
        <SignupForm />
        <p className="mt-6 text-sm text-[var(--color-text-mid)]">
          Already have an account?{" "}
          <Link href="/login" className="text-[var(--color-text-hi)] underline underline-offset-2">
            Log in
          </Link>
        </p>
      </div>
    </main>
  );
}
