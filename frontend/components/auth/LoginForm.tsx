"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ApiError, login, resendVerification } from "@/lib/api/client";

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [emailNotVerified, setEmailNotVerified] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [resendState, setResendState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [resendError, setResendError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setEmailNotVerified(false);
    setResendState("idle");
    setResendError(null);
    setSubmitting(true);

    try {
      await login({ email, password });
      router.push("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many attempts. Wait a minute and try again.");
      } else if (err instanceof ApiError && err.status === 403 && err.code === "email_not_verified") {
        // Distinct from a credentials failure — this is not "wrong password".
        setEmailNotVerified(true);
      } else if (err instanceof ApiError) {
        // Never reveal whether the email exists — docs/09.
        setError("Incorrect email or password.");
      } else {
        setError("Could not reach the server. Check your connection and try again.");
      }
      setSubmitting(false);
    }
  }

  async function handleResend() {
    setResendState("sending");
    setResendError(null);
    try {
      await resendVerification({ email });
      setResendState("sent");
    } catch (err) {
      setResendState("error");
      if (err instanceof ApiError && err.status === 429) {
        setResendError(
          "You've reached the resend limit for this address — up to 3 per hour. Try again later.",
        );
      } else if (err instanceof ApiError) {
        setResendError("Could not resend the email. Try again.");
      } else {
        setResendError("Could not reach the server. Check your connection and try again.");
      }
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="mt-8 flex flex-col gap-5">
      <div className="flex flex-col gap-1.5">
        <label htmlFor="email" className="text-sm text-[var(--color-text-mid)]">
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          disabled={submitting}
          placeholder="you@company.com"
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)] outline-none placeholder:text-[var(--color-text-lo)] disabled:opacity-50"
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="password" className="text-sm text-[var(--color-text-mid)]">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          disabled={submitting}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)] outline-none disabled:opacity-50"
        />
      </div>

      {error && (
        <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
          {error}
        </p>
      )}

      {emailNotVerified && (
        <div role="alert" className="flex flex-col gap-2">
          <p className="text-sm text-[var(--color-severity-critical)]">
            Verify your email address to sign in.
          </p>
          {resendState === "sent" ? (
            <p className="text-sm text-[var(--color-text-mid)]">
              Verification email sent to {email}.
            </p>
          ) : (
            <button
              type="button"
              onClick={handleResend}
              disabled={resendState === "sending"}
              className="self-start text-sm text-[var(--color-text-hi)] underline underline-offset-2 disabled:opacity-50"
            >
              {resendState === "sending" ? "Sending…" : "Resend verification email"}
            </button>
          )}
          {resendError && (
            <p className="text-sm text-[var(--color-severity-high)]">{resendError}</p>
          )}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="mt-2 rounded-md bg-[var(--color-text-hi)] px-4 py-2.5 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "Signing in…" : "Log in"}
      </button>
    </form>
  );
}
