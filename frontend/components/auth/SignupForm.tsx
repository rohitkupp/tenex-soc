"use client";

import { useEffect, useState, type FormEvent } from "react";
import { ApiError, resendVerification, signup } from "@/lib/api/client";

// The signup contract rejects anything shorter with 400 weak_password. Shown as helper text
// below the field before the user ever submits — the rule should never be a surprise.
const MIN_PASSWORD_LENGTH = 12;

// Resend is rate-limited to 3/hour server-side. A client cooldown after each click keeps a
// double-click (or an impatient user) from turning that into an opaque 429.
const RESEND_COOLDOWN_S = 60;

type Phase = { status: "form" } | { status: "sent"; email: string };

export function SignupForm() {
  const [phase, setPhase] = useState<Phase>({ status: "form" });
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }

    setSubmitting(true);
    try {
      const result = await signup({ email, password, org_name: orgName });
      setPhase({ status: "sent", email: result.email });
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many attempts. Wait a minute and try again.");
      } else if (err instanceof ApiError && err.code === "weak_password") {
        setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      } else if (err instanceof ApiError) {
        setError("Could not create the account. Check the details and try again.");
      } else {
        setError("Could not reach the server. Check your connection and try again.");
      }
      setSubmitting(false);
    }
  }

  if (phase.status === "sent") {
    return <VerificationSent email={phase.email} />;
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="mt-8 flex flex-col gap-5">
      <div className="flex flex-col gap-1.5">
        <label htmlFor="org_name" className="text-sm text-[var(--color-text-mid)]">
          Organization name
        </label>
        <input
          id="org_name"
          name="org_name"
          type="text"
          autoComplete="organization"
          required
          value={orgName}
          onChange={(event) => setOrgName(event.target.value)}
          disabled={submitting}
          placeholder="Acme Corp"
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)] outline-none placeholder:text-[var(--color-text-lo)] disabled:opacity-50"
        />
      </div>

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
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          disabled={submitting}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)] outline-none disabled:opacity-50"
        />
        <p className="text-xs text-[var(--color-text-lo)]">
          At least {MIN_PASSWORD_LENGTH} characters.
        </p>
      </div>

      {error && (
        <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="mt-2 rounded-md bg-[var(--color-text-hi)] px-4 py-2.5 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "Creating account…" : "Create account"}
      </button>
    </form>
  );
}

/**
 * Post-signup confirmation. Never says "account created" — a 201 here also fires for an
 * already-registered email (the API must not disclose account existence), so the only honest
 * claim is conditional: if the address is valid, a link is on its way.
 */
function VerificationSent({ email }: { email: string }) {
  const [cooldown, setCooldown] = useState(0);
  const [resendState, setResendState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [resendError, setResendError] = useState<string | null>(null);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setInterval(() => {
      setCooldown((seconds) => Math.max(0, seconds - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  async function handleResend() {
    setResendState("sending");
    setResendError(null);
    try {
      await resendVerification({ email });
      setResendState("sent");
      setCooldown(RESEND_COOLDOWN_S);
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

  const disabled = resendState === "sending" || cooldown > 0;

  return (
    <div className="mt-8 flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
      <div>
        <p className="text-sm font-medium text-[var(--color-text-hi)]">Check your email</p>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          If <span className="font-mono text-[var(--color-text-hi)]">{email}</span> is a valid
          address, a verification link is on its way. Open it to finish creating your account.
        </p>
      </div>

      {resendState === "sent" && (
        <p className="text-sm text-[var(--color-text-mid)]">Sent again.</p>
      )}
      {resendError && (
        <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
          {resendError}
        </p>
      )}

      <div className="flex flex-col gap-1.5">
        <button
          type="button"
          onClick={handleResend}
          disabled={disabled}
          className="self-start rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-mid)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)] disabled:opacity-50"
        >
          {resendState === "sending"
            ? "Sending…"
            : cooldown > 0
              ? `Resend available in ${cooldown}s`
              : "Resend verification email"}
        </button>
        <p className="text-xs text-[var(--color-text-lo)]">Limited to 3 sends per hour.</p>
      </div>
    </div>
  );
}
