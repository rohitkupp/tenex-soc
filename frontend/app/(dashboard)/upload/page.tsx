import type { Metadata } from "next";
import { UploadFlow } from "@/components/upload/UploadFlow";

export const metadata: Metadata = { title: "Upload — Tenex SOC Analyst" };

export default function UploadPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">
          Upload a log file
        </h1>
        <p className="mt-1 max-w-prose text-sm text-[var(--color-text-mid)]">
          ZScaler web proxy, Okta system log, or AWS CloudTrail. Up to 200 MB. The file streams
          straight from your browser to storage — it never passes through this app&apos;s server.
        </p>
      </div>
      <UploadFlow />
    </div>
  );
}
