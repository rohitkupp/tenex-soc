"use client";

import { useCallback, useRef, useState } from "react";
import Link from "next/link";
import { DropZone } from "./DropZone";
import { FunnelPreview } from "./FunnelPreview";
import { ApiError } from "@/lib/api/client";
import { uploadLogFile, type UploadHandle } from "@/lib/api/upload";
import type { UploadResponse } from "@/lib/api/types";
import { formatBytes } from "@/lib/format";

// 200 MB cap — docs/09. Checked client-side so an oversized file never
// starts a doomed upload; the server enforces the real limit.
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;

type Phase =
  | { status: "idle" }
  | { status: "selected"; file: File }
  | { status: "uploading"; file: File; progress: number }
  | { status: "success"; file: File; result: UploadResponse }
  | { status: "error"; file: File | null; message: string };

const primaryButton =
  "rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50";
const secondaryButton =
  "rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-mid)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)]";

export function UploadFlow() {
  const [phase, setPhase] = useState<Phase>({ status: "idle" });
  const handleRef = useRef<UploadHandle | null>(null);

  const selectFile = useCallback((file: File) => {
    if (file.size > MAX_UPLOAD_BYTES) {
      setPhase({
        status: "error",
        file: null,
        message: `${file.name} is ${formatBytes(file.size)}, over the 200 MB cap. Choose a smaller file.`,
      });
      return;
    }
    setPhase({ status: "selected", file });
  }, []);

  const startUpload = useCallback((file: File) => {
    setPhase({ status: "uploading", file, progress: 0 });

    const handle = uploadLogFile(file, (fraction) => {
      setPhase((prev) =>
        prev.status === "uploading" ? { ...prev, progress: fraction } : prev,
      );
    });
    handleRef.current = handle;

    handle.done
      .then((result) => setPhase({ status: "success", file, result }))
      .catch((err: unknown) => {
        const message =
          err instanceof ApiError
            ? err.message
            : "Upload failed — check your connection and try again.";
        setPhase({ status: "error", file, message });
      });
  }, []);

  const cancelUpload = useCallback(() => {
    handleRef.current?.cancel();
  }, []);

  const reset = useCallback(() => setPhase({ status: "idle" }), []);

  if (phase.status === "idle") {
    return <DropZone onFileSelected={selectFile} />;
  }

  if (phase.status === "selected") {
    return (
      <div className="flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
        <FileSummary file={phase.file} />
        <div className="flex flex-wrap gap-3">
          <button type="button" className={primaryButton} onClick={() => startUpload(phase.file)}>
            Upload log file
          </button>
          <button type="button" className={secondaryButton} onClick={reset}>
            Choose a different file
          </button>
        </div>
      </div>
    );
  }

  if (phase.status === "uploading") {
    const percent = Math.round(phase.progress * 100);
    return (
      <div className="flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
        <FileSummary file={phase.file} />
        <div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--color-surface-2)]">
            <div
              className="h-full rounded-full bg-[var(--color-text-mid)] transition-[width]"
              style={{ width: `${percent}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-[var(--color-text-lo)]">Uploading — {percent}%</p>
        </div>
        <div>
          <button type="button" className={secondaryButton} onClick={cancelUpload}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (phase.status === "success") {
    return (
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
          <div>
            <p className="text-sm font-medium text-[var(--color-text-hi)]">Upload complete</p>
            <p className="mt-1 text-xs text-[var(--color-text-lo)]">
              {phase.file.name} ({formatBytes(phase.file.size)})
            </p>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-[var(--color-text-lo)]">Analysis</dt>
            <dd className="font-mono text-[var(--color-text-hi)]">{phase.result.analysis_id}</dd>
            <dt className="text-[var(--color-text-lo)]">Detected sources</dt>
            <dd className="flex flex-wrap gap-2">
              {phase.result.detected_sources.length === 0 ? (
                <span className="text-[var(--color-text-mid)]">none detected</span>
              ) : (
                phase.result.detected_sources.map((source) => (
                  <span
                    key={source}
                    className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs text-[var(--color-text-mid)]"
                  >
                    {source}
                  </span>
                ))
              )}
            </dd>
          </dl>
          <div className="flex flex-wrap gap-3">
            <Link href="/" className={primaryButton}>
              View analyses
            </Link>
            <button type="button" className={secondaryButton} onClick={reset}>
              Upload another file
            </button>
          </div>
        </div>
        <FunnelPreview />
      </div>
    );
  }

  // phase.status === "error"
  return (
    <div className="flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
      {phase.file && <FileSummary file={phase.file} />}
      <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
        {phase.message}
      </p>
      <div className="flex flex-wrap gap-3">
        <button type="button" className={secondaryButton} onClick={reset}>
          Try again
        </button>
      </div>
    </div>
  );
}

function FileSummary({ file }: { file: File }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-sm text-[var(--color-text-hi)]">{file.name}</span>
      <span className="text-xs text-[var(--color-text-lo)]">{formatBytes(file.size)}</span>
    </div>
  );
}
