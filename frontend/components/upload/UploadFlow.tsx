"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { DropZone } from "./DropZone";
import { ApiError } from "@/lib/api/client";
import { uploadLogFile, type UploadHandle } from "@/lib/api/upload";
import { formatBytes } from "@/lib/format";

// 200 MB cap — docs/09. Checked client-side so an oversized file never
// starts a doomed upload; the server enforces the real limit.
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;

// docs/v2_migration change 27: "Format sniffing and the 5-line parse preview move into
// the drop zone as an inline confirmation step before the upload commits." The real
// sniffer (`app.parsers.registry.sniff_scores`) only ever runs server-side, against the
// file once it has already landed in storage (`POST /api/uploads`, unchanged by this
// change) — there is no pre-commit preview endpoint to call. Rather than duplicate that
// heuristic client-side (a second implementation that could disagree with the real one,
// which would be worse than no preview at all), this reads the first few lines straight
// off the selected `File` object with the browser's own File API and shows them
// verbatim, honestly framed as a raw preview rather than a claimed format match.
const PREVIEW_LINES = 5;
const PREVIEW_READ_BYTES = 16 * 1024; // comfortably more than 5 lines of any real log format

async function readPreviewLines(file: File): Promise<string[]> {
  const head = await file.slice(0, PREVIEW_READ_BYTES).text();
  return head.split(/\r\n|\r|\n/).slice(0, PREVIEW_LINES);
}

type Phase =
  | { status: "idle" }
  | { status: "selected"; file: File; previewLines: string[] | null }
  | { status: "uploading"; file: File; progress: number }
  | { status: "error"; file: File | null; message: string };

const primaryButton =
  "rounded-md bg-[var(--color-text-hi)] px-3 py-1.5 text-xs font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50";
const secondaryButton =
  "rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs text-[var(--color-text-mid)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)]";

/**
 * The upload entry point — docs/v2_migration change 27: "Upload becomes a drop zone in
 * the header of `/`, alongside the analysis list. On submit, route straight to
 * `/analyses/[id]`." There is deliberately no "upload complete" panel rendered here:
 * once `POST /api/uploads` returns, this navigates straight to the analysis page, which
 * itself renders the live funnel (`FunnelProgress`) while the pipeline runs and becomes
 * the overview once it finishes — "no separate page, no navigation" beyond that one hop.
 */
export function UploadFlow() {
  const router = useRouter();
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
    setPhase({ status: "selected", file, previewLines: null });
  }, []);

  // Reads the inline preview once a file is selected, before the analyst confirms the
  // upload — the "inline confirmation step" change 27 asks for.
  useEffect(() => {
    if (phase.status !== "selected" || phase.previewLines !== null) return;
    let cancelled = false;
    readPreviewLines(phase.file).then((lines) => {
      if (!cancelled) {
        setPhase((prev) =>
          prev.status === "selected" ? { ...prev, previewLines: lines } : prev,
        );
      }
    });
    return () => {
      cancelled = true;
    };
  }, [phase]);

  const startUpload = useCallback(
    (file: File) => {
      setPhase({ status: "uploading", file, progress: 0 });

      const handle = uploadLogFile(file, (fraction) => {
        setPhase((prev) =>
          prev.status === "uploading" ? { ...prev, progress: fraction } : prev,
        );
      });
      handleRef.current = handle;

      handle.done
        .then((result) => {
          router.push(`/analyses/${result.analysis_id}`);
        })
        .catch((err: unknown) => {
          const message =
            err instanceof ApiError
              ? err.message
              : "Upload failed — check your connection and try again.";
          setPhase({ status: "error", file, message });
        });
    },
    [router],
  );

  const cancelUpload = useCallback(() => {
    handleRef.current?.cancel();
  }, []);

  const reset = useCallback(() => setPhase({ status: "idle" }), []);

  if (phase.status === "idle") {
    return <DropZone onFileSelected={selectFile} compact />;
  }

  if (phase.status === "selected") {
    return (
      <div className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-4">
        <FileSummary file={phase.file} />
        <div>
          <p className="mb-1 text-xs text-[var(--color-text-lo)]">
            Preview — first {PREVIEW_LINES} lines
          </p>
          {phase.previewLines === null ? (
            <div className="h-16 animate-pulse rounded bg-[var(--color-surface-2)]" />
          ) : (
            <pre className="max-h-32 overflow-auto rounded bg-[var(--color-surface-2)] p-2 font-mono text-[11px] leading-relaxed text-[var(--color-text-mid)]">
              {phase.previewLines.join("\n") || "(empty file)"}
            </pre>
          )}
          <p className="mt-1 text-[11px] text-[var(--color-text-lo)]">
            Raw preview only — format detection (ZScaler web proxy) happens once the upload
            completes.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
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
      <div className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-4">
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

  // phase.status === "error"
  return (
    <div className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-4">
      {phase.file && <FileSummary file={phase.file} />}
      <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
        {phase.message}
      </p>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={secondaryButton} onClick={reset}>
          Try again
        </button>
      </div>
    </div>
  );
}

function FileSummary({ file }: { file: File }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-mono text-xs text-[var(--color-text-hi)]">{file.name}</span>
      <span className="text-[11px] text-[var(--color-text-lo)]">{formatBytes(file.size)}</span>
    </div>
  );
}
