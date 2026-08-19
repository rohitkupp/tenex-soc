"use client";

import { useCallback, useRef, useState, type DragEvent, type KeyboardEvent } from "react";

interface DropZoneProps {
  onFileSelected: (file: File) => void;
  disabled?: boolean;
  /** docs/v2_migration change 27: "Upload becomes a drop zone in the header of `/`,
   * alongside the analysis list" — a compact, inline-sized target rather than the tall
   * full-page one the deleted `/upload` route used. */
  compact?: boolean;
}

export function DropZone({ onFileSelected, disabled = false, compact = false }: DropZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const openPicker = useCallback(() => {
    if (!disabled) inputRef.current?.click();
  }, [disabled]);

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    const file = event.dataTransfer.files[0];
    if (file) onFileSelected(file);
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openPicker();
    }
  }

  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      aria-label="Drop a log file here, or activate to browse for one"
      onClick={openPicker}
      onKeyDown={handleKeyDown}
      onDragOver={(event) => {
        event.preventDefault();
        if (!disabled) setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={`flex items-center justify-center gap-2 rounded-lg border border-dashed text-center transition-colors ${
        compact ? "flex-row px-4 py-3" : "flex-col px-6 py-16"
      } ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"} ${
        isDragging
          ? "border-[var(--color-text-mid)] bg-[var(--color-surface-2)]"
          : "border-[var(--color-border)] bg-[var(--color-surface-1)]"
      }`}
    >
      <p className={`font-medium text-[var(--color-text-hi)] ${compact ? "text-xs" : "text-sm"}`}>
        Click to Browser
      </p>
      <p className={`text-[var(--color-text-lo)] ${compact ? "text-xs" : "text-xs"}`}>
        ZScaler web proxy. Up to 200 MB.
      </p>
      <input
        ref={inputRef}
        type="file"
        className="sr-only"
        disabled={disabled}
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) onFileSelected(file);
          event.target.value = "";
        }}
      />
    </div>
  );
}
