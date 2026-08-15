/**
 * Direct browser -> API upload. Per docs/01/docs/09 this must never proxy
 * through Next.js (sidesteps Vercel's ~4.5 MB serverless body limit; files
 * here reach 200 MB). XMLHttpRequest is used instead of `fetch` because it
 * is the well-supported way to get real upload-progress events — this is
 * genuine progress from the browser, not a simulation.
 */
import { API_URL, ApiError } from "./client";
import { isApiErrorBody, type UploadResponse } from "./types";

export interface UploadHandle {
  done: Promise<UploadResponse>;
  cancel: () => void;
}

export function uploadLogFile(
  file: File,
  onProgress: (fraction: number) => void,
): UploadHandle {
  const xhr = new XMLHttpRequest();

  const done = new Promise<UploadResponse>((resolve, reject) => {
    xhr.open("POST", `${API_URL}/api/uploads`);
    xhr.withCredentials = true;

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(event.loaded / event.total);
      }
    };

    xhr.onload = () => {
      const body = parseJson(xhr.responseText);

      if (xhr.status >= 200 && xhr.status < 300 && body) {
        resolve(body as UploadResponse);
        return;
      }

      reject(new ApiError(xhr.status, toErrorBody(body, xhr.status)));
    };

    xhr.onerror = () => {
      reject(
        new ApiError(0, {
          detail: "Network error — check your connection and try again.",
          code: "network_error",
        }),
      );
    };

    xhr.onabort = () => {
      reject(new ApiError(0, { detail: "Upload cancelled.", code: "cancelled" }));
    };

    const formData = new FormData();
    formData.append("file", file);
    xhr.send(formData);
  });

  return {
    done,
    cancel: () => xhr.abort(),
  };
}

function parseJson(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function toErrorBody(body: unknown, status: number): { detail: string; code: string } {
  if (isApiErrorBody(body)) return body;
  return { detail: `Upload failed with status ${status}.`, code: "unknown_error" };
}
