"""Streams a `multipart/form-data` upload straight to MinIO/S3, part by part, without
ever holding the whole object in memory or writing it to local disk.

FastAPI's usual `UploadFile` parameter runs Starlette's `request.form()` to
completion *before* the route handler starts, spooling anything past ~1 MB to a
`SpooledTemporaryFile` on local disk (Starlette/`python-multipart`'s default
behaviour) — exactly what docs/06-PRIVACY-SECURITY.md rules out ("stream to MinIO
... without touching local disk"). This module instead drives `python-multipart`'s
low-level, callback-based `MultipartParser` directly against `Request.stream()`
(which itself only relays bytes as they arrive off the socket — see
`starlette.requests.Request.stream`), so the only things ever resident are: the
current ~8 MiB upload buffer, a 64 KiB sniff sample, and a running SHA-256 state —
never the file itself, and never anything written to `/tmp`.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from fastapi.concurrency import run_in_threadpool
from multipart.multipart import MultipartParser
from starlette.requests import Request

from app.core.config import get_settings
from app.core.errors import ApiError
from app.storage.client import get_s3_client

# S3/MinIO requires every multipart part except the last to be >= 5 MiB. 8 MiB stays
# comfortably clear of that while bounding this process's peak memory for the upload
# to a small fixed multiple of this constant — never the size of the file itself.
_PART_SIZE = 8 * 1024 * 1024
_SNIFF_WINDOW = 64 * 1024  # first ~64 KiB, plenty for "first ~50 lines" (docs/03)

_CONTENT_DISPOSITION_NAME = re.compile(r'name="([^"]*)"')
_CONTENT_DISPOSITION_FILENAME = re.compile(r'filename="([^"]*)"')

# Reject archives (docs/06) by magic bytes rather than trusting the extension alone.
_ARCHIVE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


class UploadRejectedError(ApiError):
    """A client-facing rejection: bad extension, disallowed content, or over the size
    cap. Distinct from an unexpected server-side failure."""


def _sniff_reject_reason(sample: bytes) -> str | None:
    for magic, label in _ARCHIVE_MAGIC:
        if sample.startswith(magic):
            return f"looks like a {label} archive, not a text log"
    if b"ustar" in sample[:512]:
        return "looks like a tar archive, not a text log"
    if b"\x00" in sample:
        return "contains binary data (a NUL byte), not text"
    return None


def _suffix_of(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx != -1 else ""


def _parse_boundary(content_type: str) -> bytes:
    for chunk in content_type.split(";"):
        chunk = chunk.strip()
        if chunk.startswith("boundary="):
            return chunk[len("boundary=") :].strip().strip('"').encode("utf-8")
    raise UploadRejectedError(
        status_code=400, code="invalid_upload", detail="multipart/form-data boundary is missing."
    )


@dataclass
class UploadResult:
    storage_key: str
    size_bytes: int
    sha256_hex: str
    sample_text: str


@dataclass
class _PartState:
    """Scratch state for whichever multipart part the parser is currently in."""

    headers: dict[str, str] = field(default_factory=dict)
    header_field: bytearray = field(default_factory=bytearray)
    header_value: bytearray = field(default_factory=bytearray)
    name: str | None = None
    filename: str | None = None
    is_file_field: bool = False


class _S3PartUploader:
    """Owns one S3 object's worth of upload state: buffers bytes up to `_PART_SIZE`,
    then flushes them as a multipart part — or, if the object never crosses that
    threshold, sends it as one plain `put_object` at the end."""

    def __init__(self, bucket: str, key: str) -> None:
        self._client = get_s3_client()
        self._bucket = bucket
        self._key = key
        self._buffer = bytearray()
        self._upload_id: str | None = None
        self._parts: list[dict[str, Any]] = []
        self._part_number = 0
        self._hasher = hashlib.sha256()
        self._total_bytes = 0
        self._sniff_buffer = bytearray()

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @property
    def sniff_sample(self) -> bytes:
        return bytes(self._sniff_buffer)

    def feed(self, chunk: bytes) -> None:
        """Synchronous and in-memory only — hashing, sniff-sampling, and buffering.
        `maybe_flush` is where the (async) network call happens."""
        self._hasher.update(chunk)
        self._total_bytes += len(chunk)
        remaining = _SNIFF_WINDOW - len(self._sniff_buffer)
        if remaining > 0:
            self._sniff_buffer.extend(chunk[:remaining])
        self._buffer.extend(chunk)

    async def maybe_flush(self) -> None:
        if len(self._buffer) >= _PART_SIZE:
            await self._flush_part()

    async def _flush_part(self) -> None:
        if not self._buffer:
            return
        if self._upload_id is None:
            created = await run_in_threadpool(
                self._client.create_multipart_upload, Bucket=self._bucket, Key=self._key
            )
            self._upload_id = created["UploadId"]
        self._part_number += 1
        body = bytes(self._buffer)
        self._buffer.clear()
        response = await run_in_threadpool(
            self._client.upload_part,
            Bucket=self._bucket,
            Key=self._key,
            PartNumber=self._part_number,
            UploadId=self._upload_id,
            Body=body,
        )
        self._parts.append({"PartNumber": self._part_number, "ETag": response["ETag"]})

    async def finalize(self) -> UploadResult:
        if self._upload_id is None:
            # Never crossed _PART_SIZE — a single PUT, no multipart machinery needed.
            await run_in_threadpool(
                self._client.put_object,
                Bucket=self._bucket,
                Key=self._key,
                Body=bytes(self._buffer),
            )
        else:
            await self._flush_part()  # final, possibly short, part
            await run_in_threadpool(
                self._client.complete_multipart_upload,
                Bucket=self._bucket,
                Key=self._key,
                UploadId=self._upload_id,
                MultipartUpload={"Parts": self._parts},
            )
        return UploadResult(
            storage_key=self._key,
            size_bytes=self._total_bytes,
            sha256_hex=self._hasher.hexdigest(),
            sample_text=bytes(self._sniff_buffer).decode("utf-8", errors="replace"),
        )

    async def abort(self) -> None:
        if self._upload_id is not None:
            with suppress(Exception):  # best-effort cleanup, never masks the real error
                await run_in_threadpool(
                    self._client.abort_multipart_upload,
                    Bucket=self._bucket,
                    Key=self._key,
                    UploadId=self._upload_id,
                )


async def stream_upload_to_storage(
    request: Request, *, bucket: str, storage_key: str
) -> tuple[UploadResult, str]:
    """Consume `request`'s multipart body, streaming the required `file` field
    straight to `storage_key` in `bucket`. Returns the finished upload's metadata plus
    the client-supplied filename, kept only as display metadata — never as a path
    (docs/06: storage keys are server-generated, filenames are never used as paths).

    Raises `UploadRejectedError` for a missing/unsupported field, a disallowed extension,
    an archive/binary payload, or exceeding the size cap.
    """
    settings = get_settings()
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("multipart/form-data"):
        raise UploadRejectedError(
            status_code=400, code="invalid_upload", detail="Expected multipart/form-data."
        )
    boundary = _parse_boundary(content_type)

    part = _PartState()
    uploader = _S3PartUploader(bucket, storage_key)
    filename: str | None = None
    file_field_seen = False
    rejection: UploadRejectedError | None = None

    def on_part_begin() -> None:
        part.headers.clear()
        part.header_field.clear()
        part.header_value.clear()
        part.name = None
        part.filename = None
        part.is_file_field = False

    def on_header_field(data: bytes, start: int, end: int) -> None:
        part.header_field.extend(data[start:end])

    def on_header_value(data: bytes, start: int, end: int) -> None:
        part.header_value.extend(data[start:end])

    def on_header_end() -> None:
        key = bytes(part.header_field).decode("latin-1").strip().lower()
        value = bytes(part.header_value).decode("latin-1").strip()
        part.headers[key] = value
        part.header_field.clear()
        part.header_value.clear()

    def on_headers_finished() -> None:
        nonlocal file_field_seen, filename, rejection
        disposition = part.headers.get("content-disposition", "")
        name_match = _CONTENT_DISPOSITION_NAME.search(disposition)
        filename_match = _CONTENT_DISPOSITION_FILENAME.search(disposition)
        part.name = name_match.group(1) if name_match else None
        part.filename = filename_match.group(1) if filename_match else None
        part.is_file_field = part.name == "file" and bool(part.filename)
        if part.is_file_field:
            file_field_seen = True
            filename = part.filename
            suffix = _suffix_of(part.filename or "")
            if suffix not in settings.allowed_upload_suffixes:
                rejection = UploadRejectedError(
                    status_code=400,
                    code="invalid_upload",
                    detail=f"Unsupported file extension {suffix!r}.",
                )

    def on_part_data(data: bytes, start: int, end: int) -> None:
        nonlocal rejection
        if not part.is_file_field or rejection is not None:
            return
        uploader.feed(data[start:end])
        if uploader.total_bytes > settings.max_upload_bytes:
            rejection = UploadRejectedError(
                status_code=413,
                code="upload_too_large",
                detail=f"Upload exceeds the {settings.max_upload_bytes} byte cap.",
            )
        elif uploader.total_bytes <= _SNIFF_WINDOW:
            reason = _sniff_reject_reason(uploader.sniff_sample)
            if reason:
                rejection = UploadRejectedError(
                    status_code=400, code="invalid_upload", detail=reason
                )

    parser = MultipartParser(
        boundary,
        {
            "on_part_begin": on_part_begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": on_header_end,
            "on_headers_finished": on_headers_finished,
            "on_part_data": on_part_data,
        },
    )

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            parser.write(chunk)
            if rejection is not None:
                raise rejection
            await uploader.maybe_flush()
    except UploadRejectedError:
        await uploader.abort()
        raise
    except Exception as exc:
        await uploader.abort()
        raise UploadRejectedError(
            status_code=400, code="invalid_upload", detail=f"Malformed multipart body: {exc}"
        ) from exc

    if not file_field_seen or filename is None:
        await uploader.abort()
        raise UploadRejectedError(
            status_code=400, code="invalid_upload", detail='Missing required "file" field.'
        )

    result = await uploader.finalize()
    return result, filename


def new_storage_key(*, tenant_id: uuid.UUID, upload_id: uuid.UUID) -> str:
    """Server-generated storage key. Never derived from the client filename — that is
    the path-traversal defense docs/06 calls for."""
    return f"{tenant_id}/{upload_id}"
