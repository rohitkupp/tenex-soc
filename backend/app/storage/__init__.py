"""MinIO/S3 object storage: a lazy client (`app.storage.client`) and a streaming
multipart-upload path (`app.storage.streaming_upload`) that never buffers a whole
upload in memory or on local disk. See docs/06-PRIVACY-SECURITY.md."""

from __future__ import annotations
