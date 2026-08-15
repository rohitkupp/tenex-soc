"""Pipeline-specific exceptions."""

from __future__ import annotations


class PermanentStageError(Exception):
    """Raise instead of a bare exception when a failure is deterministic — retrying the
    exact same `StageMessage` would fail identically every time (a referenced row is
    gone, the input is structurally invalid). `app.pipeline.base_worker` skips the
    retry/backoff ladder for this exception type and dead-letters on the first failure,
    rather than spending ~21 seconds of backoff to learn the same thing three more
    times. A transient failure (MinIO hiccup, a dropped DB connection) should raise
    anything else, so it gets the full retry policy."""
