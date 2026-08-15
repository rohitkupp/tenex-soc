"""Writes `dead_letters` rows — see `app.models.dead_letter` for the table shape and
`app.pipeline.base_worker` for the retry policy that decides when a message qualifies.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import Connection, text


def insert_dead_letter(
    conn: Connection,
    *,
    analysis_id: uuid.UUID | None,
    stage: str,
    payload: dict[str, Any],
    error: str,
    attempts: int,
) -> int:
    """Insert one `dead_letters` row, returning its `id` (used by
    `POST /api/ops/dead-letters/{id}/retry`)."""
    row = conn.execute(
        text(
            """
            INSERT INTO dead_letters (analysis_id, stage, payload, error, attempts)
            VALUES (:analysis_id, :stage, CAST(:payload AS jsonb), :error, :attempts)
            RETURNING id
            """
        ),
        {
            "analysis_id": analysis_id,
            "stage": stage,
            "payload": json.dumps(payload),
            "error": error[:4000],
            "attempts": attempts,
        },
    ).one()
    return int(row[0])
