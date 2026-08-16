"""Shared helper for pipeline-stage tests that need a real, labeled ZScaler scenario log
uploaded to MinIO and parsed into real `events` rows via the real `parse` stage.

`app.pipeline.stages.detect`'s own module docstring explains why this matters: L3
(`app.detection.ml.events.load_ml_events`) reads the raw log *file*, not the `events` table, and
joins back to `events.id` via `raw_line_no` — so a detect-stage test needs the file itself,
uploaded to the same MinIO object `analyses`/`uploads` point at, and `events` rows whose
`raw_line_no` genuinely matches that file's own line numbers. Running the real `parse` stage
(rather than hand-inserting `Event` rows) is what guarantees that correspondence, the same way a
live upload would.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.models.analysis import Analysis
from app.models.tenant import Tenant
from app.models.user import User
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.pipeline.stages import parse as parse_stage
from app.storage.client import ensure_bucket, get_s3_client
from tests.conftest import make_analysis

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class UploadedScenario:
    analysis: Analysis
    log_path: Path
    labels: dict[str, Any]


def generate_scenario(out_dir: Path, *, name: str, seed: int, events: int) -> tuple[Path, Path]:
    """Shells out to `python -m datagen scenario ...` — the same CLI invocation
    `app.graph.pipeline_demo`/`app.detection.ml.train` use, never a Python import of `datagen`
    internals from test-support code that other packages also rely on staying import-light."""
    cmd = [
        sys.executable,
        "-m",
        "datagen",
        "scenario",
        "--name",
        name,
        "--seed",
        str(seed),
        "--out",
        str(out_dir),
        "--events",
        str(events),
    ]
    subprocess.run(cmd, check=True, cwd=_BACKEND_ROOT)
    log_path = sorted(out_dir.glob("*.log"))[0]
    labels_path = sorted(out_dir.glob("*.labels.json"))[0]
    return log_path, labels_path


def upload_and_parse_scenario(
    *,
    tenant: Tenant,
    user: User,
    out_dir: Path,
    name: str,
    seed: int,
    events: int = 50_000,
) -> UploadedScenario:
    """Generate a labeled scenario, upload it to MinIO exactly like a real `POST /api/uploads`
    would, create the matching `uploads`/`analyses` row pair, and drive it through the *real*
    `parse` stage — so `events` (with correct `raw_line_no`) exists for whatever pipeline stage
    the caller wants to test next."""
    log_path, labels_path = generate_scenario(out_dir, name=name, seed=seed, events=events)
    raw_bytes = log_path.read_bytes()

    settings = get_settings()
    ensure_bucket()
    storage_ref = f"{tenant.id}/{uuid.uuid4()}-zscaler.log"
    get_s3_client().put_object(Bucket=settings.s3_bucket, Key=storage_ref, Body=raw_bytes)

    analysis = make_analysis(
        tenant_id=tenant.id,
        user_id=user.id,
        detected_sources=["zscaler"],
        storage_ref=storage_ref,
    )

    message = StageMessage(
        analysis_id=analysis.id,
        tenant_id=tenant.id,
        stage="parse",
        storage_ref=storage_ref,
        source_type="zscaler",
        attempt=0,
        emitted_at=datetime.now(UTC),
    )
    asyncio.run(parse_stage.handle(message))
    # `app.pipeline.redis_client.get_redis` is `lru_cache`d process-wide (a correct optimization
    # for a long-lived worker, wrong across independent `asyncio.run()` calls — see
    # `tests/conftest.py`'s `_fresh_redis_client_per_test`, which only resets *between* tests,
    # not between two `asyncio.run()` calls inside the *same* test). This helper always runs
    # inside a caller that is about to make its own separate `asyncio.run(...)` call next (the
    # stage under test), so it must not leave a client bound to the loop that just closed.
    get_redis.cache_clear()

    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    return UploadedScenario(analysis=analysis, log_path=log_path, labels=labels)
