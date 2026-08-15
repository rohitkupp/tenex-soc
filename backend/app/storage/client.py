"""Lazy boto3 S3 client for MinIO. Mirrors `app.core.db.get_engine`'s laziness —
building a client at import time would couple importing any module to a reachable
object store, breaking tests and `--help` the same way an eager DB engine would."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import boto3
from botocore.client import Config

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# We always pass explicit static keys (MinIO, never an AWS profile), but boto3
# unconditionally tries to parse `~/.aws/{credentials,config}` anyway as part of
# resolving ambient session config — so a host with a stray malformed file in either
# location breaks client construction even though nothing here reads it.
# `setdefault` only steps in when the operator hasn't set these themselves.
os.environ.setdefault("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
os.environ.setdefault("AWS_CONFIG_FILE", os.devnull)


@lru_cache
def get_s3_client() -> Any:
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key.get_secret_value(),
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


@lru_cache
def ensure_bucket() -> None:
    """Idempotent, process-once bucket creation. MinIO does not pre-create buckets on
    startup the way docker-compose provisions the other services, so the first request
    that needs it creates it. `lru_cache` makes this a one-time check per process
    rather than a head_bucket call on every upload."""
    settings = get_settings()
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=settings.s3_bucket)
    except Exception:
        log.info("storage.bucket_create", bucket=settings.s3_bucket)
        client.create_bucket(Bucket=settings.s3_bucket)
