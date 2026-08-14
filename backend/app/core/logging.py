"""Structured logging.

JSON in containers, human-readable on a TTY. `print` is banned by ruff (T20) —
everything goes through structlog so worker output stays greppable.
"""

from __future__ import annotations

import logging
import sys

import structlog

# Values that must never reach a log line. See docs/06-PRIVACY-SECURITY.md.
_REDACT_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "token",
        "jwt_secret",
        "pseudonym_salt",
        "anthropic_api_key",
        "s3_secret_key",
        "authorization",
    }
)


def _scrub_secrets(
    _logger: object, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    for key in list(event_dict):
        if key.lower() in _REDACT_KEYS:
            event_dict[key] = "<redacted>"
    return event_dict


def configure_logging(level: str = "info") -> None:
    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=getattr(logging, level.upper(), logging.INFO)
    )

    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer()
        if sys.stdout.isatty()
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _scrub_secrets,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
