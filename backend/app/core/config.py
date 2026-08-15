"""Application settings.

Two rules from docs/06-PRIVACY-SECURITY.md are enforced here rather than trusted:

1. **Secrets never render.** Every secret is a `SecretStr`, so it cannot leak into a
   log line, a traceback, an error message, or `/api/docs` by accident. Reading one
   requires an explicit `.get_secret_value()`, which is greppable in review.
2. **Fail fast, loudly.** The dev defaults below are deliberately recognisable
   sentinels. Booting outside `local` while any of them is still in place raises at
   startup instead of silently running an app whose JWTs anyone can forge.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Placeholder values shipped in .env.example and docker-compose.yml. Recognisable on
# purpose: their only job is to be rejected outside local development.
# ruff S105 flags these on name alone. They are not credentials — they are the
# rejection targets of `_reject_dev_secrets_outside_local`, covered by tests in
# tests/test_config.py. Suppressed here rather than project-wide so that a real
# hardcoded secret anywhere else still fails the build.
DEV_JWT_SECRET = "dev-only-insecure-change-me"  # noqa: S105
DEV_PSEUDONYM_SALT = "dev-only-insecure-salt"
DEV_S3_SECRET = "tenexminio123"  # noqa: S105

_SENTINELS = {
    "jwt_secret": DEV_JWT_SECRET,
    "pseudonym_salt": DEV_PSEUDONYM_SALT,
    "s3_secret_key": DEV_S3_SECRET,
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["local", "staging", "production"] = "local"

    # --- Infrastructure ---
    database_url: str = "postgresql+psycopg://tenex:tenex@localhost:5432/tenex"
    rabbitmq_url: str = "amqp://tenex:tenex@localhost:5672/"
    redis_url: str = "redis://localhost:6379/0"

    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: str = "tenexminio"
    s3_secret_key: SecretStr = SecretStr(DEV_S3_SECRET)
    s3_bucket: str = "tenex-uploads"

    # --- Auth ---
    jwt_secret: SecretStr = SecretStr(DEV_JWT_SECRET)
    jwt_ttl_minutes: int = 60
    jwt_algorithm: Literal["HS256"] = "HS256"

    # --- Privacy ---
    # Per-tenant HMAC salt. Never logged, never in an error message, never in a prompt.
    pseudonym_salt: SecretStr = SecretStr(DEV_PSEUDONYM_SALT)

    # --- LLM ---
    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-opus-5"
    max_triage_incidents: int = 15
    agent_max_tool_calls: int = 8
    agent_timeout_seconds: int = 120
    demo_mode: bool = False

    # --- Ingest limits ---
    max_upload_bytes: int = 200 * 1024 * 1024
    allowed_upload_suffixes: tuple[str, ...] = (".log", ".txt", ".json", ".jsonl", ".csv")

    # --- HTTP ---
    # NoDecode is load-bearing, not decoration. pydantic-settings JSON-decodes any
    # complex-typed field coming from an env var *before* field validators run, so
    # without it CORS_ORIGINS="https://a,https://b" dies inside json.loads and the
    # splitter below never executes. That crash-looped the API on first deploy.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )
    log_level: str = "info"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        """Accept a comma-delimited string so one env var can carry several origins."""
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @model_validator(mode="after")
    def _reject_dev_secrets_outside_local(self) -> Settings:
        if self.environment == "local":
            return self

        unset = [
            name
            for name, sentinel in _SENTINELS.items()
            if getattr(self, name).get_secret_value() in {sentinel, ""}
        ]
        if unset:
            raise ValueError(
                f"environment={self.environment} but these secrets are still at their "
                f"development defaults: {', '.join(sorted(unset))}. Set them in the "
                f"environment before starting."
            )
        return self

    @property
    def llm_enabled(self) -> bool:
        """The pipeline runs end to end without a key; only agentic triage is skipped."""
        return bool(self.anthropic_api_key.get_secret_value()) and not self.demo_mode


@lru_cache
def get_settings() -> Settings:
    return Settings()
