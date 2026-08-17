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
# M14 (app/tier2) additions. See that package's __init__.py for the shared-vs-per-tenant
# salt tradeoff docs/06-PRIVACY-SECURITY.md requires; these are the same
# recognisable-sentinel / fail-fast-outside-local pattern as every secret above.
DEV_TIER2_INDICATOR_SALT = "dev-only-insecure-shared-indicator-salt"
DEV_TIER2_READONLY_DB_PASSWORD = "dev-only-insecure-tier2-readonly-password"  # noqa: S105

_SENTINELS = {
    "jwt_secret": DEV_JWT_SECRET,
    "pseudonym_salt": DEV_PSEUDONYM_SALT,
    "s3_secret_key": DEV_S3_SECRET,
    "tier2_indicator_salt": DEV_TIER2_INDICATOR_SALT,
    "tier2_readonly_db_password": DEV_TIER2_READONLY_DB_PASSWORD,
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
    # Must be a key in `app.agent.client._MODEL_RATES` — pricing and the prompt-cache floor are
    # both model-specific there, and an id absent from that table raises rather than guessing.
    anthropic_model: str = "claude-sonnet-5"
    max_triage_incidents: int = 20
    agent_max_tool_calls: int = 8
    agent_timeout_seconds: int = 120

    # --- Auth: self-serve signup email verification (M15, app.core.verification) ---
    # Supabase Auth's built-in email sender is the transport; our own Postgres row is
    # the durable record of the outcome. Deliberately *not* in `_SENTINELS` below --
    # unlike jwt_secret/pseudonym_salt/etc, an unset value here is not an unsafe state
    # to boot in. It just leaves `email_verification_enabled` False, and
    # `app.api.auth.signup` falls back to auto-verifying every new account (loudly
    # logged there) instead of refusing to start. That fallback is what keeps a fresh
    # `make up` — no Supabase project, no keys — usable, and what keeps the existing
    # test suite green without every test needing to know about Supabase.
    supabase_url: str = ""
    supabase_service_role_key: SecretStr = SecretStr("")
    # Where Supabase redirects the browser after the user clicks the verification
    # link (`?verified=1` on the login route lets the frontend show a confirmation
    # toast instead of a bare login form).
    frontend_base_url: str = "http://localhost:3000"

    # --- Tier 2 (docs/06 "Text-to-SQL safety", app/tier2) ---
    # Deliberately *shared* across every tenant -- see app/tier2/__init__.py for why this
    # is the one salt in the whole system that is not per-tenant.
    tier2_indicator_salt: SecretStr = SecretStr(DEV_TIER2_INDICATOR_SALT)
    # Password for the dedicated, SELECT-only `tier2_readonly` Postgres role
    # (alembic/versions/*_tier2_readonly_role_and_views.py) -- never the app's own
    # privileged DB user. Originally the execution role for an NL->SQL chatbot, now removed
    # (cost constraint: no live Anthropic calls); the role/migration are kept and still
    # exercised directly by tests/test_tier2_readonly_role.py -- see app.tier2.readonly_db's
    # docstring. Read by both the migration (to provision/rotate the role's password) and
    # app.tier2.readonly_db (to connect as it), so the two can never drift apart.
    tier2_readonly_db_password: SecretStr = SecretStr(DEV_TIER2_READONLY_DB_PASSWORD)

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
        """Whether a real Anthropic API key is configured. The upload pipeline (parse through
        correlate) always runs regardless; only agentic triage depends on this. Unlike the old
        DEMO_MODE-era version of this property, a false value here is no longer treated as a
        normal, silently-handled state by `app.agent.orchestrator` — see that module's docstring.
        (Tier 2's own no-key fallback, `app.tier2.nl_to_sql`'s canned-example path, is gone along
        with that chatbot route — this property's remaining callers are all in the triage path.)"""
        return bool(self.anthropic_api_key.get_secret_value())

    @property
    def email_verification_enabled(self) -> bool:
        """Both Supabase settings must be present. See `app.core.verification` and the
        `supabase_url`/`supabase_service_role_key` fields above for what happens on
        either side of this flag."""
        return bool(self.supabase_url) and bool(self.supabase_service_role_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    return Settings()
