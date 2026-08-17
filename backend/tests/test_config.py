"""Settings must refuse to boot with development secrets outside local.

A security product that silently runs with a forgeable JWT secret is worse than
one that refuses to start, so this behaviour is tested rather than assumed.

These tests assert Settings' *default* behaviour, so they must not read the
developer's `.env`. Whether a contributor happens to have an ANTHROPIC_API_KEY
(or, since M15, SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY) configured locally is not
allowed to change whether the suite passes — a test that is green on one machine
and red on another tells you nothing.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import (
    DEV_JWT_SECRET,
    DEV_PSEUDONYM_SALT,
    DEV_S3_SECRET,
    DEV_TIER2_INDICATOR_SALT,
    DEV_TIER2_READONLY_DB_PASSWORD,
    Settings,
)

REAL = {
    "jwt_secret": SecretStr("a-real-48-byte-secret-from-the-environment"),
    "pseudonym_salt": SecretStr("a-real-per-tenant-salt"),
    "s3_secret_key": SecretStr("a-real-object-store-key"),
    "tier2_indicator_salt": SecretStr("a-real-shared-indicator-salt"),
    "tier2_readonly_db_password": SecretStr("a-real-readonly-db-password"),
}


def make_settings(**overrides: Any) -> Settings:
    """Construct Settings in isolation from any on-disk `.env` -- AND from this process's real
    environment variables.

    `_env_file=None` only disables pydantic-settings' dotenv source; the environment-variable
    source still reads real process env vars, and docker-compose passes a live
    ANTHROPIC_API_KEY into this container (see this module's own docstring). Init-supplied
    fields are the only source that outranks env vars, so every caller gets an explicit
    `anthropic_api_key=""` default here unless it says otherwise -- "no key configured" is what
    every test in this file that doesn't ask for a real one means by "default settings". Same
    defect, same fix, as `tests/test_tier2_api.py`'s `_force_no_key_settings` used to apply
    (that fixture is gone along with the NL-to-SQL chatbot route it guarded).

    `supabase_url`/`supabase_service_role_key` get the identical treatment and for the identical
    reason: they gate a real, side-effecting Supabase call
    (`app.core.verification.send_verification_email`, netted for the whole suite by
    `tests/conftest.py`'s `_forbid_live_verification_email_calls`) the same way `anthropic_api_key`
    gates a live LLM call, and this container's environment can carry real values for either.
    Without this default, `test_email_verification_disabled_without_supabase_config` would be
    reasoning from the ambient absence of `SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY` in
    `backend/.env` rather than asserting a real default -- and would flip from green to enabled
    (silently wrong, not merely flaky) the moment those two vars are ever set in this container to
    test signup against a live Supabase project.
    """
    overrides.setdefault("anthropic_api_key", "")
    overrides.setdefault("supabase_url", "")
    overrides.setdefault("supabase_service_role_key", SecretStr(""))
    return Settings(_env_file=None, **overrides)


def test_local_tolerates_dev_defaults() -> None:
    cfg = make_settings(environment="local")
    assert cfg.jwt_secret.get_secret_value() == DEV_JWT_SECRET


@pytest.mark.parametrize(
    ("field", "sentinel"),
    [
        ("jwt_secret", DEV_JWT_SECRET),
        ("pseudonym_salt", DEV_PSEUDONYM_SALT),
        ("s3_secret_key", DEV_S3_SECRET),
        ("tier2_indicator_salt", DEV_TIER2_INDICATOR_SALT),
        ("tier2_readonly_db_password", DEV_TIER2_READONLY_DB_PASSWORD),
    ],
)
def test_production_rejects_each_dev_default(field: str, sentinel: str) -> None:
    kwargs = {**REAL, field: SecretStr(sentinel)}
    with pytest.raises(ValidationError, match=field):
        make_settings(environment="production", **kwargs)


def test_production_boots_once_every_secret_is_real() -> None:
    cfg = make_settings(environment="production", **REAL)
    assert cfg.environment == "production"


def test_secrets_never_render_in_repr() -> None:
    """SecretStr is what stops a secret reaching a log line or a traceback."""
    cfg = make_settings(environment="local")
    assert DEV_JWT_SECRET not in repr(cfg)
    assert DEV_PSEUDONYM_SALT not in str(cfg.model_dump())


def test_llm_disabled_without_a_key() -> None:
    assert make_settings(environment="local").llm_enabled is False
    assert (
        make_settings(environment="local", anthropic_api_key=SecretStr("sk-x")).llm_enabled is True
    )


def test_email_verification_disabled_without_supabase_config() -> None:
    """`make_settings()` forces `supabase_url`/`supabase_service_role_key` to their empty
    defaults by default (see that helper's docstring) the same way it already forces
    `anthropic_api_key=""` -- so this holds regardless of what this container's ambient
    environment happens to carry, not because `backend/.env` happens not to set those two vars
    today. This is still, incidentally, the state the entire test suite (and a fresh `make up`)
    actually runs in -- it just no longer has to be, for this assertion to be true."""
    assert make_settings(environment="local").email_verification_enabled is False
    assert (
        make_settings(
            environment="local", supabase_url="", supabase_service_role_key=SecretStr("")
        ).email_verification_enabled
        is False
    )


def test_email_verification_enabled_once_both_supabase_settings_are_set() -> None:
    cfg = make_settings(
        environment="local",
        supabase_url="https://project.supabase.co",
        supabase_service_role_key=SecretStr("service-role-key"),
    )
    assert cfg.email_verification_enabled is True


def test_cors_origins_accepts_a_comma_delimited_string() -> None:
    """docker-compose can only pass one env var, so the string form has to work."""
    cfg = make_settings(environment="local", cors_origins="http://a.test, http://b.test")
    assert cfg.cors_origins == ["http://a.test", "http://b.test"]


def test_settings_do_not_leak_the_developers_dotenv() -> None:
    """Regression guard for the bug this file's docstring describes -- previously a hole itself:
    it went through `make_settings()`, which (before that helper's own fix, above) only passed
    `_env_file=None` and so still inherited a real key from this container's environment, the
    exact leak this test exists to catch. It read green in CI (no key in the environment there)
    and would have stayed green here too, on a container docker-compose hands a live
    ANTHROPIC_API_KEY -- "regression guard" in name only. Now that `make_settings()` forces
    `anthropic_api_key=""` by default, this assertion is a real guard on that contract: it goes
    red the moment anyone drops that default, in every environment, key or no key.
    """
    assert make_settings(environment="local").anthropic_api_key.get_secret_value() == ""


def test_cors_origins_parses_from_a_real_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: this is the path that crash-looped the API on first deploy.

    The sibling test passes a Python list, which bypasses the env-var decode
    entirely. pydantic-settings JSON-decodes complex-typed fields sourced from the
    environment *before* validators run, so only a genuine env var reproduces it.
    """
    monkeypatch.setenv("CORS_ORIGINS", "https://a.vercel.app,https://b.vercel.app")
    cfg = Settings(_env_file=None)
    assert cfg.cors_origins == ["https://a.vercel.app", "https://b.vercel.app"]


def test_cors_origins_accepts_a_single_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "https://only.vercel.app")
    assert Settings(_env_file=None).cors_origins == ["https://only.vercel.app"]
