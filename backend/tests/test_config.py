"""Settings must refuse to boot with development secrets outside local.

A security product that silently runs with a forgeable JWT secret is worse than
one that refuses to start, so this behaviour is tested rather than assumed.

These tests assert Settings' *default* behaviour, so they must not read the
developer's `.env`. Whether a contributor happens to have an ANTHROPIC_API_KEY
configured locally is not allowed to change whether the suite passes — a test
that is green on one machine and red on another tells you nothing.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import DEV_JWT_SECRET, DEV_PSEUDONYM_SALT, DEV_S3_SECRET, Settings

REAL = {
    "jwt_secret": SecretStr("a-real-48-byte-secret-from-the-environment"),
    "pseudonym_salt": SecretStr("a-real-per-tenant-salt"),
    "s3_secret_key": SecretStr("a-real-object-store-key"),
}


def make_settings(**overrides: Any) -> Settings:
    """Construct Settings in isolation from any on-disk `.env`."""
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


def test_demo_mode_disables_the_llm_even_with_a_key() -> None:
    """DEMO_MODE must never spend API budget — the deployed demo relies on this."""
    cfg = make_settings(environment="local", anthropic_api_key=SecretStr("sk-x"), demo_mode=True)
    assert cfg.llm_enabled is False


def test_cors_origins_accepts_a_comma_delimited_string() -> None:
    """docker-compose can only pass one env var, so the string form has to work."""
    cfg = make_settings(environment="local", cors_origins="http://a.test, http://b.test")
    assert cfg.cors_origins == ["http://a.test", "http://b.test"]


def test_settings_do_not_leak_the_developers_dotenv() -> None:
    """Regression guard for the bug this file's docstring describes.

    A real key in backend/.env previously made `llm_enabled` true, turning the
    suite red for anyone who had configured one.
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
