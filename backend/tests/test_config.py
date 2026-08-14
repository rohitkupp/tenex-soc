"""Settings must refuse to boot with development secrets outside local.

A security product that silently runs with a forgeable JWT secret is worse than
one that refuses to start, so this behaviour is tested rather than assumed.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import DEV_JWT_SECRET, DEV_PSEUDONYM_SALT, DEV_S3_SECRET, Settings

REAL = {
    "jwt_secret": SecretStr("a-real-48-byte-secret-from-the-environment"),
    "pseudonym_salt": SecretStr("a-real-per-tenant-salt"),
    "s3_secret_key": SecretStr("a-real-object-store-key"),
}


def test_local_tolerates_dev_defaults() -> None:
    settings = Settings(environment="local")
    assert settings.jwt_secret.get_secret_value() == DEV_JWT_SECRET


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
        Settings(environment="production", **kwargs)


def test_production_boots_once_every_secret_is_real() -> None:
    settings = Settings(environment="production", **REAL)
    assert settings.environment == "production"


def test_secrets_never_render_in_repr() -> None:
    """SecretStr is what stops a secret reaching a log line or a traceback."""
    settings = Settings(environment="local")
    assert DEV_JWT_SECRET not in repr(settings)
    assert DEV_PSEUDONYM_SALT not in str(settings.model_dump())


def test_llm_disabled_without_a_key() -> None:
    assert Settings(environment="local").llm_enabled is False
    assert Settings(environment="local", anthropic_api_key=SecretStr("sk-x")).llm_enabled is True


def test_demo_mode_disables_the_llm_even_with_a_key() -> None:
    """DEMO_MODE must never spend API budget — the deployed demo relies on this."""
    settings = Settings(environment="local", anthropic_api_key=SecretStr("sk-x"), demo_mode=True)
    assert settings.llm_enabled is False


def test_cors_origins_accepts_a_comma_delimited_string() -> None:
    """docker-compose can only pass one env var, so the string form has to work."""
    settings = Settings(environment="local", cors_origins="http://a.test, http://b.test")
    assert settings.cors_origins == ["http://a.test", "http://b.test"]
