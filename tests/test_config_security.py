"""Production configuration guards that remain after historical-deployment exceptions."""

from __future__ import annotations

from base64 import urlsafe_b64encode

import pytest
from pydantic import ValidationError

from mailbox_service.config import Settings


def _production_encryption_key() -> str:
    return urlsafe_b64encode(b"k" * 32).decode("ascii")


def test_production_allows_root_database_user_and_wildcard_cors() -> None:
    """Historical production deploys may use root MySQL credentials and CORS=*."""
    settings = Settings(
        app_env="production",
        database_url="mysql+pymysql://root:root@db:3306/mailbox_service",
        admin_api_token="long-enough-admin-token-value",
        credential_encryption_key=_production_encryption_key(),
        cors_allow_origins="*",
        tls_mode="disabled",
        forwarded_allow_ips="10.0.0.1",
    )
    assert settings.cors_origins_list == ["*"]
    assert "root:root@" in settings.database_url


def test_production_rejects_wildcard_forwarded_allow_ips() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            database_url="mysql+pymysql://mailbox_runtime:secret@db:3306/mailbox_service",
            admin_api_token="long-enough-admin-token-value",
            credential_encryption_key=_production_encryption_key(),
            cors_allow_origins="*",
            tls_mode="terminated_at_proxy",
            forwarded_allow_ips="*",
        )


def test_production_rejects_admin_token_not_longer_than_ten() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            database_url="mysql+pymysql://root:root@db:3306/mailbox_service",
            admin_api_token="1234567890",  # exactly 10 — must be greater than 10
            credential_encryption_key=_production_encryption_key(),
            cors_allow_origins="*",
            tls_mode="disabled",
            forwarded_allow_ips="127.0.0.1",
        )


def test_production_accepts_admin_token_longer_than_ten() -> None:
    settings = Settings(
        app_env="production",
        database_url="mysql+pymysql://root:root@db:3306/mailbox_service",
        admin_api_token="a18766397268",  # 12 chars
        credential_encryption_key=_production_encryption_key(),
        cors_allow_origins="*",
        tls_mode="disabled",
        forwarded_allow_ips="127.0.0.1",
    )
    assert settings.admin_api_token == "a18766397268"


def test_development_allows_sqlite_defaults() -> None:
    settings = Settings(app_env="development", database_url="sqlite+pysqlite:///:memory:")
    assert settings.app_env == "development"
