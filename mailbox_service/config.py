"""Application configuration loaded from environment variables."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the single-instance mailbox service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "mysql+pymysql://mailbox_service:mailbox_service@127.0.0.1:3306/mailbox_service"
    admin_api_token: str | None = None
    credential_encryption_key: str | None = None
    app_env: Literal["development", "test", "production"] = "production"
    debug_token_logging: bool = False

    proxy_enabled: bool = True
    proxy_required: bool = False
    proxy_connect_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    proxy_read_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    proxy_failure_threshold: int = Field(default=3, ge=1, le=100)
    proxy_cooldown_seconds: int = Field(default=300, ge=30, le=86_400)
    proxy_switch_minimum_interval_seconds: int = Field(default=60, ge=0, le=86_400)
    proxy_health_check_interval_seconds: int = Field(default=300, ge=30, le=86_400)

    microsoft_token_endpoint: str = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    )
    microsoft_imap_host: str = "outlook.office365.com"
    microsoft_imap_port: int = Field(default=993, ge=1, le=65535)
    microsoft_graph_messages_url: str = "https://graph.microsoft.com/v1.0/me/messages?$top=1"
    access_token_refresh_skew_seconds: int = Field(default=120, ge=0, le=3600)

    @property
    def token_diagnostic_logging_enabled(self) -> bool:
        """Allow sensitive-adjacent Token diagnostics only in explicit development mode."""
        return self.app_env == "development" and self.debug_token_logging

    @field_validator("credential_encryption_key")
    @classmethod
    def validate_encryption_key(cls, value: str | None) -> str | None:
        """Reject malformed AES-GCM keys before any secrets are persisted."""
        if value is None:
            return value

        try:
            decoded_key = urlsafe_b64decode(value)
        except ValueError as error:
            raise ValueError("credential_encryption_key 必须为 URL-safe Base64") from error

        if len(decoded_key) != 32:
            raise ValueError("credential_encryption_key 解码后必须为 32 字节")

        return value


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""
    return Settings()
