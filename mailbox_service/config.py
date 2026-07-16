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
    # Comma-separated browser origins for CORS. Use "*" only when the admin UI
    # is not relying on credentialed cross-site cookies (this project uses headers).
    cors_allow_origins: str = "http://localhost:5173"

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

    # Refresh Token keepalive: Microsoft identity platform default RT lifetime is ~90 days
    # for non-SPA confidential/public client flows. Each successful refresh may rotate RT.
    refresh_token_keepalive_enabled: bool = True
    refresh_token_keepalive_interval_seconds: int = Field(default=86_400, ge=300, le=604_800)
    refresh_token_lifetime_days: int = Field(default=90, ge=1, le=365)
    refresh_token_keepalive_lead_days: int = Field(default=7, ge=0, le=90)
    refresh_token_keepalive_batch_size: int = Field(default=20, ge=1, le=500)

    @property
    def token_diagnostic_logging_enabled(self) -> bool:
        """Allow sensitive-adjacent Token diagnostics only in explicit development mode."""
        return self.app_env == "development" and self.debug_token_logging

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ALLOW_ORIGINS into a list suitable for CORSMiddleware."""
        raw_value = (self.cors_allow_origins or "").strip()
        if not raw_value:
            return ["http://localhost:5173"]
        if raw_value == "*":
            return ["*"]
        return [origin.strip() for origin in raw_value.split(",") if origin.strip()]

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
