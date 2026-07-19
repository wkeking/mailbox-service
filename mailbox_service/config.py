"""Application configuration loaded from environment variables."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_optional_secret_file(file_path: str | None) -> str | None:
    """Load a secret from a Docker/K8s secret file when the path is set."""
    if not file_path:
        return None
    secret_path = Path(file_path).expanduser()
    if not secret_path.is_file():
        raise ValueError(f"secret file does not exist: {secret_path}")
    return secret_path.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    """Runtime settings for the single-instance mailbox service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "mysql+pymysql://mailbox_service:mailbox_service@127.0.0.1:3306/mailbox_service"
    # Apply pending migrations/*.sql on process startup (records versions in schema_migrations).
    auto_migrate_on_startup: bool = True
    # Optional absolute/relative path to the migrations directory; empty uses CWD or package root.
    migrations_dir: str | None = None
    admin_api_token: str | None = None
    admin_api_token_file: str | None = None
    credential_encryption_key: str | None = None
    credential_encryption_key_file: str | None = None
    app_env: Literal["development", "test", "production"] = "production"
    debug_token_logging: bool = False
    # Comma-separated browser origins for CORS. Use "*" only when the admin UI
    # is not relying on credentialed cross-site cookies (this project uses headers).
    cors_allow_origins: str = "http://localhost:5173"
    # Trusted reverse-proxy CIDRs/IPs for Forwarded headers (never "*' in production).
    forwarded_allow_ips: str = "127.0.0.1"
    trusted_hosts: str = "localhost,127.0.0.1"
    # When true, emit HSTS only on responses already known to be HTTPS.
    enable_hsts: bool = False
    hsts_max_age_seconds: int = Field(default=86_400, ge=0, le=63_072_000)
    tls_mode: Literal["disabled", "terminated_at_proxy", "direct"] = "disabled"

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
    token_refresh_claim_ttl_seconds: int = Field(default=45, ge=5, le=300)

    # Refresh Token keepalive: Microsoft identity platform default RT lifetime is ~90 days
    # for non-SPA confidential/public client flows. Each successful refresh may rotate RT.
    refresh_token_keepalive_enabled: bool = True
    refresh_token_keepalive_interval_seconds: int = Field(default=86_400, ge=300, le=604_800)
    refresh_token_lifetime_days: int = Field(default=90, ge=1, le=365)
    refresh_token_keepalive_lead_days: int = Field(default=7, ge=0, le=90)
    refresh_token_keepalive_batch_size: int = Field(default=20, ge=1, le=500)
    scheduler_job_lease_seconds: int = Field(default=120, ge=15, le=3600)

    # Batch worker and database pool budgets (SEC-05).
    batch_max_workers: int = Field(default=8, ge=1, le=64)
    database_pool_size: int = Field(default=16, ge=1, le=128)
    database_max_overflow: int = Field(default=8, ge=0, le=128)
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    database_pool_recycle_seconds: int = Field(default=1800, ge=60, le=86_400)
    database_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    # Verification-code long-poll capacity (SEC-09 / SEC-03).
    mail_poll_max_concurrency: int = Field(default=32, ge=1, le=512)
    mail_poll_max_concurrency_per_client: int = Field(default=4, ge=1, le=64)
    mail_poll_max_concurrency_per_lease: int = Field(default=1, ge=1, le=8)
    mail_scan_timeout_seconds: float = Field(default=10.0, gt=0, le=120)

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

    @property
    def trusted_hosts_list(self) -> list[str]:
        """Parse TRUSTED_HOSTS into host patterns for TrustedHostMiddleware."""
        raw_value = (self.trusted_hosts or "").strip()
        if not raw_value:
            return ["localhost", "127.0.0.1"]
        return [host.strip() for host in raw_value.split(",") if host.strip()]

    @property
    def forwarded_allow_ips_list(self) -> list[str]:
        """Parse FORWARDED_ALLOW_IPS into proxy trust entries."""
        raw_value = (self.forwarded_allow_ips or "").strip()
        if not raw_value:
            return ["127.0.0.1"]
        return [entry.strip() for entry in raw_value.split(",") if entry.strip()]

    @property
    def database_worker_budget(self) -> int:
        """Max concurrent batch workers that should checkout a DB connection."""
        # Reserve headroom for request handlers, schedulers, and admin sessions.
        reserved_connections = 4
        total_connections = self.database_pool_size + self.database_max_overflow
        return max(1, min(self.batch_max_workers, total_connections - reserved_connections))

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

    @model_validator(mode="after")
    def apply_secret_files_and_production_guards(self) -> Settings:
        """Resolve *_FILE secrets and fail closed for production misconfiguration."""
        if not self.admin_api_token and self.admin_api_token_file:
            object.__setattr__(self, "admin_api_token", _read_optional_secret_file(self.admin_api_token_file))
        if not self.credential_encryption_key and self.credential_encryption_key_file:
            object.__setattr__(
                self,
                "credential_encryption_key",
                _read_optional_secret_file(self.credential_encryption_key_file),
            )

        if self.app_env != "production":
            return self
        # Unit tests often construct Settings(app_env="production") against in-memory SQLite.
        # Fail-closed production checks apply only to real MySQL (or other non-sqlite) deployments.
        if self.database_url.startswith("sqlite"):
            return self

        weak_admin_tokens = {
            None,
            "",
            "replace-with-a-long-random-admin-token",
            "change-me",
            "admin",
            "root",
        }
        # Require more than 10 characters; still reject common placeholders.
        if self.admin_api_token in weak_admin_tokens or (
            self.admin_api_token is not None and len(self.admin_api_token) <= 10
        ):
            raise ValueError("production 要求 ADMIN_API_TOKEN 长度大于 10 位")

        if not self.credential_encryption_key:
            raise ValueError("production 要求配置 CREDENTIAL_ENCRYPTION_KEY")
        if self.credential_encryption_key.startswith("replace-with"):
            raise ValueError("production 禁止使用示例 CREDENTIAL_ENCRYPTION_KEY")

        # Intentionally allow production historical deployments that use:
        # - DATABASE_URL with root (or other privileged) MySQL accounts
        # - CORS_ALLOW_ORIGINS=* for header-auth admin UI cross-origin access
        # - TLS_MODE=disabled when TLS is handled outside this process
        # Operators should still prefer least-privilege DB users and explicit CORS when feasible.

        if "*" in self.forwarded_allow_ips_list:
            raise ValueError("production 禁止 FORWARDED_ALLOW_IPS=*")

        return self


def _extract_database_username(database_url: str) -> str | None:
    """Extract the database username from a SQLAlchemy URL when present."""
    try:
        parsed = urlparse(database_url)
    except ValueError:
        return None
    if parsed.username:
        return parsed.username
    # SQLAlchemy style may put credentials before @ without standard URL parsing.
    if "://" not in database_url or "@" not in database_url:
        return None
    credentials = database_url.split("://", 1)[1].split("@", 1)[0]
    if ":" in credentials:
        return credentials.split(":", 1)[0] or None
    return credentials or None


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""
    return Settings()
