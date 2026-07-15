"""API schemas that avoid returning egress proxy authentication material."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mailbox_service.models import EgressProxyProtocol, EgressProxyStatus, LeaseMode, MailboxStatus


class EgressProxyCreate(BaseModel):
    """Writable fields for registering a global egress proxy."""

    name: str = Field(min_length=1, max_length=100)
    protocol: EgressProxyProtocol
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=4096)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1_000_000)

    @field_validator("name", "host")
    @classmethod
    def normalize_nonempty_text(cls, value: str) -> str:
        """Normalize routing identifiers while rejecting whitespace-only values."""
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("字段不能为空")
        return normalized_value


class EgressProxyUpdate(BaseModel):
    """Optional writable fields; omitted credentials remain untouched."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    protocol: EgressProxyProtocol | None = None
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=4096)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=1_000_000)

    @field_validator("name", "host")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("字段不能为空")
        return normalized_value


class EgressProxyResponse(BaseModel):
    """Safe proxy representation intentionally excluding username and password."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    protocol: EgressProxyProtocol
    host_preview: str
    port: int
    enabled: bool
    priority: int
    status: EgressProxyStatus
    has_credentials: bool
    consecutive_failure_count: int
    cooldown_until: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error_summary: str | None
    bound_mailbox_count: int = 0
    created_at: datetime
    updated_at: datetime


class ProxyPolicyResponse(BaseModel):
    """Safe configuration returned to administrators."""

    model_config = ConfigDict(from_attributes=True)

    enabled: bool
    required: bool
    allowed_protocols: list[str]
    connect_timeout_seconds: int
    read_timeout_seconds: int
    health_check_interval_seconds: int
    failure_threshold: int
    cooldown_seconds: int
    switch_minimum_interval_seconds: int
    allow_direct_development: bool
    updated_at: datetime


class ProxyPolicyUpdate(BaseModel):
    """Administrative updates for global proxy routing behavior."""

    enabled: bool | None = None
    required: bool | None = None
    allowed_protocols: list[EgressProxyProtocol] | None = None
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    read_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    health_check_interval_seconds: int | None = Field(default=None, ge=30, le=86_400)
    failure_threshold: int | None = Field(default=None, ge=1, le=100)
    cooldown_seconds: int | None = Field(default=None, ge=30, le=86_400)
    switch_minimum_interval_seconds: int | None = Field(default=None, ge=0, le=86_400)
    allow_direct_development: bool | None = None


class ProxyConnectivityTestResponse(BaseModel):
    """Result of a bounded proxy handshake test without remote response content."""

    successful: bool
    error_code: str | None = None
    error_summary: str | None = None


class ProxyBoundMailboxResponse(BaseModel):
    """Mailbox metadata exposed from the proxy impact endpoint."""

    id: str
    primary_email: str
    status: str
    proxy_bound_at: datetime | None
    proxy_last_switch_at: datetime | None


class ProxyBindingUpdate(BaseModel):
    """Manual binding update; null explicitly requests direct routing."""

    egress_proxy_id: str | None = None


class MailboxImportRequest(BaseModel):
    """Bulk mailbox import payload using the four-segment text format."""

    content: str = Field(min_length=1)
    on_conflict: str = Field(default="replace_token", pattern="^(skip|replace_token|error)$")


class MailboxImportLineError(BaseModel):
    """A validation error for one import line."""

    line_number: int
    message: str


class MailboxImportResponse(BaseModel):
    """Bulk import result summary safe for UI display."""

    created: int
    updated: int
    skipped: int
    failed: int
    errors: list[MailboxImportLineError]


class MailboxAccessTokenResponse(BaseModel):
    """A usable access token returned only by protected token endpoints."""

    mailbox_id: str
    primary_email: str
    access_token: str
    expires_at: datetime
    token_version: int
    refreshed: bool
    refresh_token_rotated: bool


class MailboxAccessTokenRefreshRequest(BaseModel):
    """Administrative batch refresh request; null or empty means all active mailboxes."""

    mailbox_ids: list[str] | None = None


class MailboxAccessTokenRefreshItemResponse(BaseModel):
    """One mailbox result in an administrative access-token refresh batch."""

    mailbox_id: str
    primary_email: str | None
    successful: bool
    refreshed: bool
    refresh_token_rotated: bool
    access_token_expires_at: datetime | None
    error_summary: str | None = None


class MailboxAccessTokenRefreshResponse(BaseModel):
    """Batch AT refresh summary safe for UI display."""

    successful: int
    failed: int
    results: list[MailboxAccessTokenRefreshItemResponse]


class DashboardSummaryResponse(BaseModel):
    """Compact overview metrics for the admin dashboard."""

    total_mailbox_count: int
    active_mailbox_count: int
    invalid_mailbox_count: int
    disabled_mailbox_count: int
    cooldown_mailbox_count: int
    active_lease_count: int
    expired_lease_count: int
    total_proxy_count: int
    healthy_proxy_count: int
    cooldown_proxy_count: int
    bound_mailbox_count: int
    recent_audit_count: int


class MailboxListItemResponse(BaseModel):
    """Safe mailbox list item for the Admin console."""

    id: str
    primary_email: str
    status: MailboxStatus
    client_id: str | None
    token_version: int
    egress_proxy_id: str | None
    egress_proxy_name: str | None
    proxy_bound_at: datetime | None
    proxy_last_switch_at: datetime | None
    has_access_token: bool
    access_token_expires_at: datetime | None
    access_token_refreshed_at: datetime | None
    scope: str | None
    capability: str | None
    capability_probed_at: datetime | None
    capability_probe_error: str | None
    active_lease_count: int
    created_at: datetime
    updated_at: datetime


class MailboxListResponse(BaseModel):
    """Paginated mailbox list response for the Admin console."""

    total: int
    page: int
    page_size: int
    total_pages: int
    items: list[MailboxListItemResponse]


class LeaseListItemResponse(BaseModel):
    """Lease list item with mailbox metadata but without secrets."""

    id: str
    mailbox_id: str
    primary_email: str
    client_key_id: str | None
    client_tag: str | None
    purpose: str | None
    mode: LeaseMode
    status: str
    expires_at: datetime
    released_at: datetime | None
    created_at: datetime


class LeaseListResponse(BaseModel):
    """Paginated lease list response for the Admin console."""

    total: int
    page: int
    page_size: int
    total_pages: int
    items: list[LeaseListItemResponse]


class ClientKeyCreateRequest(BaseModel):
    """管理员创建外部 Client Key 的请求。"""

    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def normalize_client_key_name(cls, value: str) -> str:
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("Client Key 名称不能为空")
        return normalized_value


class ClientKeyCreatedResponse(BaseModel):
    """包含仅显示一次的 API Key 明文的创建响应。"""

    id: str
    name: str
    api_key: str
    scopes: list[str]
    enabled: bool
    expires_at: datetime | None
    created_at: datetime


class ClientKeyListItemResponse(BaseModel):
    """不包含 API Key 明文或摘要的管理列表项。"""

    id: str
    name: str
    scopes: list[str]
    enabled: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime


class LeaseAcquireRequest(BaseModel):
    """外部调用方领取邮箱租约的请求。"""

    mode: Literal[LeaseMode.ACCESS_TOKEN, LeaseMode.REFRESH_TOKEN]
    lease_ttl_seconds: int = Field(default=600, ge=60, le=86_400)
    preferred_email: str | None = Field(default=None, max_length=320)
    client_tag: str | None = Field(default=None, max_length=100)
    purpose: str | None = Field(default=None, max_length=100)

    @field_validator("preferred_email", "client_tag", "purpose")
    @classmethod
    def normalize_optional_lease_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_value = value.strip()
        return normalized_value or None


class AccessTokenLeaseCredentialResponse(BaseModel):
    """Access Token mode 租约返回的短期凭证。"""

    type: Literal["access_token"] = "access_token"
    access_token: str
    expires_at: datetime
    refreshed: bool
    token_version: int


class RefreshTokenLeaseCredentialResponse(BaseModel):
    """Refresh Token mode 租约返回的长期凭证。"""

    type: Literal["refresh_token"] = "refresh_token"
    client_id: str
    refresh_token: str
    token_version: int


LeaseCredentialResponse = Annotated[
    AccessTokenLeaseCredentialResponse | RefreshTokenLeaseCredentialResponse,
    Field(discriminator="type"),
]


class LeaseAcquireResponse(BaseModel):
    """外部邮箱租约及其 mode 对应凭证。"""

    lease_id: str
    mailbox_id: str
    primary_email: str
    mode: LeaseMode
    expires_at: datetime
    created_at: datetime
    credential: LeaseCredentialResponse


class LeaseReleaseResponse(BaseModel):
    """幂等租约释放响应。"""

    lease_id: str
    released_at: datetime


class LeaseAccessTokenResponse(BaseModel):
    """有效租约内返回的可用 Access Token。"""

    lease_id: str
    mailbox_id: str
    primary_email: str
    access_token: str
    expires_at: datetime
    token_version: int
    refreshed: bool
    refresh_token_rotated: bool


class LeaseRefreshTokenUpdateRequest(BaseModel):
    """使用 token_version 进行 CAS 的 Refresh Token 回写请求。"""

    expected_token_version: int = Field(ge=1)
    refresh_token: str = Field(min_length=1, max_length=16_384)

    @field_validator("refresh_token")
    @classmethod
    def validate_refresh_token(cls, value: str) -> str:
        if "\n" in value or "\r" in value or "----" in value:
            raise ValueError("Refresh Token 格式无效")
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("Refresh Token 不能为空")
        return normalized_value


class LeaseRefreshTokenUpdateResponse(BaseModel):
    """Refresh Token CAS 回写结果，不回显 Token 明文。"""

    lease_id: str
    mailbox_id: str
    updated: bool
    token_version: int
