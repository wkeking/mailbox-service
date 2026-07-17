"""API schemas that avoid returning egress proxy authentication material."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mailbox_service.models import EgressProxyProtocol, EgressProxyStatus, LeaseMode, MailboxStatus


class EgressProxyCreate(BaseModel):
    """创建出口代理的请求参数。"""

    name: str = Field(min_length=1, max_length=100, description="代理显示名称，全局唯一。")
    protocol: EgressProxyProtocol = Field(description="代理协议：socks5 或 http_connect。")
    host: str = Field(min_length=1, max_length=255, description="代理主机名或 IP。")
    port: int = Field(ge=1, le=65535, description="代理端口。")
    username: str | None = Field(default=None, max_length=255, description="代理认证用户名；可选。")
    password: str | None = Field(default=None, max_length=4096, description="代理认证密码；可选，不会在列表中回显。")
    enabled: bool = Field(default=True, description="创建后是否立即启用。")
    priority: int = Field(default=100, ge=0, le=1_000_000, description="选择优先级，数值越小越优先。")
    # When set and username/password are both omitted, encrypted credentials are cloned server-side.
    copy_credentials_from_proxy_id: str | None = Field(
        default=None,
        max_length=36,
        description="从已有代理复制已加密凭证；未填写 username/password 时生效，明文不会返回前端。",
    )

    @field_validator("name", "host")
    @classmethod
    def normalize_nonempty_text(cls, value: str) -> str:
        """Normalize routing identifiers while rejecting whitespace-only values."""
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("字段不能为空")
        return normalized_value


class EgressProxyUpdate(BaseModel):
    """更新出口代理的请求参数；未提供的凭证字段保持不变。"""

    name: str | None = Field(default=None, min_length=1, max_length=100, description="新的代理显示名称。")
    protocol: EgressProxyProtocol | None = Field(default=None, description="新的代理协议。")
    host: str | None = Field(default=None, min_length=1, max_length=255, description="新的代理主机。")
    port: int | None = Field(default=None, ge=1, le=65535, description="新的代理端口。")
    username: str | None = Field(default=None, max_length=255, description="新的用户名；传空字符串可清空。")
    password: str | None = Field(default=None, max_length=4096, description="新的密码；传空字符串可清空。")
    enabled: bool | None = Field(default=None, description="是否启用该代理。")
    priority: int | None = Field(default=None, ge=0, le=1_000_000, description="新的选择优先级。")

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
    """不包含认证凭证明文的出口代理响应。"""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="代理唯一 ID。")
    name: str = Field(description="代理显示名称。")
    protocol: EgressProxyProtocol = Field(description="代理协议。")
    host: str = Field(description="代理主机名或 IP（管理接口完整返回，便于复制编辑）。")
    host_preview: str = Field(description="脱敏后的主机预览，用于列表展示。")
    port: int = Field(description="代理端口。")
    enabled: bool = Field(description="是否启用。")
    priority: int = Field(description="选择优先级，数值越小越优先。")
    status: EgressProxyStatus = Field(description="健康状态：healthy / cooldown / unknown。")
    has_credentials: bool = Field(description="是否已配置用户名或密码。")
    consecutive_failure_count: int = Field(description="连续失败次数。")
    cooldown_until: datetime | None = Field(default=None, description="冷却结束时间；非冷却中为空。")
    last_success_at: datetime | None = Field(default=None, description="最近一次连通成功时间。")
    last_failure_at: datetime | None = Field(default=None, description="最近一次连通失败时间。")
    last_error_summary: str | None = Field(default=None, description="最近一次错误摘要，不含敏感信息。")
    bound_mailbox_count: int = Field(default=0, description="当前粘性绑定到该代理的邮箱数量。")
    created_at: datetime = Field(description="创建时间。")
    updated_at: datetime = Field(description="最后更新时间。")


class ProxyPolicyResponse(BaseModel):
    """全局出口代理策略响应。"""

    model_config = ConfigDict(from_attributes=True)

    enabled: bool = Field(description="是否启用代理池。")
    required: bool = Field(description="是否强制使用代理；为 true 时不可回退直连。")
    allowed_protocols: list[str] = Field(description="允许参与选择的协议列表。")
    connect_timeout_seconds: int = Field(description="代理连接超时（秒）。")
    read_timeout_seconds: int = Field(description="代理读超时（秒）。")
    health_check_interval_seconds: int = Field(description="健康探测间隔（秒）。")
    failure_threshold: int = Field(description="进入冷却前允许的连续失败次数。")
    cooldown_seconds: int = Field(description="冷却持续时间（秒）。")
    switch_minimum_interval_seconds: int = Field(description="同一邮箱最短换绑间隔（秒）。")
    allow_direct_development: bool = Field(description="开发场景下是否允许无代理直连。")
    updated_at: datetime = Field(description="策略最后更新时间。")


class ProxyPolicyUpdate(BaseModel):
    """全局出口代理策略更新请求。"""

    enabled: bool | None = Field(default=None, description="是否启用代理池。")
    required: bool | None = Field(default=None, description="是否强制使用代理。")
    allowed_protocols: list[EgressProxyProtocol] | None = Field(default=None, description="允许的协议列表。")
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120, description="连接超时（秒）。")
    read_timeout_seconds: int | None = Field(default=None, ge=1, le=300, description="读超时（秒）。")
    health_check_interval_seconds: int | None = Field(default=None, ge=30, le=86_400, description="健康探测间隔（秒）。")
    failure_threshold: int | None = Field(default=None, ge=1, le=100, description="连续失败阈值。")
    cooldown_seconds: int | None = Field(default=None, ge=30, le=86_400, description="冷却时长（秒）。")
    switch_minimum_interval_seconds: int | None = Field(default=None, ge=0, le=86_400, description="最短换绑间隔（秒）。")
    allow_direct_development: bool | None = Field(default=None, description="是否允许开发直连。")


class ProxyConnectivityTestResponse(BaseModel):
    """出口代理连通性测试结果。"""

    successful: bool = Field(description="握手是否成功。")
    error_code: str | None = Field(default=None, description="失败时的稳定错误码。")
    error_summary: str | None = Field(default=None, description="失败原因摘要，不含上游响应正文。")


class ProxyBoundMailboxResponse(BaseModel):
    """出口代理影响范围内的邮箱信息。"""

    id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    status: str = Field(description="邮箱状态。")
    proxy_bound_at: datetime | None = Field(default=None, description="绑定到该代理的时间。")
    proxy_last_switch_at: datetime | None = Field(default=None, description="最近一次换绑时间。")


class ProxyBindingUpdate(BaseModel):
    """邮箱出口代理绑定更新请求；空值表示请求直连。"""

    egress_proxy_id: str | None = Field(default=None, description="目标代理 ID；null 表示解除绑定/直连。")


class MailboxImportRequest(BaseModel):
    """四段文本格式的邮箱批量导入请求。"""

    content: str = Field(min_length=1, description="多行导入文本，每行：邮箱----密码----ClientID----RefreshToken。")
    on_conflict: str = Field(
        default="replace_token",
        pattern="^(skip|replace_token|error)$",
        description="邮箱已存在时的策略：skip 跳过，replace_token 替换凭证，error 记为失败。",
    )


class MailboxImportLineError(BaseModel):
    """邮箱导入内容中的单行错误。"""

    line_number: int = Field(description="出错行号，从 1 开始。")
    message: str = Field(description="错误说明，不包含密钥明文。")


class MailboxImportResponse(BaseModel):
    """邮箱批量导入结果汇总。"""

    created: int = Field(description="新建邮箱数量。")
    updated: int = Field(description="更新邮箱数量。")
    skipped: int = Field(description="跳过数量。")
    failed: int = Field(description="失败数量。")
    errors: list[MailboxImportLineError] = Field(description="失败行明细。")


class MailboxBatchIdsRequest(BaseModel):
    """按邮箱 ID 批量操作的请求体。"""

    mailbox_ids: list[str] = Field(
        min_length=1,
        max_length=500,
        description="待操作邮箱 ID 列表；会自动去重，最多 500 个。",
    )

    @field_validator("mailbox_ids")
    @classmethod
    def normalize_mailbox_ids(cls, mailbox_ids: list[str]) -> list[str]:
        """Strip, drop blanks, and de-duplicate while preserving first-seen order."""
        ordered_unique_mailbox_ids: list[str] = []
        seen_mailbox_ids: set[str] = set()
        for raw_mailbox_id in mailbox_ids:
            normalized_mailbox_id = raw_mailbox_id.strip()
            if not normalized_mailbox_id or normalized_mailbox_id in seen_mailbox_ids:
                continue
            seen_mailbox_ids.add(normalized_mailbox_id)
            ordered_unique_mailbox_ids.append(normalized_mailbox_id)
        if not ordered_unique_mailbox_ids:
            raise ValueError("至少需要提供一个有效的邮箱 ID")
        if len(ordered_unique_mailbox_ids) > 500:
            raise ValueError("单次最多处理 500 个邮箱 ID")
        return ordered_unique_mailbox_ids


class MailboxBatchDeleteResponse(BaseModel):
    """选中邮箱批量删除结果。"""

    deleted: int = Field(description="实际删除的邮箱数量。")
    deleted_mailbox_ids: list[str] = Field(description="已删除的邮箱 ID 列表。")
    missing_mailbox_ids: list[str] = Field(description="请求中不存在的邮箱 ID 列表。")


class MailboxDeleteInvalidResponse(BaseModel):
    """删除全部失效邮箱的结果。"""

    deleted: int = Field(description="实际删除的失效邮箱数量。")
    deleted_mailbox_ids: list[str] = Field(description="已删除的邮箱 ID 列表。")
    deleted_primary_emails: list[str] = Field(description="已删除的主邮箱地址列表。")


class MailboxAccessTokenResponse(BaseModel):
    """受保护接口返回的可用 Access Token。"""

    mailbox_id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    access_token: str = Field(description="可用的 Microsoft Access Token 明文。")
    expires_at: datetime = Field(description="Access Token 过期时间（UTC）。")
    token_version: int = Field(description="当前 Refresh Token 版本号。")
    refreshed: bool = Field(description="本次是否触发了 Microsoft 刷新。")
    refresh_token_rotated: bool = Field(description="本次是否写入了轮换后的 Refresh Token。")


class MailboxAccessTokenRefreshRequest(BaseModel):
    """批量刷新请求；邮箱 ID 为空时刷新全部可用邮箱。"""

    mailbox_ids: list[str] | None = Field(default=None, description="待刷新邮箱 ID 列表；null/空表示全部 active 邮箱。")


class MailboxAccessTokenRefreshItemResponse(BaseModel):
    """单个邮箱的 Token 刷新结果。"""

    mailbox_id: str = Field(description="邮箱 ID。")
    primary_email: str | None = Field(default=None, description="主邮箱地址；邮箱不存在时可能为空。")
    successful: bool = Field(description="该行是否刷新成功。")
    refreshed: bool = Field(description="是否实际调用了 Microsoft 刷新。")
    refresh_token_rotated: bool = Field(description="是否轮换了 Refresh Token。")
    access_token_expires_at: datetime | None = Field(default=None, description="成功时的 AT 过期时间。")
    error_summary: str | None = Field(default=None, description="失败原因摘要。")


class MailboxAccessTokenRefreshResponse(BaseModel):
    """批量刷新汇总响应，不返回 Token 明文。"""

    successful: int = Field(description="成功数量。")
    failed: int = Field(description="失败数量。")
    results: list[MailboxAccessTokenRefreshItemResponse] = Field(description="逐邮箱结果列表。")


class MailboxUnprobedRefreshRequest(BaseModel):
    """对未探测 / 能力未知邮箱分批刷新 RT/AT 的请求。"""

    batch_size: int = Field(
        default=1000,
        ge=1,
        le=5000,
        description="本批最多处理的邮箱数量，默认 1000，上限 5000。",
    )


class MailboxUnprobedRefreshResponse(BaseModel):
    """未探测 / 未知能力邮箱分批刷新结果。"""

    candidate_total: int = Field(description="操作前仍待识别的邮箱总数（未探测或 capability=unknown）。")
    processed: int = Field(description="本批实际处理数量。")
    successful: int = Field(description="本批刷新成功数量。")
    failed: int = Field(description="本批刷新失败数量。")
    remaining_candidates: int = Field(description="本批结束后仍待识别的邮箱数量。")
    batch_size: int = Field(description="本批请求使用的 batch_size。")
    worker_count: int = Field(description="本批并发 worker 数，按当前可用出口代理数计算，至少 1。")
    results: list[MailboxAccessTokenRefreshItemResponse] = Field(description="本批逐邮箱结果列表。")


class DashboardSummaryResponse(BaseModel):
    """管理台概览指标响应。"""

    total_mailbox_count: int = Field(description="邮箱总数。")
    active_mailbox_count: int = Field(description="状态为 active 的邮箱数。")
    usable_mailbox_count: int = Field(
        description="运营可用邮箱数：status=active 且 capability 为 imap 或 graph。",
    )
    invalid_mailbox_count: int = Field(description="凭证失效（status=invalid）邮箱数。")
    disabled_mailbox_count: int = Field(description="停用（status=disabled）邮箱数。")
    cooldown_mailbox_count: int = Field(description="冷却中（status=cooldown）邮箱数。")
    imap_capable_mailbox_count: int = Field(description="运行时能力为 IMAP 的邮箱数。")
    graph_capable_mailbox_count: int = Field(description="运行时能力为 Graph 的邮箱数。")
    unusable_mailbox_count: int = Field(description="运行时能力为不可用（unusable）的邮箱数。")
    unprobed_capability_mailbox_count: int = Field(description="尚未完成能力探测的邮箱数。")
    active_lease_count: int = Field(description="进行中租约数。")
    expired_lease_count: int = Field(description="已过期未释放租约数。")
    total_proxy_count: int = Field(description="出口代理总数。")
    healthy_proxy_count: int = Field(description="健康代理数。")
    cooldown_proxy_count: int = Field(description="冷却中代理数。")
    bound_mailbox_count: int = Field(description="已绑定出口代理的邮箱数。")
    recent_audit_count: int = Field(description="近期审计事件数量。")


class MailboxListItemResponse(BaseModel):
    """邮箱管理列表项，不包含敏感凭证明文。"""

    id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    status: MailboxStatus = Field(description="邮箱健康状态。")
    client_id: str | None = Field(default=None, description="OAuth Client ID。")
    token_version: int = Field(description="Refresh Token 版本号。")
    egress_proxy_id: str | None = Field(default=None, description="粘性绑定的出口代理 ID。")
    egress_proxy_name: str | None = Field(default=None, description="绑定代理名称。")
    proxy_bound_at: datetime | None = Field(default=None, description="绑定时间。")
    proxy_last_switch_at: datetime | None = Field(default=None, description="最近换绑时间。")
    has_access_token: bool = Field(description="是否已缓存 Access Token。")
    access_token_expires_at: datetime | None = Field(default=None, description="缓存 AT 过期时间。")
    access_token_refreshed_at: datetime | None = Field(default=None, description="最近一次刷新 AT 的时间。")
    scope: str | None = Field(default=None, description="识别到的 OAuth scope 字符串。")
    capability: str | None = Field(default=None, description="运行时探测能力：imap / graph / unusable / unknown。")
    capability_probed_at: datetime | None = Field(default=None, description="能力最近探测时间。")
    capability_probe_error: str | None = Field(default=None, description="能力探测失败摘要。")
    active_lease_count: int = Field(description="当前活跃租约数。")
    created_at: datetime = Field(description="创建时间。")
    updated_at: datetime = Field(description="最后更新时间。")


class MailboxListResponse(BaseModel):
    """邮箱分页查询响应。"""

    total: int = Field(description="总记录数。")
    page: int = Field(description="当前页码，从 1 开始。")
    page_size: int = Field(description="每页条数。")
    total_pages: int = Field(description="总页数。")
    items: list[MailboxListItemResponse] = Field(description="当前页邮箱列表。")


class LeaseListItemResponse(BaseModel):
    """租约列表项，不包含邮箱敏感凭证。"""

    id: str = Field(description="租约 ID。")
    mailbox_id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    allocated_email: str | None = Field(
        default=None,
        description="本租约分配的业务地址（主邮箱或 plus alias）；mail_read 常用。",
    )
    client_key_id: str | None = Field(default=None, description="领取方 Client Key ID。")
    client_tag: str | None = Field(default=None, description="调用方自定义标签。")
    purpose: str | None = Field(default=None, description="领取用途说明。")
    mode: LeaseMode = Field(description="租约模式：access_token、refresh_token 或 mail_read。")
    status: str = Field(description="租约状态：active / released / expired。")
    expires_at: datetime = Field(description="租约到期时间。")
    released_at: datetime | None = Field(default=None, description="释放时间；未释放为空。")
    created_at: datetime = Field(description="创建时间。")


class LeaseListResponse(BaseModel):
    """租约分页查询响应。"""

    total: int = Field(description="总记录数。")
    page: int = Field(description="当前页码，从 1 开始。")
    page_size: int = Field(description="每页条数。")
    total_pages: int = Field(description="总页数。")
    items: list[LeaseListItemResponse] = Field(description="当前页租约列表。")


class ClientKeyCreateRequest(BaseModel):
    """管理员创建外部 Client Key 的请求。"""

    name: str = Field(min_length=1, max_length=100, description="Client Key 显示名称，全局唯一。")
    scopes: list[str] = Field(
        min_length=1,
        description=(
            "权限列表，可选："
            "leases:acquire、leases:release、tokens:access:read、"
            "tokens:refresh:read、tokens:refresh:write、"
            "mailboxes:acquire、mail:verification-code:read。"
        ),
    )
    expires_at: datetime | None = Field(default=None, description="过期时间（UTC）；为空表示不过期。")

    @field_validator("name")
    @classmethod
    def normalize_client_key_name(cls, value: str) -> str:
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("Client Key 名称不能为空")
        return normalized_value


class ClientKeyCreatedResponse(BaseModel):
    """包含仅显示一次的 API Key 明文的创建响应。"""

    id: str = Field(description="Client Key ID。")
    name: str = Field(description="显示名称。")
    api_key: str = Field(description="明文 API Key，仅本次响应返回，请立即保存。")
    scopes: list[str] = Field(description="已授予的权限列表。")
    enabled: bool = Field(description="是否启用。")
    expires_at: datetime | None = Field(default=None, description="过期时间；为空表示不过期。")
    created_at: datetime = Field(description="创建时间。")


class ClientKeyListItemResponse(BaseModel):
    """不包含 API Key 明文或摘要的管理列表项。"""

    id: str = Field(description="Client Key ID。")
    name: str = Field(description="显示名称。")
    scopes: list[str] = Field(description="已授予的权限列表。")
    enabled: bool = Field(description="是否启用。")
    expires_at: datetime | None = Field(default=None, description="过期时间；为空表示不过期。")
    last_used_at: datetime | None = Field(default=None, description="最近一次成功鉴权时间。")
    created_at: datetime = Field(description="创建时间。")
    updated_at: datetime = Field(description="最后更新时间。")


class LeaseAcquireRequest(BaseModel):
    """外部调用方领取邮箱租约的请求。"""

    mode: Literal[LeaseMode.ACCESS_TOKEN, LeaseMode.REFRESH_TOKEN] = Field(
        description="凭证模式：access_token 返回短期 AT；refresh_token 返回 RT 与版本号。"
    )
    lease_ttl_seconds: int = Field(
        default=600,
        ge=60,
        le=86_400,
        description="租约有效期（秒），默认 600，范围 60–86400。",
    )
    preferred_email: str | None = Field(
        default=None,
        max_length=320,
        description="优先领取的邮箱地址；不传则由服务分配可用邮箱。",
    )
    client_tag: str | None = Field(default=None, max_length=100, description="调用方自定义标签，便于排查。")
    purpose: str | None = Field(default=None, max_length=100, description="领取用途说明。")

    @field_validator("preferred_email", "client_tag", "purpose")
    @classmethod
    def normalize_optional_lease_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_value = value.strip()
        return normalized_value or None


class MailboxAcquireRequest(BaseModel):
    """领取一个可用邮箱账号用于后续读信 / 验证码，不返回 Token。"""

    lease_ttl_seconds: int = Field(
        default=600,
        ge=60,
        le=86_400,
        description="mail_read 租约有效期（秒），默认 600，范围 60–86400。",
    )
    preferred_email: str | None = Field(
        default=None,
        max_length=320,
        description="优先领取的主邮箱地址；不传则由服务分配可用邮箱。",
    )
    use_plus_alias: bool = Field(
        default=False,
        description=(
            "为 true 时为本租约生成主邮箱的 plus alias（如 user+xxxxxxxx@domain），"
            "后续取验证码默认按该别名匹配收件人；OAuth/IMAP 仍使用主邮箱。"
        ),
    )
    alias_suffix: str | None = Field(
        default=None,
        max_length=32,
        description=(
            "可选：指定 plus alias 后缀（仅小写字母与数字）。"
            "传入时等价于 use_plus_alias=true；不传且 use_plus_alias=true 时随机生成 8 位。"
        ),
    )
    client_tag: str | None = Field(default=None, max_length=100, description="调用方自定义标签，便于排查。")
    purpose: str | None = Field(default=None, max_length=100, description="领取用途说明。")

    @field_validator("preferred_email", "client_tag", "purpose", "alias_suffix")
    @classmethod
    def normalize_optional_mailbox_acquire_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_value = value.strip()
        return normalized_value or None


class MailboxAcquireResponse(BaseModel):
    """可用邮箱账号领取结果，仅返回邮箱身份与 mail_read 租约。"""

    lease_id: str = Field(description="mail_read 租约 ID，后续取验证码 / 释放时使用。")
    mailbox_id: str = Field(description="被领取邮箱的 ID。")
    primary_email: str = Field(description="主邮箱地址（OAuth / IMAP 登录身份）。")
    allocated_email: str = Field(
        description="本租约分配的业务收件地址：主邮箱或 plus alias，用于注册与验证码匹配。",
    )
    mode: Literal[LeaseMode.MAIL_READ] = Field(
        default=LeaseMode.MAIL_READ,
        description="固定为 mail_read，不返回 access_token / refresh_token。",
    )
    expires_at: datetime = Field(description="租约到期时间。")
    created_at: datetime = Field(description="租约创建时间。")


class LeaseVerificationCodeRequest(BaseModel):
    """在 mail_read 租约下从收件箱提取验证码。"""

    timeout_seconds: int = Field(
        default=60,
        ge=0,
        le=300,
        description="最长等待时间（秒）。默认 60；为 0 时只扫描一次。",
    )
    since_seconds: int = Field(
        default=180,
        ge=30,
        le=3_600,
        description=(
            "只查看最近 N 秒内的邮件，默认 180（3 分钟）。"
            "服务端会额外放宽约 15 分钟时钟偏差缓冲；"
            "IMAP 优先使用服务器 INTERNALDATE，而不是不可靠的 Date 头。"
        ),
    )
    poll_interval_seconds: int = Field(
        default=3,
        ge=1,
        le=30,
        description="轮询间隔（秒），默认 3。",
    )
    from_address: str | None = Field(
        default=None,
        max_length=320,
        description="可选：发件人地址子串过滤（不区分大小写）。",
    )
    subject_contains: str | None = Field(
        default=None,
        max_length=200,
        description="可选：主题包含的关键词（不区分大小写）。",
    )
    body_contains: str | None = Field(
        default=None,
        max_length=200,
        description="可选：正文包含的关键词（不区分大小写）。",
    )
    recipient: str | None = Field(
        default=None,
        max_length=320,
        description=(
            "期望收件人地址（支持 plus alias）。"
            "默认使用租约 allocated_email（领取时分配的主邮箱或别名），"
            "再回退到 primary_email；与 To/Cc/Delivered-To/X-Original-To/X-Envelope-To 匹配。"
        ),
    )
    require_recipient_match: bool = Field(
        default=True,
        description="是否要求邮件收件人匹配 recipient（默认 true）。",
    )
    code_regex: str | None = Field(
        default=None,
        max_length=200,
        description=(
            "可选：自定义验证码正则（建议捕获组）。"
            "默认优先匹配 xAI 格式 ABC-123，再兜底数字；传入时在 xAI 之后仅使用该正则。"
        ),
    )

    @field_validator("from_address", "subject_contains", "body_contains", "recipient", "code_regex")
    @classmethod
    def normalize_optional_filter_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_value = value.strip()
        return normalized_value or None


class LeaseVerificationCodeResponse(BaseModel):
    """验证码提取结果。"""

    lease_id: str = Field(description="mail_read 租约 ID。")
    mailbox_id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    allocated_email: str | None = Field(
        default=None,
        description="本租约分配的业务收件地址（主邮箱或 plus alias）。",
    )
    found: bool = Field(description="是否在时间窗内匹配到验证码。")
    code: str | None = Field(default=None, description="提取到的验证码；未找到时为 null。")
    matched_from: str | None = Field(default=None, description="匹配邮件的发件人。")
    matched_subject: str | None = Field(default=None, description="匹配邮件的主题。")
    message_received_at: datetime | None = Field(default=None, description="匹配邮件的接收时间（UTC）。")
    channel: Literal["imap", "graph"] | None = Field(
        default=None,
        description="实际读信通道：imap 或 graph。",
    )
    attempts: int = Field(description="本次请求内的扫描次数。")


class AccessTokenLeaseCredentialResponse(BaseModel):
    """Access Token mode 租约返回的短期凭证。"""

    type: Literal["access_token"] = Field(default="access_token", description="凭证类型固定为 access_token。")
    access_token: str = Field(description="Microsoft Access Token 明文。")
    expires_at: datetime = Field(description="Access Token 过期时间（UTC）。")
    refreshed: bool = Field(description="领取时是否触发了 Token 刷新。")
    token_version: int = Field(description="当前 Refresh Token 版本号。")


class RefreshTokenLeaseCredentialResponse(BaseModel):
    """Refresh Token mode 租约返回的长期凭证。"""

    type: Literal["refresh_token"] = Field(default="refresh_token", description="凭证类型固定为 refresh_token。")
    client_id: str = Field(description="OAuth Client ID，刷新 Token 时使用。")
    refresh_token: str = Field(description="当前 Refresh Token 明文。")
    token_version: int = Field(description="Refresh Token 版本号，回写时用于 CAS。")


LeaseCredentialResponse = Annotated[
    AccessTokenLeaseCredentialResponse | RefreshTokenLeaseCredentialResponse,
    Field(discriminator="type", description="按 mode 返回的凭证联合体。"),
]


class LeaseAcquireResponse(BaseModel):
    """外部邮箱租约及其 mode 对应凭证。"""

    lease_id: str = Field(description="租约 ID，后续释放/取 Token 时使用。")
    mailbox_id: str = Field(description="被领取邮箱的 ID。")
    primary_email: str = Field(description="被领取邮箱地址。")
    mode: LeaseMode = Field(description="本次租约模式。")
    expires_at: datetime = Field(description="租约到期时间。")
    created_at: datetime = Field(description="租约创建时间。")
    credential: LeaseCredentialResponse = Field(description="与 mode 对应的凭证内容。")


class LeaseReleaseResponse(BaseModel):
    """幂等租约释放响应。"""

    lease_id: str = Field(description="已释放的租约 ID。")
    released_at: datetime = Field(description="释放时间；重复释放时返回原释放时间。")


class LeaseAccessTokenResponse(BaseModel):
    """有效租约内返回的可用 Access Token。"""

    lease_id: str = Field(description="租约 ID。")
    mailbox_id: str = Field(description="邮箱 ID。")
    primary_email: str = Field(description="主邮箱地址。")
    access_token: str = Field(description="可用的 Access Token 明文。")
    expires_at: datetime = Field(description="Access Token 过期时间（UTC）。")
    token_version: int = Field(description="当前 Refresh Token 版本号。")
    refreshed: bool = Field(description="本次是否触发了刷新。")
    refresh_token_rotated: bool = Field(description="本次是否轮换了 Refresh Token。")


class LeaseRefreshTokenUpdateRequest(BaseModel):
    """使用 token_version 进行 CAS 的 Refresh Token 回写请求。"""

    expected_token_version: int = Field(
        ge=1,
        description="调用方持有的 token_version；与库中不一致时拒绝覆盖。",
    )
    refresh_token: str = Field(
        min_length=1,
        max_length=16_384,
        description="要回写的新 Refresh Token 明文。",
    )

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

    lease_id: str = Field(description="租约 ID。")
    mailbox_id: str = Field(description="邮箱 ID。")
    updated: bool = Field(description="是否成功写入新的 Refresh Token。")
    token_version: int = Field(description="写入后的 token_version；未更新时为当前版本。")
