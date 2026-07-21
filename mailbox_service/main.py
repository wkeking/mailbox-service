"""FastAPI application exposing the global egress proxy administration API."""

from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.routing import APIRoute
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from mailbox_service.config import Settings, get_settings
from mailbox_service.client_key_service import (
    ClientKeyAuthenticationError,
    ClientKeyService,
    ClientKeyScopeError,
    ClientPrincipal,
)
from mailbox_service.database import SessionFactory, database_engine, get_session
from mailbox_service.migration_runner import run_pending_migrations
from mailbox_service.lease_service import (
    ProviderNotConfiguredError,
    ProviderUnsupportedError,
    LeaseEmailNotFoundError,
    LeaseEmailSiteConflictError,
    LeaseInactiveError,
    LeaseMailboxBusyError,
    LeaseModeError,
    LeaseNotFoundError,
    LeaseService,
    LeaseUnavailableError,
    LeaseUsageSiteError,
    TokenVersionConflictError,
    UsageSiteConflictError,
    UsageSiteInUseError,
    UsageSiteNotFoundError,
)
from mailbox_service.models import (
    AuditLog,
    ClientKey,
    EgressProxy,
    EgressProxyStatus,
    Lease,
    LeaseMode,
    Mailbox,
    MailboxCapability,
    MailboxStatus,
    ProxyPolicy,
    is_expired,
    utc_now,
)
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    NoHealthyEgressProxyError,
)
from mailbox_service.proxy_scheduler import start_proxy_health_scheduler
from mailbox_service.token_keepalive_scheduler import start_refresh_token_keepalive_scheduler
from mailbox_service.schemas import (
    AccessTokenLeaseCredentialResponse,
    ClientKeyCreateRequest,
    ClientKeyCreatedResponse,
    ClientKeyListItemResponse,
    ClientKeyUpdateRequest,
    DashboardSummaryResponse,
    EgressProxyCreate,
    EgressProxyResponse,
    EgressProxyUpdate,
    LeaseListResponse,
    LeaseListItemResponse,
    LeaseAccessTokenResponse,
    LeaseAcquireRequest,
    LeaseAcquireResponse,
    LeaseRefreshTokenUpdateRequest,
    LeaseRefreshTokenUpdateResponse,
    LeaseReleaseResponse,
    LeaseVerificationCodeRequest,
    LeaseVerificationCodeResponse,
    EmailSiteUsageItemResponse,
    EmailSiteUsageListResponse,
    EmailSiteUsageRevokeResponse,
    MailboxAcquireRequest,
    MailboxAcquireResponse,
    SmsbowerReplenishResponse,
    ProviderCatalogResponse,
    ProviderCatalogItemResponse,
    ProviderInstanceSettingsResponse,
    ProviderInstanceSettingsUpdate,
    SmsbowerSettingsResponse,
    SmsbowerSettingsUpdate,
    MailboxReacquireRequest,
    UsageSiteCreateRequest,
    UsageSiteItemResponse,
    UsageSiteListResponse,
    UsageSiteUpdateRequest,
    MailboxAccessTokenRefreshRequest,
    MailboxAccessTokenRefreshResponse,
    MailboxAccessTokenResponse,
    MailboxBatchDeleteResponse,
    MailboxBatchIdsRequest,
    MailboxDeleteInvalidResponse,
    MailboxImportLineError,
    MailboxImportRequest,
    MailboxImportResponse,
    MailboxListItemResponse,
    MailboxListResponse,
    MailboxUnprobedRefreshRequest,
    MailboxUnprobedRefreshResponse,
    ProxyBindingUpdate,
    ProxyBoundMailboxResponse,
    ProxyConnectivityTestResponse,
    ProxyPolicyResponse,
    ProxyPolicyUpdate,
    RefreshTokenLeaseCredentialResponse,
)
from mailbox_service.security import (
    CredentialCipher,
    build_proxy_credential_fingerprint,
    redact_proxy_host,
    summarize_exception,
)
from mailbox_service.capability_probe_service import (
    MailboxCapabilityProbeService,
    MicrosoftGraphMailProbeClient,
)
from mailbox_service.token_service import MailboxAccessTokenService, stamp_refresh_token_lifetime
from mailbox_service.proxy_service import (
    MicrosoftIMAPClient,
    MicrosoftOAuthClient,
    MicrosoftInvalidGrantError,
    MicrosoftOAuthError,
)
from mailbox_service.mailbox_admin_service import (
    ActiveLeaseClaimConflictError,
    MailboxAdminService,
)
from mailbox_service.verification_authorization import (
    VerificationAuthorizationError,
    revalidate_verification_authorization,
)
from mailbox_service.verification_poll_capacity import (
    VerificationPollCapacityExceededError,
    acquire_verification_poll_slot,
)
from mailbox_service.verification_code_service import (
    MicrosoftGraphMailReader,
    VerificationCodeLookupOptions,
    VerificationCodeReadError,
    VerificationCodeService,
)

SessionDependency = Annotated[Session, Depends(get_session)]
SettingsDependency = Annotated[Settings, Depends(get_settings)]
admin_token_header = APIKeyHeader(
    name="X-Admin-Token",
    scheme_name="AdminToken",
    description="管理员 API Token，请求时写入 X-Admin-Token Header。",
    auto_error=False,
)
client_api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ClientApiKey",
    description="外部调用方 API Key，请求时写入 X-API-Key Header。",
    auto_error=False,
)

OPENAPI_TAGS = [
    {"name": "服务状态", "description": "服务健康检查与基础可用性。"},
    {"name": "外部租约", "description": "外部调用方领取、使用和释放邮箱租约。"},
    {"name": "外部邮箱", "description": "外部调用方领取可用邮箱账号并读取收件箱验证码。"},
    {"name": "概览", "description": "管理台概览与运行指标。"},
    {"name": "邮箱管理", "description": "邮箱凭证导入、Token 缓存、刷新和代理绑定。"},
    {"name": "租约管理", "description": "邮箱租约记录与生命周期查询。"},
    {"name": "出口代理", "description": "出口代理的增删改查、连通性测试和健康恢复。"},
    {"name": "代理策略", "description": "OAuth 与 IMAP 出站流量使用的全局代理策略。"},
    {"name": "Client Key 管理", "description": "外部调用方 Client API Key 的创建、修改、查询和停用。"},
]

PUBLIC_OPENAPI_TAG_NAMES = {"服务状态", "外部租约", "外部邮箱"}

OPENAPI_OPERATION_DOCUMENTATION: dict[tuple[str, str], tuple[str, str, str]] = {
    ("GET", "/health"): ("查询服务状态", "返回无副作用的服务健康状态。", "服务状态"),
    ("POST", "/api/v1/leases/acquire"): (
        "领取邮箱租约",
        "领取一个当前可用的邮箱。access_token mode 返回可用 AT；refresh_token mode 返回当前 RT 和版本号。",
        "外部租约",
    ),
    ("POST", "/api/v1/leases/{lease_id}/release"): (
        "释放邮箱租约",
        "幂等释放当前 Client Key 所属的租约。",
        "外部租约",
    ),
    ("POST", "/api/v1/leases/{lease_id}/access-token"): (
        "获取租约 Access Token",
        "未过期时返回缓存 AT，过期或不存在时刷新并持久化最新 AT 和过期时间。",
        "外部租约",
    ),
    ("POST", "/api/v1/leases/{lease_id}/refresh-token"): (
        "回写租约 Refresh Token",
        "使用 expected_token_version 执行 CAS 更新，防止较旧 RT 覆盖数据库中的较新值。",
        "外部租约",
    ),
    ("POST", "/api/v1/mailboxes/acquire"): (
        "领取可用邮箱账号",
        "领取 mail_read 租约并返回业务邮箱地址（不返回 Token）。"
        "provider 可省略 / all / 单类型 / 多类型：省略与 all 在已授权类型中随机；"
        "exclude_providers 排除优先级最高；非 microsoft 须对应 providers:{type}:acquire。"
        "microsoft 主邮箱路径须声明 usage_site；use_plus_alias=true 时只分配 plus 别名。",
        "外部邮箱",
    ),
    ("GET", "/api/v1/usage-sites"): (
        "查询可用注册站点",
        "返回当前启用的注册站点白名单（code 与展示名），供 mail_read 领取时填写 usage_site。",
        "外部邮箱",
    ),
    ("POST", "/api/v1/mailboxes/reacquire"): (
        "按历史地址重新领取邮箱",
        "传入业务侧保存的主邮箱或 plus 别名（首次领取的 allocated_email）；"
        "服务端自动判定地址类型，仅允许本 Client Key 历史 mail_read 租约用过的地址，"
        "创建或续期 mail_read 租约，不返回 Token，不新增站点占用记录。",
        "外部邮箱",
    ),
    ("POST", "/api/v1/leases/{lease_id}/verification-code"): (
        "获取收件箱验证码",
        "在 mail_read 租约下读取最近邮件并提取验证码；优先 xAI（ABC-123）格式再兜底数字，"
        "默认按收件人匹配，IMAP 使用 UID SEARCH ALL 取最近 N 封。",
        "外部邮箱",
    ),
    ("GET", "/api/v1/admin/dashboard"): (
        "查询管理概览",
        "返回邮箱、租约、出口代理和审计事件的汇总指标。",
        "概览",
    ),
    ("GET", "/api/v1/admin/mailboxes"): (
        "分页查询邮箱",
        "分页返回邮箱运行状态、Token 缓存时间和当前活跃租约数量，不返回敏感凭证明文。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/import"): (
        "批量导入邮箱",
        "按照四段文本格式批量导入邮箱凭证，密码和 Refresh Token 加密保存。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/export"): (
        "导出选中邮箱",
        "按导入相同的四段文本格式导出选中邮箱凭证明文，响应为 text/plain 的 txt 内容。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/delete"): (
        "删除选中邮箱",
        "按邮箱 ID 批量删除选中邮箱；关联租约会一并删除，操作不可恢复。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/{mailbox_id}/access-token"): (
        "获取可用 Access Token",
        "缓存未过期时返回现有 Access Token；缓存过期或不存在时刷新并更新数据库。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/access-tokens/refresh"): (
        "批量刷新 RT/AT",
        "强制刷新选中邮箱或全部可用邮箱的 Token；Microsoft 返回新 Refresh Token 时同步保存。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/access-tokens/refresh-unprobed"): (
        "分批识别未探测邮箱",
        "对 capability 为空或 unknown 的 active 邮箱分批强制刷新 RT/AT，识别可用与失效凭证。",
        "邮箱管理",
    ),
    ("POST", "/api/v1/admin/mailboxes/delete-invalid"): (
        "删除全部失效邮箱",
        "删除 status=invalid 的全部邮箱及其关联租约，操作不可恢复。",
        "邮箱管理",
    ),
    ("GET", "/api/v1/admin/usage-sites"): (
        "查询注册站点白名单",
        "返回全部注册站点（含已禁用），供管理端查看与配置。",
        "租约管理",
    ),
    ("POST", "/api/v1/admin/usage-sites"): (
        "创建注册站点",
        "新增 usage_site 白名单 code；code 创建后不可修改，可禁用以阻止新声明。",
        "租约管理",
    ),
    ("PATCH", "/api/v1/admin/usage-sites/{code}"): (
        "更新注册站点",
        "更新站点展示名或启用状态；禁用后历史占用仍参与排除，但禁止新声明。",
        "租约管理",
    ),
    ("DELETE", "/api/v1/admin/usage-sites/{code}"): (
        "删除注册站点",
        "仅当该站点无未撤销占用时可删除；已撤销占用会一并清理。",
        "租约管理",
    ),
    ("GET", "/api/v1/admin/email-site-usages"): (
        "分页查询邮箱站点占用",
        "按业务地址、站点、是否已撤销筛选占用记录，用于排查为何无法再分配到某站。",
        "租约管理",
    ),
    ("POST", "/api/v1/admin/email-site-usages/{usage_id}/revoke"): (
        "撤销邮箱站点占用",
        "软删除占用记录（写 revoked_at），之后同一业务地址可再次声明该站点；幂等。",
        "租约管理",
    ),
    ("GET", "/api/v1/admin/leases"): (
        "分页查询租约",
        "分页返回邮箱租约及其当前状态、调用方、用途和到期时间。",
        "租约管理",
    ),
    ("POST", "/api/v1/admin/client-keys"): (
        "创建 Client Key",
        "创建外部 Client Key；API Key 明文只在本次响应中返回一次。",
        "Client Key 管理",
    ),
    ("GET", "/api/v1/admin/client-keys"): (
        "查询 Client Key",
        "返回 Client Key 元数据，不返回密钥明文或摘要。",
        "Client Key 管理",
    ),
    ("PATCH", "/api/v1/admin/client-keys/{client_key_id}"): (
        "修改 Client Key",
        "修改已有 Client Key 的显示名称与权限 scopes；不轮换 API Key 明文。",
        "Client Key 管理",
    ),
    ("POST", "/api/v1/admin/client-keys/{client_key_id}/disable"): (
        "停用 Client Key",
        "停用指定 Client Key，后续外部请求立即拒绝该密钥。",
        "Client Key 管理",
    ),
    ("GET", "/api/v1/admin/egress-proxies"): (
        "查询出口代理",
        "返回脱敏后的出口代理列表和邮箱绑定数量。",
        "出口代理",
    ),
    ("POST", "/api/v1/admin/egress-proxies"): (
        "创建出口代理",
        "创建出口代理，并加密保存可选的代理认证凭证。",
        "出口代理",
    ),
    ("GET", "/api/v1/admin/egress-proxies/{proxy_id}"): (
        "查询出口代理详情",
        "返回单个出口代理的脱敏配置和健康状态。",
        "出口代理",
    ),
    ("PATCH", "/api/v1/admin/egress-proxies/{proxy_id}"): (
        "更新出口代理",
        "更新出口代理元数据或认证凭证，响应不会回显凭证明文。",
        "出口代理",
    ),
    ("DELETE", "/api/v1/admin/egress-proxies/{proxy_id}"): (
        "删除出口代理",
        "删除未被邮箱使用的代理；强制删除时先解除邮箱绑定。",
        "出口代理",
    ),
    ("POST", "/api/v1/admin/egress-proxies/{proxy_id}/enable"): (
        "启用出口代理",
        "启用出口代理并保留现有邮箱绑定。",
        "出口代理",
    ),
    ("POST", "/api/v1/admin/egress-proxies/{proxy_id}/disable"): (
        "停用出口代理",
        "停用出口代理；已绑定邮箱会在下次外部请求时重新选择代理。",
        "出口代理",
    ),
    ("POST", "/api/v1/admin/egress-proxies/{proxy_id}/recover"): (
        "恢复出口代理",
        "人工解除出口代理的冷却状态并重置连续失败计数。",
        "出口代理",
    ),
    ("POST", "/api/v1/admin/egress-proxies/{proxy_id}/test"): (
        "测试出口代理",
        "执行受限的代理连通性测试，不返回上游响应正文。",
        "出口代理",
    ),
    ("GET", "/api/v1/admin/egress-proxies/{proxy_id}/mailboxes"): (
        "查询代理绑定邮箱",
        "返回绑定到指定出口代理的邮箱，不包含邮箱凭证明文。",
        "出口代理",
    ),
    ("GET", "/api/v1/admin/egress-proxy-policy"): (
        "查询代理策略",
        "返回 OAuth 与 IMAP 出站流量使用的全局代理策略。",
        "代理策略",
    ),
    ("PATCH", "/api/v1/admin/egress-proxy-policy"): (
        "更新代理策略",
        "更新全局代理策略并记录不含敏感信息的审计数据。",
        "代理策略",
    ),
    ("PUT", "/api/v1/admin/mailboxes/{mailbox_id}/egress-proxy"): (
        "更新邮箱代理绑定",
        "将邮箱绑定到健康出口代理，或明确设置为直连。",
        "邮箱管理",
    ),
    ("GET", "/api/v1/admin/dashboard/proxies"): (
        "查询代理概览",
        "返回出口代理健康状态和绑定情况的汇总指标。",
        "概览",
    ),
}

OPENAPI_SCHEMA_DESCRIPTIONS = {
    "AccessTokenLeaseCredentialResponse": "Access Token mode 租约返回的短期凭证。",
    "ClientKeyCreateRequest": "管理员创建外部 Client Key 的请求。",
    "ClientKeyCreatedResponse": "包含仅显示一次的 API Key 明文的创建响应。",
    "ClientKeyListItemResponse": "不包含密钥明文或摘要的 Client Key 管理列表项。",
    "DashboardSummaryResponse": "管理台概览指标响应。",
    "EgressProxyCreate": "创建出口代理的请求参数。",
    "EgressProxyProtocol": "出口代理支持的协议。",
    "EgressProxyResponse": "不包含认证凭证明文的出口代理响应。",
    "EgressProxyStatus": "出口代理运行状态。",
    "EgressProxyUpdate": "更新出口代理的请求参数；未提供的凭证字段保持不变。",
    "HTTPValidationError": "HTTP 请求参数校验错误响应。",
    "LeaseListItemResponse": "租约列表项，不包含邮箱敏感凭证。",
    "LeaseListResponse": "租约分页查询响应。",
    "LeaseMode": "邮箱租约授予的凭证使用模式。",
    "LeaseAccessTokenResponse": "有效租约内返回的可用 Access Token。",
    "LeaseAcquireRequest": "外部调用方领取邮箱租约的请求。",
    "LeaseAcquireResponse": "外部邮箱租约及其 mode 对应凭证。",
    "LeaseRefreshTokenUpdateRequest": "使用 token_version 进行 CAS 的 Refresh Token 回写请求。",
    "LeaseRefreshTokenUpdateResponse": "Refresh Token CAS 回写结果，不回显 Token 明文。",
    "LeaseReleaseResponse": "幂等租约释放响应。",
    "LeaseVerificationCodeRequest": "mail_read 租约下提取收件箱验证码的请求。",
    "LeaseVerificationCodeResponse": "验证码提取结果。",
    "MailboxAcquireRequest": "领取可用邮箱账号（mail_read 租约）的请求。",
    "MailboxAcquireResponse": "可用邮箱账号领取结果，不返回 Token。",
    "MailboxReacquireRequest": "按历史主邮箱或 plus 别名重新领取 mail_read 租约的请求。",
    "UsageSiteItemResponse": "注册站点白名单条目。",
    "UsageSiteListResponse": "注册站点白名单列表。",
    "UsageSiteCreateRequest": "管理员创建注册站点白名单的请求。",
    "UsageSiteUpdateRequest": "管理员更新注册站点展示名或启用状态的请求。",
    "EmailSiteUsageItemResponse": "邮箱在某站点的占用记录。",
    "EmailSiteUsageListResponse": "邮箱站点占用分页查询响应。",
    "EmailSiteUsageRevokeResponse": "撤销邮箱站点占用的结果。",
    "MailboxAccessTokenRefreshItemResponse": "单个邮箱的 Token 刷新结果。",
    "MailboxAccessTokenRefreshRequest": "批量刷新请求；邮箱 ID 为空时刷新全部可用邮箱。",
    "MailboxAccessTokenRefreshResponse": "批量刷新汇总响应，不返回 Token 明文。",
    "MailboxAccessTokenResponse": "受保护接口返回的可用 Access Token。",
    "MailboxBatchDeleteResponse": "选中邮箱批量删除结果。",
    "MailboxBatchIdsRequest": "按邮箱 ID 批量操作的请求体。",
    "MailboxDeleteInvalidResponse": "删除全部失效邮箱的结果。",
    "MailboxImportLineError": "邮箱导入内容中的单行错误。",
    "MailboxImportRequest": "四段文本格式的邮箱批量导入请求。",
    "MailboxImportResponse": "邮箱批量导入结果汇总。",
    "MailboxListItemResponse": "邮箱管理列表项，不包含敏感凭证明文。",
    "MailboxListResponse": "邮箱分页查询响应。",
    "MailboxStatus": "邮箱健康状态，与当前是否存在租约相互独立。",
    "MailboxUnprobedRefreshRequest": "对未探测 / 能力未知邮箱分批刷新 RT/AT 的请求。",
    "MailboxUnprobedRefreshResponse": "未探测 / 未知能力邮箱分批刷新结果。",
    "ProxyBindingUpdate": "邮箱出口代理绑定更新请求；空值表示请求直连。",
    "ProxyBoundMailboxResponse": "出口代理影响范围中的邮箱信息。",
    "ProxyConnectivityTestResponse": "出口代理连通性测试结果。",
    "ProxyPolicyResponse": "全局出口代理策略响应。",
    "ProxyPolicyUpdate": "全局出口代理策略更新请求。",
    "RefreshTokenLeaseCredentialResponse": "Refresh Token mode 租约返回的长期凭证。",
    "ValidationError": "单个请求字段的校验错误。",
}

@asynccontextmanager
async def application_lifespan(_: FastAPI):
    """Run schema migrations, then process-local background jobs for this instance."""
    settings = get_settings()
    run_pending_migrations(database_engine, settings)
    cipher = get_credential_cipher(settings)
    if cipher is not None:
        from mailbox_service.lease_service import set_on_demand_provision_hook
        from mailbox_service.providers.ondemand_facade import OnDemandProviderService

        on_demand_service = OnDemandProviderService(
            settings,
            credential_cipher=cipher,
            session_factory=SessionFactory,
        )
        set_on_demand_provision_hook(on_demand_service.provision)
    proxy_health_scheduler = start_proxy_health_scheduler(settings)
    refresh_token_keepalive_scheduler = start_refresh_token_keepalive_scheduler(settings)
    try:
        yield
    finally:
        proxy_health_scheduler.shutdown(wait=False)
        if refresh_token_keepalive_scheduler is not None:
            refresh_token_keepalive_scheduler.shutdown(wait=False)


app = FastAPI(
    title="邮箱服务外部 API",
    version="0.1.0",
    description=(
        "面向外部调用方的邮箱租约与 Token 服务。"
        "受保护接口使用 X-API-Key 请求头认证。"
        "需要人工查看原始定义时，请使用 [OpenAPI JSON 查看器](/openapi-viewer)。"
    ),
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=application_lifespan,
)


@app.middleware("http")
async def apply_security_and_cache_headers(request: Request, call_next):
    """Attach security headers and prevent API responses from being cached."""
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )
    # SPA CSP: no remote script, no framing; styles allow Vite-injected inline rules.
    if not request.url.path.startswith("/api/v1/") and "Content-Security-Policy" not in response.headers:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
    settings = get_settings()
    if settings.enable_hsts and settings.app_env == "production":
        # Only emit HSTS when the request is already known to be HTTPS (proxy-terminated).
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        if request.url.scheme == "https" or forwarded_proto == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={settings.hsts_max_age_seconds}; includeSubDomains",
            )
    return response


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    """Return validation details without reflecting sensitive request input values."""
    sanitized_errors = [
        {
            "type": validation_error.get("type", "value_error"),
            "loc": validation_error.get("loc", ()),
            "msg": validation_error.get("msg", "请求参数校验失败"),
        }
        for validation_error in error.errors()
    ]
    response_headers = {}
    if request.url.path.startswith("/api/v1/"):
        response_headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": sanitized_errors},
        headers=response_headers,
    )


def build_documented_openapi_schema(
    *,
    title: str,
    description: str,
    routes: list[APIRoute],
    included_tag_names: set[str],
) -> dict[str, Any]:
    """Generate one Chinese OpenAPI schema from an explicit route subset."""
    openapi_schema = get_openapi(
        title=title,
        version=app.version,
        description=description,
        routes=routes,
    )
    openapi_schema["tags"] = [tag for tag in OPENAPI_TAGS if tag["name"] in included_tag_names]

    for path, path_item in openapi_schema.get("paths", {}).items():
        for method, operation in path_item.items():
            documentation = OPENAPI_OPERATION_DOCUMENTATION.get((method.upper(), path))
            if documentation is None or not isinstance(operation, dict):
                continue

            summary, description, tag = documentation
            operation["summary"] = summary
            operation["description"] = description
            operation["tags"] = [tag]
            for response in operation.get("responses", {}).values():
                if response.get("description") == "Successful Response":
                    response["description"] = "请求成功"
                elif response.get("description") == "Validation Error":
                    response["description"] = "请求参数校验失败"

    component_schemas = openapi_schema.get("components", {}).get("schemas", {})
    for schema_name, chinese_description in OPENAPI_SCHEMA_DESCRIPTIONS.items():
        if schema_name in component_schemas:
            component_schemas[schema_name]["description"] = chinese_description

    return openapi_schema


def get_public_openapi_routes() -> list[APIRoute]:
    """Return only health and non-Admin external service routes."""
    return [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.include_in_schema
        and (
            route.path == "/health"
            or route.path.startswith("/api/v1/leases")
            or route.path.startswith("/api/v1/mailboxes")
            or route.path == "/api/v1/usage-sites"
        )
    ]


public_openapi_schema_cache: dict[str, Any] | None = None


def build_public_openapi_schema() -> dict[str, Any]:
    """Build the public schema without Admin paths, models, or authentication."""
    global public_openapi_schema_cache
    if public_openapi_schema_cache is None:
        public_openapi_schema_cache = build_documented_openapi_schema(
            title="邮箱服务外部 API",
            description=(
                "面向外部调用方的邮箱租约与 Token 服务。受保护接口使用 X-API-Key 请求头认证。"
            ),
            routes=get_public_openapi_routes(),
            included_tag_names=PUBLIC_OPENAPI_TAG_NAMES,
        )
    return public_openapi_schema_cache


app.openapi = build_public_openapi_schema


@app.get("/openapi.json", include_in_schema=False)
def get_public_openapi_json() -> JSONResponse:
    """Return the machine-readable public OpenAPI schema."""
    return JSONResponse(build_public_openapi_schema())


@app.get("/docs", include_in_schema=False)
def get_public_swagger_ui() -> HTMLResponse:
    """Render Swagger UI for external service APIs only."""
    return get_swagger_ui_html(openapi_url="/openapi.json", title="邮箱服务外部 API - Swagger UI")


@app.get("/redoc", include_in_schema=False)
def get_public_redoc() -> HTMLResponse:
    """Render ReDoc for external service APIs only."""
    return get_redoc_html(openapi_url="/openapi.json", title="邮箱服务外部 API - ReDoc")


_cors_settings = get_settings()
_cors_origins = _cors_settings.cors_origins_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    # Browsers reject allow_credentials=True together with Access-Control-Allow-Origin: *.
    allow_credentials="*" not in _cors_origins,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Admin-Token", "X-API-Key"],
)


@app.get("/openapi-viewer", include_in_schema=False, response_class=HTMLResponse)
def get_openapi_viewer() -> HTMLResponse:
    """提供不受浏览器 JSON 主题影响的 OpenAPI JSON 人工查看页。"""
    return HTMLResponse(
        content="""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenAPI JSON 查看器</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; background: #111827; color: #e5e7eb; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    header { position: sticky; top: 0; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 20px; background: #1f2937; border-bottom: 1px solid #374151; }
    h1 { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 16px; }
    nav { display: flex; gap: 14px; }
    a { color: #93c5fd; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 13px; text-decoration: none; }
    a:hover { text-decoration: underline; }
    pre { margin: 0; padding: 20px; overflow: auto; white-space: pre; tab-size: 2; font-size: 13px; line-height: 1.55; }
    .error { color: #fca5a5; }
  </style>
</head>
<body>
  <header>
    <h1>OpenAPI JSON 查看器</h1>
    <nav><a href="/docs">Swagger UI</a><a href="/redoc">ReDoc</a><a href="/openapi.json">原始 JSON</a></nav>
  </header>
  <pre id="openapi-json">正在加载 OpenAPI JSON...</pre>
  <script>
    const outputElement = document.getElementById("openapi-json");
    fetch("/openapi.json")
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((openapiSchema) => {
        outputElement.textContent = JSON.stringify(openapiSchema, null, 2);
      })
      .catch((error) => {
        outputElement.className = "error";
        outputElement.textContent = `OpenAPI JSON 加载失败：${error.message}`;
      });
  </script>
</body>
</html>"""
    )


def get_credential_cipher(settings: Settings) -> CredentialCipher | None:
    """Construct the configured cipher only when a runtime key is supplied."""
    if settings.credential_encryption_key is None:
        return None
    return CredentialCipher(settings.credential_encryption_key)


def get_proxy_service(session: SessionDependency, settings: SettingsDependency) -> EgressProxyService:
    """Provide request-local proxy domain services backed by one transaction."""
    return EgressProxyService(session, settings, get_credential_cipher(settings))


ProxyServiceDependency = Annotated[EgressProxyService, Depends(get_proxy_service)]


def get_access_token_service(
    session: SessionDependency,
    settings: SettingsDependency,
) -> MailboxAccessTokenService:
    """Provide request-local AT cache services backed by encrypted storage.

    OAuth/IMAP/Graph transports use an independent proxy Unit of Work so network
    I/O never commits or holds the request-scoped session.
    """
    cipher = get_credential_cipher(settings)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )
    transport_proxy_service = EgressProxyService(
        session_factory=SessionFactory,
        settings=settings,
        credential_cipher=cipher,
    )
    oauth_client = MicrosoftOAuthClient(transport_proxy_service, settings)
    capability_prober = MailboxCapabilityProbeService(
        settings,
        MicrosoftIMAPClient(transport_proxy_service, settings),
        MicrosoftGraphMailProbeClient(transport_proxy_service, settings),
        oauth_client=oauth_client,
    )
    return MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        capability_prober=capability_prober,
        session_factory=SessionFactory,
    )


AccessTokenServiceDependency = Annotated[MailboxAccessTokenService, Depends(get_access_token_service)]


def get_client_principal(
    session: SessionDependency,
    api_key: Annotated[str | None, Depends(client_api_key_header)],
) -> ClientPrincipal:
    """Authenticate an external caller without accepting the Admin Token."""
    try:
        return ClientKeyService(session).authenticate(api_key)
    except ClientKeyAuthenticationError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "CLIENT_API_KEY_INVALID", "message": "Client API Key 无效"},
        ) from error


ClientPrincipalDependency = Annotated[ClientPrincipal, Depends(get_client_principal)]


def get_lease_service(
    session: SessionDependency,
    settings: SettingsDependency,
    access_token_service: AccessTokenServiceDependency,
) -> LeaseService:
    """Provide request-local external lease services with encrypted Token access."""
    credential_cipher = get_credential_cipher(settings)
    if credential_cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )
    return LeaseService(
        session,
        credential_cipher,
        access_token_service,
        session_factory=SessionFactory,
    )


LeaseServiceDependency = Annotated[LeaseService, Depends(get_lease_service)]


def get_verification_code_service(
    settings: SettingsDependency,
    access_token_service: AccessTokenServiceDependency,
) -> VerificationCodeService:
    """Provide verification-code extraction that uses short-lived sessions per poll attempt."""
    return VerificationCodeService(
        access_token_service,
        settings=settings,
    )


VerificationCodeServiceDependency = Annotated[VerificationCodeService, Depends(get_verification_code_service)]


def require_admin(
    settings: SettingsDependency,
    admin_token: Annotated[str | None, Depends(admin_token_header)],
) -> str:
    """Protect administrative endpoints without embedding a development fallback secret."""
    if settings.admin_api_token is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "ADMIN_AUTH_NOT_CONFIGURED", "message": "管理员认证尚未配置"},
        )
    if admin_token is None or not hmac.compare_digest(admin_token, settings.admin_api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "ADMIN_AUTH_REQUIRED", "message": "管理员认证失败"},
        )
    return "environment-admin"


AdminDependency = Annotated[str, Depends(require_admin)]


def build_client_key_response(client_key: ClientKey) -> ClientKeyListItemResponse:
    """Serialize Client Key metadata without secret or digest fields."""
    return ClientKeyListItemResponse(
        id=client_key.id,
        name=client_key.name,
        scopes=client_key.scopes,
        enabled=client_key.enabled,
        expires_at=client_key.expires_at,
        last_used_at=client_key.last_used_at,
        created_at=client_key.created_at,
        updated_at=client_key.updated_at,
    )


def configure_no_store(response: Response) -> None:
    """Prevent browsers and intermediary caches from retaining credential responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def to_external_http_exception(error: Exception) -> HTTPException:
    """Map domain failures to stable external API error contracts."""
    external_api_logger = logging.getLogger("uvicorn.error")
    if isinstance(error, ClientKeyScopeError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CLIENT_SCOPE_REQUIRED", "message": str(error)},
        )
    if isinstance(error, ProviderUnsupportedError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "PROVIDER_UNSUPPORTED", "message": str(error)},
        )
    if isinstance(error, ProviderNotConfiguredError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "PROVIDER_NOT_CONFIGURED", "message": str(error)},
        )
    try:
        from mailbox_service.providers.smsbower_gmail import SmsBowerUnsupportedFilterError
        from mailbox_service.providers.microsoft_guards import ProviderNotMicrosoftError
    except Exception:  # pragma: no cover - import always available in production
        SmsBowerUnsupportedFilterError = ()  # type: ignore[misc, assignment]
        ProviderNotMicrosoftError = ()  # type: ignore[misc, assignment]
    if isinstance(error, SmsBowerUnsupportedFilterError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "PROVIDER_FILTER_UNSUPPORTED", "message": str(error)},
        )
    if isinstance(error, ProviderNotMicrosoftError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "PROVIDER_NOT_MICROSOFT", "message": str(error)},
        )
    if isinstance(error, LeaseNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "LEASE_NOT_FOUND", "message": str(error)},
        )
    if isinstance(error, LeaseEmailNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EMAIL_NOT_FOUND", "message": str(error)},
        )
    if isinstance(error, LeaseMailboxBusyError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "MAILBOX_BUSY", "message": str(error)},
        )
    if isinstance(error, LeaseUsageSiteError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_USAGE_SITE", "message": str(error)},
        )
    if isinstance(error, LeaseEmailSiteConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "EMAIL_SITE_IN_USE", "message": str(error)},
        )
    if isinstance(error, LeaseUnavailableError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "NO_AVAILABLE_MAILBOX", "message": str(error)},
        )
    if isinstance(error, LeaseInactiveError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "LEASE_INACTIVE", "message": str(error)},
        )
    if isinstance(error, LeaseModeError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "LEASE_MODE_MISMATCH", "message": str(error)},
        )
    if isinstance(error, TokenVersionConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "TOKEN_VERSION_CONFLICT", "message": str(error)},
        )
    if isinstance(error, MicrosoftInvalidGrantError):
        external_api_logger.warning(
            "external_api_error code=MICROSOFT_REFRESH_TOKEN_INVALID status=409 message=%s",
            summarize_exception(error),
        )
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "MICROSOFT_REFRESH_TOKEN_INVALID", "message": str(error)},
        )
    if isinstance(error, MicrosoftOAuthError):
        external_api_logger.warning(
            "external_api_error code=MICROSOFT_TOKEN_REFRESH_FAILED status=502 message=%s",
            summarize_exception(error),
        )
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "MICROSOFT_TOKEN_REFRESH_FAILED", "message": str(error)},
        )
    if isinstance(error, VerificationCodeReadError):
        external_api_logger.warning(
            "external_api_error code=MAILBOX_INBOX_READ_FAILED status=502 message=%s",
            summarize_exception(error),
        )
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "MAILBOX_INBOX_READ_FAILED", "message": str(error)},
        )
    if isinstance(error, ValueError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_REQUEST", "message": str(error)},
        )
    external_api_logger.error(
        "external_api_error code=EXTERNAL_API_ERROR status=500 message=%s",
        summarize_exception(error),
    )
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"code": "EXTERNAL_API_ERROR", "message": "外部服务请求处理失败"},
    )


def create_audit_log(
    session: Session,
    actor_id: str,
    event_type: str,
    target_type: str,
    target_id: str | None,
    metadata: dict[str, Any],
    *,
    operation_id: str | None = None,
) -> None:
    """Persist an Admin audit event after callers have already removed secret values."""
    from mailbox_service.audit_service import write_audit_event

    write_audit_event(
        session,
        actor_type="admin",
        actor_id=actor_id,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        metadata=metadata,
        operation_id=operation_id,
    )


def serialize_proxy(proxy: EgressProxy, bound_mailbox_count: int = 0) -> EgressProxyResponse:
    """Build the only proxy response shape exposed by Admin APIs."""
    return EgressProxyResponse(
        id=proxy.id,
        name=proxy.name,
        protocol=proxy.protocol,
        host=proxy.host,
        host_preview=redact_proxy_host(proxy.host),
        port=proxy.port,
        enabled=proxy.enabled,
        priority=proxy.priority,
        status=proxy.status,
        has_credentials=proxy.username_ciphertext is not None or proxy.password_ciphertext is not None,
        consecutive_failure_count=proxy.consecutive_failure_count,
        cooldown_until=proxy.cooldown_until,
        last_success_at=proxy.last_success_at,
        last_failure_at=proxy.last_failure_at,
        last_error_summary=proxy.last_error_summary,
        bound_mailbox_count=bound_mailbox_count,
        created_at=proxy.created_at,
        updated_at=proxy.updated_at,
    )


def serialize_policy(policy: ProxyPolicy) -> ProxyPolicyResponse:
    """Return policy data without deriving behavior from the browser."""
    return ProxyPolicyResponse(
        enabled=policy.enabled,
        required=policy.required,
        allowed_protocols=policy.allowed_protocols,
        connect_timeout_seconds=policy.connect_timeout_seconds,
        read_timeout_seconds=policy.read_timeout_seconds,
        health_check_interval_seconds=policy.health_check_interval_seconds,
        failure_threshold=policy.failure_threshold,
        cooldown_seconds=policy.cooldown_seconds,
        switch_minimum_interval_seconds=policy.switch_minimum_interval_seconds,
        allow_direct_development=policy.allow_direct_development,
        updated_at=policy.updated_at,
    )


def raise_for_egress_proxy_integrity_error(error: IntegrityError) -> None:
    """Map unique-constraint violations into stable Admin API conflict responses."""
    error_message = str(error.orig) if getattr(error, "orig", None) is not None else str(error)
    lowered_error_message = error_message.lower()
    endpoint_conflict_markers = (
        "uq_egress_proxies_endpoint_credentials",
        "uq_egress_proxies_endpoint",
        "credential_fingerprint",
        "egress_proxies.protocol",
        "protocol, egress_proxies.host, egress_proxies.port",
        "protocol, host, port",
    )
    name_conflict_markers = (
        "uq_egress_proxies_name",
        "egress_proxies.name",
    )
    if any(marker in lowered_error_message for marker in endpoint_conflict_markers):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "EGRESS_PROXY_ENDPOINT_CONFLICT",
                "message": (
                    "相同协议、主机、端口以及用户名/密码的出口代理已存在。"
                    "代理池节点若用户名或密码不同可分别创建；完全相同则请编辑现有代理。"
                ),
            },
        ) from error
    if any(marker in lowered_error_message for marker in name_conflict_markers):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "EGRESS_PROXY_NAME_CONFLICT",
                "message": "出口代理名称已存在，请更换名称后再试。",
            },
        ) from error
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "EGRESS_PROXY_CONFLICT",
            "message": "出口代理保存冲突，请检查名称与端点是否重复。",
        },
    ) from error


def resolve_proxy_credential_fingerprint(
    username: str | None,
    password: str | None,
    cipher: CredentialCipher | None,
) -> str:
    """Build the unique-identity fingerprint for one proxy-pool membership."""
    return build_proxy_credential_fingerprint(
        username,
        password,
        hmac_key=cipher.hmac_key if cipher is not None else None,
    )


def _normalize_optional_proxy_secret(value: str | None) -> str | None:
    """Treat missing/blank form values as omitted so copy dialogs can clone credentials."""
    if value is None:
        return None
    # Passwords may intentionally contain only spaces; only pure empty means omitted.
    if value == "":
        return None
    return value


def read_proxy_plaintext_credentials(
    proxy: EgressProxy,
    cipher: CredentialCipher | None,
) -> tuple[str | None, str | None]:
    """Decrypt stored proxy credentials when a cipher is available."""
    if cipher is None:
        return None, None
    username = cipher.decrypt(proxy.username_ciphertext) if proxy.username_ciphertext else None
    password = cipher.decrypt(proxy.password_ciphertext) if proxy.password_ciphertext else None
    return username, password


def get_proxy_or_404(session: Session, proxy_id: str) -> EgressProxy:
    """Fetch a proxy or expose a stable administrative not-found error."""
    proxy = session.get(EgressProxy, proxy_id)
    if proxy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EGRESS_PROXY_NOT_FOUND", "message": "出口代理不存在"},
        )
    return proxy


def parse_mailbox_import_line(line_number: int, raw_line: str) -> tuple[str, str, str, str] | MailboxImportLineError:
    """Parse one four-segment mailbox import line without exposing secret values."""
    normalized_line = raw_line.strip().lstrip("\ufeff")
    segments = [segment.strip() for segment in normalized_line.split("----")]
    if len(segments) != 4:
        return MailboxImportLineError(line_number=line_number, message="每行必须包含 4 段，并使用 ---- 分隔。")

    primary_email, mail_password, client_id, refresh_token = segments
    if not primary_email or not mail_password or not client_id or not refresh_token:
        return MailboxImportLineError(line_number=line_number, message="邮箱、邮箱密码、Client ID 和 Refresh Token 均不能为空。")

    try:
        validated_email = validate_email(primary_email, check_deliverability=False)
    except EmailNotValidError:
        return MailboxImportLineError(line_number=line_number, message="邮箱格式无效。")

    return validated_email.normalized, mail_password, client_id, refresh_token


@app.get("/health")
def get_health() -> dict[str, str]:
    """Return a side-effect-free liveness-compatible response for local deployment checks."""
    return {"status": "ok"}


@app.get("/live")
def get_liveness() -> dict[str, str]:
    """Process liveness probe: does not touch the database."""
    return {"status": "alive"}


@app.get("/ready")
def get_readiness(session: SessionDependency) -> dict[str, str]:
    """Readiness probe: verifies the database accepts a trivial query."""
    from sqlalchemy import text as sql_text

    try:
        session.execute(sql_text("SELECT 1"))
    except Exception as error:  # noqa: BLE001 - map any connectivity failure to 503.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "DATABASE_NOT_READY", "message": "数据库尚未就绪"},
        ) from error
    return {"status": "ready"}


@app.post(
    "/api/v1/mailboxes/acquire",
    response_model=MailboxAcquireResponse,
    status_code=status.HTTP_201_CREATED,
)
def acquire_mailbox_account(
    payload: MailboxAcquireRequest,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> MailboxAcquireResponse:
    """Acquire one usable mailbox account as a mail_read lease without returning tokens."""
    try:
        # Explicit when caller named one or more concrete types (not omitted / all).
        explicit_provider = payload.provider is not None
        result = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=payload.lease_ttl_seconds,
            preferred_email=payload.preferred_email,
            client_tag=payload.client_tag,
            purpose=payload.purpose,
            use_plus_alias=payload.use_plus_alias,
            preferred_alias_suffix=payload.alias_suffix,
            usage_site=payload.usage_site,
            provider=payload.provider,
            exclude_providers=payload.exclude_providers,
            explicit_provider_request=explicit_provider,
        )
    except Exception as error:
        raise to_external_http_exception(error) from error
    return MailboxAcquireResponse(
        lease_id=result.lease_id,
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        allocated_email=result.allocated_email or result.primary_email,
        address_kind=result.address_kind,
        usage_site=result.usage_site,
        provider=result.provider_type,
        mode=LeaseMode.MAIL_READ,
        expires_at=result.expires_at,
        created_at=result.created_at,
    )


@app.get("/api/v1/usage-sites", response_model=UsageSiteListResponse)
def list_enabled_usage_sites(
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> UsageSiteListResponse:
    """List enabled registration sites for mail_read acquire clients."""
    try:
        sites = lease_service.list_enabled_usage_sites(principal)
    except Exception as error:
        raise to_external_http_exception(error) from error
    return UsageSiteListResponse(
        items=[
            UsageSiteItemResponse(
                code=site.code,
                display_name=site.display_name,
                enabled=site.enabled,
            )
            for site in sites
        ]
    )


@app.post(
    "/api/v1/mailboxes/reacquire",
    response_model=MailboxAcquireResponse,
    status_code=status.HTTP_201_CREATED,
)
def reacquire_mailbox_account(
    payload: MailboxReacquireRequest,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> MailboxAcquireResponse:
    """Re-open a mail_read lease for a historically owned primary or plus-alias address."""
    try:
        result = lease_service.reacquire_lease_by_email(
            principal,
            email=payload.email,
            ttl_seconds=payload.lease_ttl_seconds,
            client_tag=payload.client_tag,
            purpose=payload.purpose,
        )
    except Exception as error:
        raise to_external_http_exception(error) from error
    return MailboxAcquireResponse(
        lease_id=result.lease_id,
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        allocated_email=result.allocated_email or result.primary_email,
        address_kind=result.address_kind,
        usage_site=None,
        mode=LeaseMode.MAIL_READ,
        expires_at=result.expires_at,
        created_at=result.created_at,
    )


@app.post(
    "/api/v1/leases/{lease_id}/verification-code",
    response_model=LeaseVerificationCodeResponse,
)
async def get_lease_verification_code(
    lease_id: str,
    payload: LeaseVerificationCodeRequest,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
    verification_code_service: VerificationCodeServiceDependency,
    session: SessionDependency,
    settings: SettingsDependency,
) -> LeaseVerificationCodeResponse:
    """Extract a verification code from recent inbox mail for an owned mail_read lease."""
    verification_code_logger = logging.getLogger("uvicorn.error")
    response_mailbox_id: str | None = None
    response_primary_email: str | None = None
    try:
        # Initial authorization checkpoint (also enforces scope).
        auth_snapshot = revalidate_verification_authorization(
            session, principal=principal, lease_id=lease_id
        )
        lease, mailbox = lease_service.load_active_mail_read_lease(principal, lease_id)
        response_lease_id = lease.id
        response_mailbox_id = mailbox.id
        response_primary_email = mailbox.primary_email
        response_allocated_email = lease.allocated_email or mailbox.primary_email
        default_recipient = payload.recipient or response_allocated_email
        # End request transaction before long polling so locks are not held across waits.
        session.commit()

        def _checkpoint() -> None:
            with SessionFactory() as checkpoint_session:
                try:
                    revalidate_verification_authorization(
                        checkpoint_session,
                        principal=principal,
                        lease_id=lease_id,
                    )
                    checkpoint_session.commit()
                except Exception:
                    checkpoint_session.rollback()
                    raise

        with acquire_verification_poll_slot(
            settings,
            client_key_id=principal.client_key_id,
            lease_id=response_lease_id,
        ):
            lookup_result = await verification_code_service.wait_for_verification_code(
                mailbox,
                VerificationCodeLookupOptions(
                    timeout_seconds=payload.timeout_seconds,
                    since_seconds=payload.since_seconds,
                    poll_interval_seconds=payload.poll_interval_seconds,
                    from_address=payload.from_address,
                    subject_contains=payload.subject_contains,
                    body_contains=payload.body_contains,
                    code_regex=payload.code_regex,
                    recipient=default_recipient,
                    require_recipient_match=payload.require_recipient_match,
                ),
                authorization_checkpoint=_checkpoint,
            )
    except VerificationPollCapacityExceededError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "VERIFICATION_POLL_CAPACITY_EXCEEDED",
                "message": "验证码轮询并发已达上限，请稍后重试",
                "scope": error.scope,
            },
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from error
    except VerificationAuthorizationError as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN
            if error.code.startswith("CLIENT_KEY")
            else status.HTTP_409_CONFLICT,
            detail={"code": error.code, "message": error.message},
        ) from error
    except Exception as error:
        verification_code_logger.warning(
            "verification_code_request_failed lease_id=%s mailbox_id=%s primary_email=%s error=%s",
            lease_id,
            response_mailbox_id or "-",
            response_primary_email or "-",
            summarize_exception(error),
        )
        raise to_external_http_exception(error) from error
    return LeaseVerificationCodeResponse(
        lease_id=response_lease_id,
        mailbox_id=response_mailbox_id,
        primary_email=response_primary_email,
        allocated_email=response_allocated_email,
        found=lookup_result.found,
        code=lookup_result.code,
        matched_from=lookup_result.matched_from,
        matched_subject=lookup_result.matched_subject,
        message_received_at=lookup_result.message_received_at,
        channel=lookup_result.channel,
        attempts=lookup_result.attempts,
    )


@app.post(
    "/api/v1/leases/acquire",
    response_model=LeaseAcquireResponse,
    status_code=status.HTTP_201_CREATED,
)
def acquire_external_lease(
    payload: LeaseAcquireRequest,
    response: Response,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> LeaseAcquireResponse:
    """Acquire one mailbox lease and return the credential selected by its mode."""
    try:
        if payload.provider not in (None, "microsoft"):
            raise ProviderUnsupportedError("leases/acquire 本轮仅支持省略 provider 或 provider=microsoft")
        result = lease_service.acquire_lease(
            principal,
            mode=LeaseMode(payload.mode),
            ttl_seconds=payload.lease_ttl_seconds,
            preferred_email=payload.preferred_email,
            client_tag=payload.client_tag,
            purpose=payload.purpose,
            provider=payload.provider or "microsoft",
            explicit_provider_request=payload.provider is not None,
        )
    except Exception as error:
        raise to_external_http_exception(error) from error

    configure_no_store(response)
    if result.mode == LeaseMode.ACCESS_TOKEN:
        if (
            result.access_token is None
            or result.access_token_expires_at is None
            or result.access_token_refreshed is None
            or result.token_version is None
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"code": "LEASE_CREDENTIAL_MISSING", "message": "租约凭证生成失败"},
            )
        credential = AccessTokenLeaseCredentialResponse(
            access_token=result.access_token,
            expires_at=result.access_token_expires_at,
            refreshed=result.access_token_refreshed,
            token_version=result.token_version,
        )
    else:
        if result.client_id is None or result.refresh_token is None or result.token_version is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"code": "LEASE_CREDENTIAL_MISSING", "message": "租约凭证生成失败"},
            )
        credential = RefreshTokenLeaseCredentialResponse(
            client_id=result.client_id,
            refresh_token=result.refresh_token,
            token_version=result.token_version,
        )

    return LeaseAcquireResponse(
        lease_id=result.lease_id,
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        mode=result.mode,
        expires_at=result.expires_at,
        created_at=result.created_at,
        credential=credential,
    )


@app.post("/api/v1/leases/{lease_id}/release", response_model=LeaseReleaseResponse)
def release_external_lease(
    lease_id: str,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
    session: SessionDependency,
    settings: SettingsDependency,
) -> LeaseReleaseResponse:
    """Idempotently release an active lease owned by the authenticated Client Key."""
    try:
        result = lease_service.release_lease(principal, lease_id)
        # Durable remote finalize runs after local release is durable.
        # request Session is committed by middleware after success; finalize opens short UoWs.
        _maybe_finalize_smsbower_release(session, settings, lease_id)
    except Exception as error:
        raise to_external_http_exception(error) from error
    return LeaseReleaseResponse(lease_id=result.lease_id, released_at=result.released_at)


@app.post("/api/v1/leases/{lease_id}/access-token", response_model=LeaseAccessTokenResponse)
def get_external_lease_access_token(
    lease_id: str,
    response: Response,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> LeaseAccessTokenResponse:
    """Return a cached or refreshed Access Token for an owned active lease."""
    try:
        result = lease_service.get_access_token(principal, lease_id)
    except Exception as error:
        raise to_external_http_exception(error) from error
    configure_no_store(response)
    return LeaseAccessTokenResponse(
        lease_id=lease_id,
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        access_token=result.access_token,
        expires_at=result.expires_at,
        token_version=result.token_version,
        refreshed=result.refreshed,
        refresh_token_rotated=result.refresh_token_rotated,
    )


@app.post("/api/v1/leases/{lease_id}/refresh-token", response_model=LeaseRefreshTokenUpdateResponse)
def update_external_lease_refresh_token(
    lease_id: str,
    payload: LeaseRefreshTokenUpdateRequest,
    response: Response,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
) -> LeaseRefreshTokenUpdateResponse:
    """CAS-update the Refresh Token associated with an owned active lease."""
    try:
        result = lease_service.update_refresh_token(
            principal,
            lease_id,
            expected_token_version=payload.expected_token_version,
            refresh_token=payload.refresh_token,
        )
    except Exception as error:
        raise to_external_http_exception(error) from error
    configure_no_store(response)
    return LeaseRefreshTokenUpdateResponse(
        lease_id=result.lease_id,
        mailbox_id=result.mailbox_id,
        updated=result.updated,
        token_version=result.token_version,
    )


@app.post(
    "/api/v1/admin/client-keys",
    response_model=ClientKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_client_key(
    payload: ClientKeyCreateRequest,
    response: Response,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> ClientKeyCreatedResponse:
    """Create an external Client Key and return its plaintext value exactly once."""
    try:
        creation_result = ClientKeyService(session).create_client_key(
            name=payload.name,
            scopes=payload.scopes,
            expires_at=payload.expires_at,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "CLIENT_KEY_INVALID", "message": str(error)},
        ) from error
    configure_no_store(response)
    create_audit_log(
        session,
        admin_id,
        "client_key.created",
        "client_key",
        creation_result.client_key.id,
        {"name": creation_result.client_key.name, "scopes": creation_result.client_key.scopes},
    )
    return ClientKeyCreatedResponse(
        id=creation_result.client_key.id,
        name=creation_result.client_key.name,
        api_key=creation_result.api_key,
        scopes=creation_result.client_key.scopes,
        enabled=creation_result.client_key.enabled,
        expires_at=creation_result.client_key.expires_at,
        created_at=creation_result.client_key.created_at,
    )


@app.get("/api/v1/admin/client-keys", response_model=list[ClientKeyListItemResponse])
def list_client_keys(
    session: SessionDependency,
    _: AdminDependency,
) -> list[ClientKeyListItemResponse]:
    """List Client Key metadata without returning plaintext keys or digests."""
    return [build_client_key_response(client_key) for client_key in ClientKeyService(session).list_client_keys()]


@app.patch("/api/v1/admin/client-keys/{client_key_id}", response_model=ClientKeyListItemResponse)
def update_client_key(
    client_key_id: str,
    payload: ClientKeyUpdateRequest,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> ClientKeyListItemResponse:
    """Update one Client Key name and scopes without rotating the secret."""
    try:
        client_key = ClientKeyService(session).update_client_key(
            client_key_id,
            name=payload.name,
            scopes=payload.scopes,
        )
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CLIENT_KEY_NOT_FOUND", "message": str(error)},
        ) from error
    except ValueError as error:
        message = str(error)
        if "名称已存在" in message:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "CLIENT_KEY_NAME_CONFLICT", "message": message},
            ) from error
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "CLIENT_KEY_INVALID", "message": message},
        ) from error
    create_audit_log(
        session,
        admin_id,
        "client_key.updated",
        "client_key",
        client_key.id,
        {"name": client_key.name, "scopes": client_key.scopes},
    )
    return build_client_key_response(client_key)


@app.post("/api/v1/admin/client-keys/{client_key_id}/disable", response_model=ClientKeyListItemResponse)
def disable_client_key(
    client_key_id: str,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> ClientKeyListItemResponse:
    """Disable one Client Key and immediately reject subsequent external requests."""
    try:
        client_key = ClientKeyService(session).disable_client_key(client_key_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CLIENT_KEY_NOT_FOUND", "message": str(error)},
        ) from error
    create_audit_log(
        session,
        admin_id,
        "client_key.disabled",
        "client_key",
        client_key.id,
        {"name": client_key.name},
    )
    return build_client_key_response(client_key)


@app.get("/api/v1/admin/dashboard", response_model=DashboardSummaryResponse)
def get_dashboard_summary(
    session: SessionDependency,
    _: AdminDependency,
) -> DashboardSummaryResponse:
    """Return overview metrics for the Admin console without exposing secrets."""
    # MySQL DATETIME is typically naive; strip tzinfo so SQL comparisons stay consistent.
    current_time = utc_now().replace(tzinfo=None)
    total_mailbox_count = session.scalar(select(func.count(Mailbox.id))) or 0
    active_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.status == MailboxStatus.ACTIVE)
    ) or 0
    # Operationally usable: active status plus a verified mail-access channel.
    usable_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(
            Mailbox.status == MailboxStatus.ACTIVE,
            Mailbox.capability.in_((MailboxCapability.IMAP, MailboxCapability.GRAPH)),
        )
    ) or 0
    invalid_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.status == MailboxStatus.INVALID)
    ) or 0
    disabled_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.status == MailboxStatus.DISABLED)
    ) or 0
    cooldown_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.status == MailboxStatus.COOLDOWN)
    ) or 0
    # Capability is the operational health signal used by the admin console mailbox list.
    imap_capable_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.capability == MailboxCapability.IMAP)
    ) or 0
    graph_capable_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.capability == MailboxCapability.GRAPH)
    ) or 0
    unusable_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.capability == MailboxCapability.UNUSABLE)
    ) or 0
    unprobed_capability_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.capability.is_(None))
    ) or 0
    active_lease_count = session.scalar(
        select(func.count(Lease.id)).where(Lease.released_at.is_(None), Lease.expires_at > current_time)
    ) or 0
    expired_lease_count = session.scalar(
        select(func.count(Lease.id)).where(Lease.released_at.is_(None), Lease.expires_at <= current_time)
    ) or 0
    total_proxy_count = session.scalar(select(func.count(EgressProxy.id))) or 0
    healthy_proxy_count = session.scalar(
        select(func.count(EgressProxy.id)).where(
            EgressProxy.enabled.is_(True), EgressProxy.status == EgressProxyStatus.HEALTHY
        )
    ) or 0
    cooldown_proxy_count = session.scalar(
        select(func.count(EgressProxy.id)).where(EgressProxy.status == EgressProxyStatus.COOLDOWN)
    ) or 0
    bound_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.egress_proxy_id.is_not(None))
    ) or 0
    recent_audit_count = session.scalar(select(func.count(AuditLog.id))) or 0
    return DashboardSummaryResponse(
        total_mailbox_count=total_mailbox_count,
        active_mailbox_count=active_mailbox_count,
        usable_mailbox_count=usable_mailbox_count,
        invalid_mailbox_count=invalid_mailbox_count,
        disabled_mailbox_count=disabled_mailbox_count,
        cooldown_mailbox_count=cooldown_mailbox_count,
        imap_capable_mailbox_count=imap_capable_mailbox_count,
        graph_capable_mailbox_count=graph_capable_mailbox_count,
        unusable_mailbox_count=unusable_mailbox_count,
        unprobed_capability_mailbox_count=unprobed_capability_mailbox_count,
        active_lease_count=active_lease_count,
        expired_lease_count=expired_lease_count,
        total_proxy_count=total_proxy_count,
        healthy_proxy_count=healthy_proxy_count,
        cooldown_proxy_count=cooldown_proxy_count,
        bound_mailbox_count=bound_mailbox_count,
        recent_audit_count=recent_audit_count,
    )


@app.get("/api/v1/admin/mailboxes", response_model=MailboxListResponse)
def list_mailboxes(
    session: SessionDependency,
    _: AdminDependency,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> MailboxListResponse:
    """List mailbox operational metadata page by page without returning credentials."""
    current_time = utc_now()
    total_mailbox_count = session.scalar(select(func.count(Mailbox.id))) or 0
    total_pages = max(1, (total_mailbox_count + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    active_lease_count = (
        select(func.count(Lease.id))
        .where(Lease.mailbox_id == Mailbox.id)
        .where(Lease.released_at.is_(None), Lease.expires_at > current_time)
        .correlate(Mailbox)
        .scalar_subquery()
    )
    rows = session.execute(
        select(Mailbox, EgressProxy.name, active_lease_count.label("active_lease_count"))
        .outerjoin(EgressProxy, Mailbox.egress_proxy_id == EgressProxy.id)
        .order_by(Mailbox.updated_at.desc(), Mailbox.primary_email.asc())
        .offset(offset)
        .limit(page_size)
    ).all()
    response_items = [
        MailboxListItemResponse(
            id=mailbox.id,
            primary_email=mailbox.primary_email,
            status=mailbox.status,
            client_id=mailbox.client_id,
            token_version=mailbox.token_version,
            egress_proxy_id=mailbox.egress_proxy_id,
            egress_proxy_name=egress_proxy_name,
            proxy_bound_at=mailbox.proxy_bound_at,
            proxy_last_switch_at=mailbox.proxy_last_switch_at,
            has_access_token=mailbox.access_token_ciphertext is not None,
            access_token_expires_at=mailbox.access_token_expires_at,
            access_token_refreshed_at=mailbox.access_token_refreshed_at,
            refresh_token_updated_at=mailbox.refresh_token_updated_at,
            refresh_token_expires_at=mailbox.refresh_token_expires_at,
            scope=mailbox.scope,
            capability=mailbox.capability.value if mailbox.capability is not None else None,
            capability_probed_at=mailbox.capability_probed_at,
            capability_probe_error=mailbox.capability_probe_error,
            active_lease_count=count,
            created_at=mailbox.created_at,
            updated_at=mailbox.updated_at,
        )
        for mailbox, egress_proxy_name, count in rows
    ]
    return MailboxListResponse(
        total=total_mailbox_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=response_items,
    )




def _maybe_finalize_smsbower_release(session, settings: Settings, lease_id: str) -> None:
    """Best-effort setStatus after local release commit path (same request after flush)."""
    from mailbox_service.models import Lease, MailboxProviderOperation, MailboxProviderResource
    from mailbox_service.provider_operation_service import ProviderOperationService
    from mailbox_service.providers.ports import ReleaseOperationSnapshot
    from mailbox_service.providers.smsbower_contracts import SMSBOWER_STATUS_CLOSE_SUCCESS
    from mailbox_service.providers.smsbower_gmail import SmsBowerGmailProvider

    lease = session.get(Lease, lease_id)
    if lease is None or (lease.provider_type or "microsoft") != "smsbower_gmail":
        return
    operation = session.scalar(
        select(MailboxProviderOperation).where(
            MailboxProviderOperation.lease_id == lease_id,
            MailboxProviderOperation.operation_type == "release",
        ).order_by(MailboxProviderOperation.created_at.desc())
    )
    if operation is None or operation.status not in ("pending", "running", "unknown"):
        return
    resource = session.get(MailboxProviderResource, lease.mailbox_id)
    if resource is None:
        return
    # Commit local state before network.
    session.commit()
    provider = SmsBowerGmailProvider(
        settings,
        credential_cipher=get_credential_cipher(settings),
        session_factory=SessionFactory,
    )
    snapshot = ReleaseOperationSnapshot(
        operation_id=operation.id,
        provider_type=operation.provider_type,
        provider_instance_id=operation.provider_instance_id,
        external_resource_id=resource.external_resource_id,
        resource_generation=int(operation.resource_generation or resource.resource_generation or 0),
        expected_state_version=int(operation.expected_state_version or resource.state_version or 0),
        lease_id=lease_id,
        remote_status=SMSBOWER_STATUS_CLOSE_SUCCESS,
    )
    try:
        outcome = provider.finalize(snapshot)
    except Exception:
        outcome_status = "unknown"
        error_class = "exception"
        clear_secret = False
    else:
        outcome_status = outcome.outcome
        error_class = outcome.error_class
        clear_secret = outcome.outcome == "succeeded"
    with SessionFactory() as finalize_session:
        try:
            ops = ProviderOperationService(finalize_session)
            ops.finalize_release_cas(
                operation_id=operation.id,
                mailbox_id=lease.mailbox_id,
                expected_generation=int(snapshot.resource_generation),
                expected_state_version=int(snapshot.expected_state_version),
                outcome=outcome_status if outcome_status in ("succeeded", "failed", "unknown") else "unknown",
                clear_secret=clear_secret,
            )
            if error_class and outcome_status != "succeeded":
                op_row = finalize_session.get(MailboxProviderOperation, operation.id)
                if op_row is not None:
                    op_row.last_error_class = error_class
            finalize_session.commit()
        except Exception:
            finalize_session.rollback()


def _serialize_smsbower_settings(view) -> SmsbowerSettingsResponse:
    return SmsbowerSettingsResponse(
        provider_type=view.provider_type,
        instance_id=view.instance_id,
        enabled=view.enabled,
        api_base=view.api_base,
        service=view.service,
        domain=view.domain,
        max_price=view.max_price,
        request_timeout_seconds=view.request_timeout_seconds,
        has_api_key=view.has_api_key,
        source=view.source,
        env_enabled_default=view.env_enabled_default,
        updated_at=view.updated_at,
    )


@app.get("/api/v1/admin/providers", response_model=ProviderCatalogResponse)
def admin_list_providers(
    session: SessionDependency,
    settings: SettingsDependency,
    _: AdminDependency,
) -> ProviderCatalogResponse:
    """List known mailbox providers and whether they are UI-configurable."""
    from mailbox_service.provider_settings_service import ProviderSettingsService

    service = ProviderSettingsService(session, settings, get_credential_cipher(settings))
    items = [
        ProviderCatalogItemResponse(**item) for item in service.list_provider_summaries()
    ]
    return ProviderCatalogResponse(items=items)


@app.get(
    "/api/v1/admin/providers/{provider_type}/instances/{instance_id}",
    response_model=ProviderInstanceSettingsResponse,
)
def admin_get_provider_instance(
    provider_type: str,
    instance_id: str,
    session: SessionDependency,
    settings: SettingsDependency,
    _: AdminDependency,
) -> ProviderInstanceSettingsResponse:
    """Read one provider instance settings without secret plaintext."""
    from mailbox_service.provider_settings_service import ProviderSettingsService
    from mailbox_service.providers.catalog import ALL_PROVIDER_TYPES

    if provider_type not in ALL_PROVIDER_TYPES or provider_type == "microsoft":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "PROVIDER_NOT_FOUND", "message": f"未知或不可配置的 provider：{provider_type}"},
        )
    view = ProviderSettingsService(
        session, settings, get_credential_cipher(settings)
    ).get_provider_admin_view(provider_type, instance_id)
    return ProviderInstanceSettingsResponse(**view)


@app.put(
    "/api/v1/admin/providers/{provider_type}/instances/{instance_id}",
    response_model=ProviderInstanceSettingsResponse,
)
def admin_update_provider_instance(
    provider_type: str,
    instance_id: str,
    payload: ProviderInstanceSettingsUpdate,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> ProviderInstanceSettingsResponse:
    """Update one provider instance; secrets are encrypted and never returned."""
    from mailbox_service.provider_settings_service import ProviderSettingsService
    from mailbox_service.providers.catalog import ALL_PROVIDER_TYPES

    if provider_type not in ALL_PROVIDER_TYPES or provider_type == "microsoft":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "PROVIDER_NOT_FOUND", "message": f"未知或不可配置的 provider：{provider_type}"},
        )
    try:
        view = ProviderSettingsService(
            session, settings, get_credential_cipher(settings)
        ).update_provider_instance(
            provider_type,
            instance_id=instance_id,
            enabled=payload.enabled,
            values=payload.values,
            secrets=payload.secrets,
            clear_secrets=payload.clear_secrets,
        )
    except KeyError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "PROVIDER_NOT_FOUND", "message": str(error)},
        ) from error
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": str(error)},
        ) from error
    create_audit_log(
        session,
        admin_id,
        "provider.settings_updated",
        "provider_instance",
        f"{provider_type}:{instance_id}",
        {
            "provider_type": provider_type,
            "enabled": view.get("enabled"),
            "has_any_secret": view.get("has_any_secret"),
            "cleared_secrets": payload.clear_secrets or [],
            "updated_value_keys": sorted((payload.values or {}).keys()),
            "updated_secret_keys": sorted((payload.secrets or {}).keys()),
        },
    )
    return ProviderInstanceSettingsResponse(**view)


@app.get(
    "/api/v1/admin/providers/smsbower_gmail/settings",
    response_model=SmsbowerSettingsResponse,
)
def admin_get_smsbower_settings(
    session: SessionDependency,
    settings: SettingsDependency,
    _: AdminDependency,
) -> SmsbowerSettingsResponse:
    """Read SMSBower instance settings without API Key plaintext."""
    from mailbox_service.provider_settings_service import ProviderSettingsService

    view = ProviderSettingsService(
        session, settings, get_credential_cipher(settings)
    ).get_smsbower_admin_view()
    return _serialize_smsbower_settings(view)


@app.patch(
    "/api/v1/admin/providers/smsbower_gmail/settings",
    response_model=SmsbowerSettingsResponse,
)
def admin_update_smsbower_settings(
    payload: SmsbowerSettingsUpdate,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> SmsbowerSettingsResponse:
    """Update SMSBower settings; API Key is encrypted and never returned."""
    from mailbox_service.provider_settings_service import ProviderSettingsService

    cipher = get_credential_cipher(settings)
    service = ProviderSettingsService(session, settings, cipher)
    try:
        view = service.update_smsbower(
            enabled=payload.enabled,
            api_base=payload.api_base,
            service=payload.service,
            domain=payload.domain,
            max_price=payload.max_price,
            clear_max_price=payload.clear_max_price,
            request_timeout_seconds=payload.request_timeout_seconds,
            api_key=payload.api_key,
            clear_api_key=payload.clear_api_key,
        )
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": str(error)},
        ) from error
    create_audit_log(
        session,
        admin_id,
        "provider.settings_updated",
        "provider_instance",
        f"smsbower_gmail:{view.instance_id}",
        {
            "provider_type": "smsbower_gmail",
            "updated_fields": sorted(payload.model_fields_set),
            "has_api_key": view.has_api_key,
            "enabled": view.enabled,
        },
    )
    return _serialize_smsbower_settings(view)


@app.post(
    "/api/v1/admin/providers/smsbower_gmail/replenish",
    response_model=SmsbowerReplenishResponse,
)
def admin_replenish_smsbower(
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> SmsbowerReplenishResponse:
    """Admin-triggered SMSBower inventory replenish (single activation)."""
    cipher = get_credential_cipher(settings)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )
    from mailbox_service.providers.smsbower_gmail import SmsBowerGmailProvider, SmsBowerNotConfiguredError

    provider = SmsBowerGmailProvider(
        settings,
        credential_cipher=cipher,
        session_factory=SessionFactory,
    )
    try:
        outcome = provider.replenish_one(actor_id=admin_id)
    except SmsBowerNotConfiguredError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "PROVIDER_NOT_CONFIGURED", "message": str(error)},
        ) from error
    return SmsbowerReplenishResponse(
        operation_id=outcome.operation_id,
        status=outcome.status,
        mailbox_id=outcome.mailbox_id,
        primary_email=outcome.primary_email,
        external_resource_id=outcome.external_resource_id,
        error_class=outcome.error_class,
    )


@app.post("/api/v1/admin/mailboxes/import", response_model=MailboxImportResponse)
def import_mailboxes(
    payload: MailboxImportRequest,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> MailboxImportResponse:
    """Import mailbox credentials from four-segment text while encrypting secrets at rest."""
    cipher = get_credential_cipher(settings)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )

    created_count = 0
    updated_count = 0
    skipped_count = 0
    errors: list[MailboxImportLineError] = []
    seen_primary_emails: set[str] = set()

    for line_number, raw_line in enumerate(payload.content.splitlines(), start=1):
        if not raw_line.strip():
            continue

        parsed_line = parse_mailbox_import_line(line_number, raw_line)
        if isinstance(parsed_line, MailboxImportLineError):
            errors.append(parsed_line)
            continue

        primary_email, mail_password, client_id, refresh_token = parsed_line
        if primary_email in seen_primary_emails:
            errors.append(MailboxImportLineError(line_number=line_number, message="同一批导入中存在重复邮箱。"))
            continue
        seen_primary_emails.add(primary_email)

        existing_mailbox = session.scalar(select(Mailbox).where(Mailbox.primary_email == primary_email))
        if existing_mailbox is not None and (existing_mailbox.provider_type or "microsoft") != "microsoft":
            errors.append(
                MailboxImportLineError(
                    line_number=line_number,
                    message="邮箱已存在且属于其他 Provider，Microsoft 四段导入拒绝覆盖。",
                )
            )
            continue
        if existing_mailbox is not None and payload.on_conflict == "skip":
            skipped_count += 1
            continue
        if existing_mailbox is not None and payload.on_conflict == "error":
            errors.append(MailboxImportLineError(line_number=line_number, message="邮箱已存在。"))
            continue

        if existing_mailbox is not None and payload.on_conflict == "replace_token":
            admin_service = MailboxAdminService(session)
            if admin_service.list_active_claim_mailbox_ids([existing_mailbox.id]):
                if not payload.force_release_active_leases:
                    errors.append(
                        MailboxImportLineError(
                            line_number=line_number,
                            message="邮箱存在活跃租约 claim，默认拒绝替换；可 force_release_active_leases=true",
                        )
                    )
                    continue
                admin_service.force_release_active_claims(
                    existing_mailbox.id,
                    admin_id=admin_id,
                )

        encrypted_mail_password = cipher.encrypt(mail_password)
        encrypted_refresh_token = cipher.encrypt(refresh_token)
        refresh_token_touched_at = utc_now()
        if existing_mailbox is None:
            new_mailbox = Mailbox(
                primary_email=primary_email,
                provider_type="microsoft",
                status=MailboxStatus.ACTIVE,
                client_id=client_id,
                mail_password_ciphertext=encrypted_mail_password,
                refresh_token_ciphertext=encrypted_refresh_token,
            )
            stamp_refresh_token_lifetime(
                new_mailbox,
                lifetime_days=settings.refresh_token_lifetime_days,
                touched_at=refresh_token_touched_at,
            )
            session.add(new_mailbox)
            session.flush()
            create_audit_log(
                session,
                admin_id,
                "mailbox.import_item",
                "mailbox",
                new_mailbox.id,
                {
                    "action": "created",
                    "line_number": line_number,
                    "primary_email": primary_email,
                },
            )
            created_count += 1
        else:
            existing_mailbox.status = MailboxStatus.ACTIVE
            existing_mailbox.client_id = client_id
            existing_mailbox.mail_password_ciphertext = encrypted_mail_password
            existing_mailbox.refresh_token_ciphertext = encrypted_refresh_token
            stamp_refresh_token_lifetime(
                existing_mailbox,
                lifetime_days=settings.refresh_token_lifetime_days,
                touched_at=refresh_token_touched_at,
            )
            existing_mailbox.access_token_ciphertext = None
            existing_mailbox.access_token_expires_at = None
            existing_mailbox.access_token_refreshed_at = None
            existing_mailbox.access_token_source_version = None
            existing_mailbox.scope = None
            existing_mailbox.capability = None
            existing_mailbox.capability_probed_at = None
            existing_mailbox.capability_probe_error = None
            existing_mailbox.updated_at = refresh_token_touched_at
            # Persist field updates first, then atomically bump token_version in SQL (SEC-08).
            session.flush()
            from sqlalchemy import text as sql_text

            session.execute(
                sql_text(
                    "UPDATE mailboxes SET token_version = token_version + 1 "
                    "WHERE id = :mailbox_id"
                ),
                {"mailbox_id": existing_mailbox.id},
            )
            session.refresh(existing_mailbox)
            create_audit_log(
                session,
                admin_id,
                "mailbox.import_item",
                "mailbox",
                existing_mailbox.id,
                {
                    "action": "replaced",
                    "line_number": line_number,
                    "primary_email": primary_email,
                    "token_version": existing_mailbox.token_version,
                },
            )
            updated_count += 1

    if not seen_primary_emails and not errors:
        errors.append(MailboxImportLineError(line_number=0, message="导入内容没有可处理的邮箱行。"))

    session.flush()
    create_audit_log(
        session,
        admin_id,
        "mailbox.imported",
        "mailbox",
        None,
        {
            "created": created_count,
            "updated": updated_count,
            "skipped": skipped_count,
            "failed": len(errors),
            "on_conflict": payload.on_conflict,
        },
    )
    return MailboxImportResponse(
        created=created_count,
        updated=updated_count,
        skipped=skipped_count,
        failed=len(errors),
        errors=errors,
    )


def format_mailbox_import_line(
    primary_email: str,
    mail_password: str,
    client_id: str,
    refresh_token: str,
) -> str:
    """Serialize one mailbox into the same four-segment text format used by import."""
    return f"{primary_email}----{mail_password}----{client_id}----{refresh_token}"


def load_mailboxes_by_ids(session: Session, mailbox_ids: list[str]) -> tuple[list[Mailbox], list[str]]:
    """Load mailboxes for the requested IDs, preserving request order and reporting missing IDs."""
    if not mailbox_ids:
        return [], []

    mailboxes = list(session.scalars(select(Mailbox).where(Mailbox.id.in_(mailbox_ids))).all())
    mailbox_by_id = {mailbox.id: mailbox for mailbox in mailboxes}
    ordered_mailboxes = [mailbox_by_id[mailbox_id] for mailbox_id in mailbox_ids if mailbox_id in mailbox_by_id]
    missing_mailbox_ids = [mailbox_id for mailbox_id in mailbox_ids if mailbox_id not in mailbox_by_id]
    return ordered_mailboxes, missing_mailbox_ids


@app.post("/api/v1/admin/mailboxes/export")
def export_mailboxes(
    payload: MailboxBatchIdsRequest,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> PlainTextResponse:
    """Export selected mailbox credentials using the import four-segment text format."""
    cipher = get_credential_cipher(settings)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )

    mailboxes, missing_mailbox_ids = load_mailboxes_by_ids(session, payload.mailbox_ids)
    if missing_mailbox_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "MAILBOX_NOT_FOUND",
                "message": f"有 {len(missing_mailbox_ids)} 个邮箱不存在，无法导出",
                "missing_mailbox_ids": missing_mailbox_ids,
            },
        )

    incomplete_mailbox_emails: list[str] = []
    export_lines: list[str] = []
    for mailbox in mailboxes:
        if (
            not mailbox.primary_email
            or not mailbox.client_id
            or not mailbox.mail_password_ciphertext
            or not mailbox.refresh_token_ciphertext
        ):
            incomplete_mailbox_emails.append(mailbox.primary_email)
            continue
        try:
            mail_password = cipher.decrypt(mailbox.mail_password_ciphertext)
            refresh_token = cipher.decrypt(mailbox.refresh_token_ciphertext)
        except Exception as error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": "MAILBOX_CREDENTIAL_DECRYPT_FAILED",
                    "message": f"邮箱 {mailbox.primary_email} 凭证解密失败：{summarize_exception(error)}",
                },
            ) from error
        if not mail_password or not refresh_token:
            incomplete_mailbox_emails.append(mailbox.primary_email)
            continue
        export_lines.append(
            format_mailbox_import_line(
                mailbox.primary_email,
                mail_password,
                mailbox.client_id,
                refresh_token,
            )
        )

    if incomplete_mailbox_emails:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "MAILBOX_CREDENTIALS_INCOMPLETE",
                "message": f"有 {len(incomplete_mailbox_emails)} 个邮箱缺少可导出凭证，无法生成完整导入格式",
                "incomplete_primary_emails": incomplete_mailbox_emails,
            },
        )

    create_audit_log(
        session,
        admin_id,
        "mailbox.exported",
        "mailbox",
        None,
        {"exported": len(export_lines), "mailbox_ids": payload.mailbox_ids},
    )
    export_content = "\n".join(export_lines)
    if export_content:
        export_content += "\n"
    return PlainTextResponse(
        content=export_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="mailboxes-export.txt"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/v1/admin/mailboxes/delete", response_model=MailboxBatchDeleteResponse)
def delete_mailboxes(
    payload: MailboxBatchIdsRequest,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> MailboxBatchDeleteResponse:
    """Delete selected mailboxes; active claims block unless force_release_active_leases."""
    admin_service = MailboxAdminService(session)
    try:
        result = admin_service.delete_mailboxes_by_ids(
            payload.mailbox_ids,
            admin_id=admin_id,
            force_release_active_leases=payload.force_release_active_leases,
        )
    except ActiveLeaseClaimConflictError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "ACTIVE_LEASE_CLAIM",
                "message": "存在活跃租约 claim，默认拒绝删除；可 force_release_active_leases=true",
                "mailbox_ids": error.mailbox_ids,
            },
        ) from error
    return MailboxBatchDeleteResponse(
        deleted=result.deleted,
        deleted_mailbox_ids=result.deleted_mailbox_ids,
        missing_mailbox_ids=result.missing_mailbox_ids,
    )


@app.post("/api/v1/admin/mailboxes/{mailbox_id}/access-token", response_model=MailboxAccessTokenResponse)
def get_mailbox_access_token(
    mailbox_id: str,
    access_token_service: AccessTokenServiceDependency,
    _: AdminDependency,
) -> MailboxAccessTokenResponse:
    """Return a usable AT, refreshing only when the encrypted cache is stale."""
    try:
        result = access_token_service.ensure_access_token(mailbox_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "MAILBOX_NOT_FOUND", "message": str(error)},
        ) from error
    except MicrosoftInvalidGrantError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "MICROSOFT_REFRESH_TOKEN_INVALID", "message": str(error)},
        ) from error
    except MicrosoftOAuthError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "MICROSOFT_TOKEN_REFRESH_FAILED", "message": str(error)},
        ) from error
    return MailboxAccessTokenResponse(
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        access_token=result.access_token,
        expires_at=result.expires_at,
        token_version=result.token_version,
        refreshed=result.refreshed,
        refresh_token_rotated=result.refresh_token_rotated,
    )


@app.post("/api/v1/admin/mailboxes/access-tokens/refresh", response_model=MailboxAccessTokenRefreshResponse)
def refresh_mailbox_access_tokens(
    payload: MailboxAccessTokenRefreshRequest,
    access_token_service: AccessTokenServiceDependency,
    _: AdminDependency,
) -> MailboxAccessTokenRefreshResponse:
    """Refresh selected or all mailbox RT/AT data without exposing token values."""
    result = access_token_service.refresh_access_tokens(payload.mailbox_ids)
    return MailboxAccessTokenRefreshResponse(
        successful=result.successful,
        failed=result.failed,
        results=[
            {
                "mailbox_id": item.mailbox_id,
                "primary_email": item.primary_email,
                "successful": item.successful,
                "refreshed": item.refreshed,
                "refresh_token_rotated": item.refresh_token_rotated,
                "access_token_expires_at": item.access_token_expires_at,
                "error_summary": item.error_summary,
            }
            for item in result.results
        ],
    )


@app.post(
    "/api/v1/admin/mailboxes/access-tokens/refresh-unprobed",
    response_model=MailboxUnprobedRefreshResponse,
)
def refresh_unprobed_mailbox_access_tokens(
    payload: MailboxUnprobedRefreshRequest,
    access_token_service: AccessTokenServiceDependency,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> MailboxUnprobedRefreshResponse:
    """Force-refresh one batch of unprobed/unknown mailboxes to classify usable vs invalid RT."""
    result = access_token_service.refresh_unprobed_or_unknown_access_tokens(batch_size=payload.batch_size)
    failure_reason_counts: dict[str, int] = {}
    for item in result.results:
        if item.successful:
            continue
        reason = (item.error_summary or "").strip() or "识别失败（无 error_summary）"
        failure_reason_counts[reason] = failure_reason_counts.get(reason, 0) + 1
    top_failure_reasons = sorted(
        failure_reason_counts.items(),
        key=lambda pair: pair[1],
        reverse=True,
    )[:10]
    create_audit_log(
        session,
        admin_id,
        "mailbox.unprobed_refreshed",
        "mailbox",
        None,
        {
            "candidate_total": result.candidate_total,
            "processed": result.processed,
            "successful": result.successful,
            "failed": result.failed,
            "remaining_candidates": result.remaining_candidates,
            "batch_size": result.batch_size,
            "worker_count": result.worker_count,
            "top_failure_reasons": [
                {"reason": reason, "count": count} for reason, count in top_failure_reasons
            ],
        },
    )
    return MailboxUnprobedRefreshResponse(
        candidate_total=result.candidate_total,
        processed=result.processed,
        successful=result.successful,
        failed=result.failed,
        remaining_candidates=result.remaining_candidates,
        batch_size=result.batch_size,
        worker_count=result.worker_count,
        results=[
            {
                "mailbox_id": item.mailbox_id,
                "primary_email": item.primary_email,
                "successful": item.successful,
                "refreshed": item.refreshed,
                "refresh_token_rotated": item.refresh_token_rotated,
                "access_token_expires_at": item.access_token_expires_at,
                "error_summary": item.error_summary,
            }
            for item in result.results
        ],
    )


def _is_mysql_lock_wait_timeout(error: Exception) -> bool:
    """Return whether the failure is MySQL 1205 lock wait timeout (or a nested cause)."""
    current_error: BaseException | None = error
    while current_error is not None:
        if isinstance(current_error, OperationalError):
            original_error = getattr(current_error, "orig", None)
            if original_error is not None and getattr(original_error, "args", None):
                if original_error.args and original_error.args[0] == 1205:
                    return True
            if "1205" in str(current_error) and "Lock wait timeout" in str(current_error):
                return True
        current_error = current_error.__cause__ or current_error.__context__
    return False


@app.post("/api/v1/admin/mailboxes/delete-invalid", response_model=MailboxDeleteInvalidResponse)
def delete_invalid_mailboxes(
    session: SessionDependency,
    admin_id: AdminDependency,
    force_release_active_leases: bool = Query(default=False),
) -> MailboxDeleteInvalidResponse:
    """Delete invalid mailboxes in SKIP LOCKED chunks with per-chunk durable audit."""
    admin_service = MailboxAdminService(session)
    try:
        result = admin_service.delete_invalid_mailboxes_in_chunks(
            admin_id=admin_id,
            batch_size=25,
            force_release_active_leases=force_release_active_leases,
        )
        session.commit()
    except ActiveLeaseClaimConflictError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "ACTIVE_LEASE_CLAIM",
                "message": "存在活跃租约 claim，默认拒绝删除；可 force_release_active_leases=true",
                "mailbox_ids": error.mailbox_ids,
            },
        ) from error
    except OperationalError as error:
        session.rollback()
        if _is_mysql_lock_wait_timeout(error):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "MAILBOX_DELETE_LOCK_TIMEOUT",
                    "message": "删除失效邮箱时等待数据库锁超时，请稍后重试。",
                },
            ) from error
        raise
    return MailboxDeleteInvalidResponse(
        deleted=result.deleted,
        deleted_mailbox_ids=result.deleted_mailbox_ids,
        deleted_primary_emails=result.deleted_primary_emails,
    )


def serialize_usage_site_item(
    site,
    *,
    active_usage_count: int | None = None,
) -> UsageSiteItemResponse:
    """Serialize a UsageSite ORM row for admin and external list responses."""
    return UsageSiteItemResponse(
        code=site.code,
        display_name=site.display_name,
        enabled=site.enabled,
        created_at=site.created_at,
        active_usage_count=active_usage_count,
    )


@app.get("/api/v1/admin/usage-sites", response_model=UsageSiteListResponse)
def admin_list_usage_sites(
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
    include_disabled: bool = Query(default=True, description="是否包含已禁用站点。"),
) -> UsageSiteListResponse:
    """List registration-site whitelist entries for operators."""
    sites = lease_service.list_usage_sites_for_admin(include_disabled=include_disabled)
    return UsageSiteListResponse(
        items=[
            serialize_usage_site_item(
                site,
                active_usage_count=lease_service.count_active_email_site_usages(site.code),
            )
            for site in sites
        ]
    )


@app.post(
    "/api/v1/admin/usage-sites",
    response_model=UsageSiteItemResponse,
    status_code=status.HTTP_201_CREATED,
)
def admin_create_usage_site(
    payload: UsageSiteCreateRequest,
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
) -> UsageSiteItemResponse:
    """Create a new registration-site whitelist entry."""
    try:
        site = lease_service.create_usage_site(
            code=payload.code,
            display_name=payload.display_name,
            enabled=payload.enabled,
        )
    except UsageSiteConflictError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "USAGE_SITE_ALREADY_EXISTS", "message": str(error)},
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_REQUEST", "message": str(error)},
        ) from error
    return serialize_usage_site_item(site)


@app.patch("/api/v1/admin/usage-sites/{code}", response_model=UsageSiteItemResponse)
def admin_update_usage_site(
    code: str,
    payload: UsageSiteUpdateRequest,
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
) -> UsageSiteItemResponse:
    """Update display name and/or enabled flag for a whitelist site."""
    try:
        site = lease_service.update_usage_site(
            code,
            display_name=payload.display_name,
            enabled=payload.enabled,
        )
    except UsageSiteNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "USAGE_SITE_NOT_FOUND", "message": str(error)},
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_REQUEST", "message": str(error)},
        ) from error
    return serialize_usage_site_item(
        site,
        active_usage_count=lease_service.count_active_email_site_usages(site.code),
    )


@app.delete("/api/v1/admin/usage-sites/{code}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_usage_site(
    code: str,
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
) -> Response:
    """Delete a whitelist site when it has no active occupancy."""
    try:
        lease_service.delete_usage_site(code)
    except UsageSiteNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "USAGE_SITE_NOT_FOUND", "message": str(error)},
        ) from error
    except UsageSiteInUseError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "USAGE_SITE_IN_USE", "message": str(error)},
        ) from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/v1/admin/email-site-usages", response_model=EmailSiteUsageListResponse)
def admin_list_email_site_usages(
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    allocated_email: str | None = Query(default=None, description="按完整业务地址精确筛选。"),
    usage_site: str | None = Query(default=None, description="按站点 code 筛选。"),
    include_revoked: bool = Query(default=True, description="是否包含已撤销记录。"),
) -> EmailSiteUsageListResponse:
    """Page through email/site occupancy for operational troubleshooting."""
    items, total_count = lease_service.list_email_site_usages(
        allocated_email=allocated_email,
        usage_site=usage_site,
        include_revoked=include_revoked,
        page=page,
        page_size=page_size,
    )
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    return EmailSiteUsageListResponse(
        total=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=[
            EmailSiteUsageItemResponse(
                id=item.id,
                allocated_email=item.allocated_email,
                usage_site=item.usage_site_code,
                mailbox_id=item.mailbox_id,
                lease_id=item.lease_id,
                client_key_id=item.client_key_id,
                created_at=item.created_at,
                revoked_at=item.revoked_at,
                updated_at=item.updated_at,
            )
            for item in items
        ],
    )


@app.post(
    "/api/v1/admin/email-site-usages/{usage_id}/revoke",
    response_model=EmailSiteUsageRevokeResponse,
)
def admin_revoke_email_site_usage(
    usage_id: str,
    lease_service: LeaseServiceDependency,
    _: AdminDependency,
) -> EmailSiteUsageRevokeResponse:
    """Soft-revoke an occupancy row so the address can be registered again."""
    try:
        usage = lease_service.revoke_email_site_usage(usage_id)
    except LeaseNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EMAIL_SITE_USAGE_NOT_FOUND", "message": str(error)},
        ) from error
    assert usage.revoked_at is not None
    return EmailSiteUsageRevokeResponse(
        id=usage.id,
        allocated_email=usage.allocated_email,
        usage_site=usage.usage_site_code,
        revoked_at=usage.revoked_at,
    )


@app.get("/api/v1/admin/leases", response_model=LeaseListResponse)
def list_leases(
    session: SessionDependency,
    _: AdminDependency,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> LeaseListResponse:
    """List mailbox leases page by page for operational review."""
    total_lease_count = session.scalar(select(func.count(Lease.id))) or 0
    total_pages = max(1, (total_lease_count + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    rows = session.execute(
        select(Lease, Mailbox.primary_email)
        .join(Mailbox, Lease.mailbox_id == Mailbox.id)
        .order_by(Lease.created_at.desc())
        .offset(offset)
        .limit(page_size)
    ).all()
    response_items: list[LeaseListItemResponse] = []
    for lease, primary_email in rows:
        if lease.released_at is not None:
            lease_status = "released"
        elif is_expired(lease.expires_at):
            lease_status = "expired"
        else:
            lease_status = "active"
        response_items.append(
            LeaseListItemResponse(
                id=lease.id,
                mailbox_id=lease.mailbox_id,
                primary_email=primary_email,
                allocated_email=lease.allocated_email,
                client_key_id=lease.client_key_id,
                client_tag=lease.client_tag,
                purpose=lease.purpose,
                mode=lease.mode,
                status=lease_status,
                expires_at=lease.expires_at,
                released_at=lease.released_at,
                created_at=lease.created_at,
            )
        )
    return LeaseListResponse(
        total=total_lease_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=response_items,
    )


@app.get("/api/v1/admin/egress-proxies", response_model=list[EgressProxyResponse])
def list_egress_proxies(
    session: SessionDependency,
    _: AdminDependency,
) -> list[EgressProxyResponse]:
    """List proxies without returning proxy authentication material."""
    bound_mailbox_count = (
        select(func.count(Mailbox.id))
        .where(Mailbox.egress_proxy_id == EgressProxy.id)
        .correlate(EgressProxy)
        .scalar_subquery()
    )
    results = session.execute(
        select(EgressProxy, bound_mailbox_count.label("bound_mailbox_count"))
        .order_by(EgressProxy.priority.asc(), EgressProxy.name.asc())
    ).all()
    return [serialize_proxy(proxy, count) for proxy, count in results]


@app.post(
    "/api/v1/admin/egress-proxies",
    response_model=EgressProxyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_egress_proxy(
    payload: EgressProxyCreate,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> EgressProxyResponse:
    """Register an egress proxy and encrypt any supplied authentication material."""
    cipher = get_credential_cipher(settings)
    # Empty strings mean "not provided" so copy dialogs can leave fields blank.
    provided_username = _normalize_optional_proxy_secret(payload.username)
    provided_password = _normalize_optional_proxy_secret(payload.password)
    source_username: str | None = None
    source_password: str | None = None

    if payload.copy_credentials_from_proxy_id:
        source_proxy = get_proxy_or_404(session, payload.copy_credentials_from_proxy_id)
        if cipher is None and (
            source_proxy.username_ciphertext is not None or source_proxy.password_ciphertext is not None
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED",
                    "message": "未配置凭证加密密钥，无法从源代理复制认证凭证",
                },
            )
        try:
            source_username, source_password = read_proxy_plaintext_credentials(source_proxy, cipher)
        except Exception as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "EGRESS_PROXY_CREDENTIAL_COPY_FAILED",
                    "message": "无法解密源代理认证凭证，请手动填写用户名和密码",
                },
            ) from error

    # Prefer explicit form values; otherwise fall back to decrypted source secrets.
    final_username = provided_username if provided_username is not None else source_username
    final_password = provided_password if provided_password is not None else source_password
    needs_encryption = final_username is not None or final_password is not None
    if needs_encryption and cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )

    # Always encrypt plaintext once. Never store ciphertext copied from another row
    # without decrypt, so we never double-encrypt or persist unusable blobs.
    username_ciphertext = (
        cipher.encrypt(final_username) if final_username is not None and cipher is not None else None
    )
    password_ciphertext = (
        cipher.encrypt(final_password) if final_password is not None and cipher is not None else None
    )
    credential_fingerprint = resolve_proxy_credential_fingerprint(
        final_username,
        final_password,
        cipher,
    )

    proxy = EgressProxy(
        name=payload.name,
        protocol=payload.protocol,
        host=payload.host,
        port=payload.port,
        username_ciphertext=username_ciphertext,
        password_ciphertext=password_ciphertext,
        credential_fingerprint=credential_fingerprint,
        enabled=payload.enabled,
        priority=payload.priority,
    )
    session.add(proxy)
    try:
        session.flush()
    except IntegrityError as error:
        session.rollback()
        raise_for_egress_proxy_integrity_error(error)
    create_audit_log(
        session,
        admin_id,
        "egress_proxy.created",
        "egress_proxy",
        proxy.id,
        {"host_preview": redact_proxy_host(proxy.host), "protocol": proxy.protocol.value, "port": proxy.port},
    )
    return serialize_proxy(proxy)


@app.get("/api/v1/admin/egress-proxies/{proxy_id}", response_model=EgressProxyResponse)
def get_egress_proxy(
    proxy_id: str,
    session: SessionDependency,
    _: AdminDependency,
) -> EgressProxyResponse:
    """Retrieve safe details for one proxy."""
    proxy = get_proxy_or_404(session, proxy_id)
    bound_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.egress_proxy_id == proxy.id)
    )
    return serialize_proxy(proxy, bound_mailbox_count or 0)


@app.patch("/api/v1/admin/egress-proxies/{proxy_id}", response_model=EgressProxyResponse)
def update_egress_proxy(
    proxy_id: str,
    payload: EgressProxyUpdate,
    session: SessionDependency,
    settings: SettingsDependency,
    admin_id: AdminDependency,
) -> EgressProxyResponse:
    """Update proxy metadata without ever reading credentials back to the client."""
    proxy = get_proxy_or_404(session, proxy_id)
    cipher = get_credential_cipher(settings)
    written_fields = payload.model_fields_set
    if ({"username", "password"} & written_fields) and cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )

    for field_name in ("name", "protocol", "host", "port", "enabled", "priority"):
        value = getattr(payload, field_name)
        if value is not None:
            setattr(proxy, field_name, value)
    if "username" in written_fields:
        proxy.username_ciphertext = cipher.encrypt(payload.username) if payload.username and cipher else None
    if "password" in written_fields:
        proxy.password_ciphertext = cipher.encrypt(payload.password) if payload.password and cipher else None

    current_username, current_password = read_proxy_plaintext_credentials(proxy, cipher)
    if "username" in written_fields:
        current_username = payload.username
    if "password" in written_fields:
        current_password = payload.password
    if {"username", "password", "protocol", "host", "port"} & written_fields or not proxy.credential_fingerprint:
        proxy.credential_fingerprint = resolve_proxy_credential_fingerprint(
            current_username,
            current_password,
            cipher,
        )
    try:
        session.flush()
    except IntegrityError as error:
        session.rollback()
        raise_for_egress_proxy_integrity_error(error)
    create_audit_log(
        session,
        admin_id,
        "egress_proxy.updated",
        "egress_proxy",
        proxy.id,
        {"updated_fields": sorted(written_fields)},
    )
    return serialize_proxy(proxy)


def count_bound_mailboxes(session: Session, proxy_id: str) -> int:
    """Return how many mailboxes currently stick to one egress proxy."""
    return session.scalar(select(func.count(Mailbox.id)).where(Mailbox.egress_proxy_id == proxy_id)) or 0


@app.post("/api/v1/admin/egress-proxies/{proxy_id}/enable", response_model=EgressProxyResponse)
def enable_egress_proxy(
    proxy_id: str,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> EgressProxyResponse:
    """Enable a proxy while preserving its existing mailbox bindings."""
    proxy = get_proxy_or_404(session, proxy_id)
    proxy.enabled = True
    create_audit_log(session, admin_id, "egress_proxy.enabled", "egress_proxy", proxy.id, {})
    # Commit before the response leaves so a follow-up list request cannot read stale enabled state.
    session.commit()
    session.refresh(proxy)
    return serialize_proxy(proxy, count_bound_mailboxes(session, proxy.id))


@app.post("/api/v1/admin/egress-proxies/{proxy_id}/disable", response_model=EgressProxyResponse)
def disable_egress_proxy(
    proxy_id: str,
    session: SessionDependency,
    admin_id: AdminDependency,
) -> EgressProxyResponse:
    """Disable a proxy; bound mailboxes reselect on their next external operation."""
    proxy = get_proxy_or_404(session, proxy_id)
    proxy.enabled = False
    create_audit_log(session, admin_id, "egress_proxy.disabled", "egress_proxy", proxy.id, {})
    session.commit()
    session.refresh(proxy)
    return serialize_proxy(proxy, count_bound_mailboxes(session, proxy.id))


@app.post(
    "/api/v1/admin/egress-proxies/{proxy_id}/recover",
    response_model=EgressProxyResponse,
)
def recover_egress_proxy(
    proxy_id: str,
    session: SessionDependency,
    proxy_service: ProxyServiceDependency,
    _: AdminDependency,
) -> EgressProxyResponse:
    """Clear a cooldown after a deliberate administrative recovery decision."""
    try:
        proxy = proxy_service.recover_proxy(proxy_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EGRESS_PROXY_NOT_FOUND", "message": str(error)},
        ) from error
    session.commit()
    session.refresh(proxy)
    return serialize_proxy(proxy, count_bound_mailboxes(session, proxy.id))


@app.post(
    "/api/v1/admin/egress-proxies/{proxy_id}/test",
    response_model=ProxyConnectivityTestResponse,
)
def test_egress_proxy(
    proxy_id: str,
    proxy_service: ProxyServiceDependency,
    _: AdminDependency,
) -> ProxyConnectivityTestResponse:
    """Test only a proxy handshake and never return upstream response content."""
    try:
        proxy_service.test_proxy_connectivity(proxy_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EGRESS_PROXY_NOT_FOUND", "message": str(error)},
        ) from error
    except EgressProxyTransportError as error:
        proxy_service.record_proxy_failure(proxy_id, error)
        return ProxyConnectivityTestResponse(
            successful=False,
            error_code="PROXY_CONNECTIVITY_TEST_FAILED",
            error_summary=str(error) or "代理连接测试失败。",
        )
    except Exception as error:
        return ProxyConnectivityTestResponse(
            successful=False,
            error_code="PROXY_CONNECTIVITY_TEST_UNAVAILABLE",
            error_summary=summarize_exception(error),
        )
    return ProxyConnectivityTestResponse(successful=True)


@app.get(
    "/api/v1/admin/egress-proxies/{proxy_id}/mailboxes",
    response_model=list[ProxyBoundMailboxResponse],
)
def list_proxy_bound_mailboxes(
    proxy_id: str,
    session: SessionDependency,
    _: AdminDependency,
) -> list[ProxyBoundMailboxResponse]:
    """Show affected mailboxes without exposing their credentials."""
    get_proxy_or_404(session, proxy_id)
    mailboxes = session.scalars(
        select(Mailbox)
        .where(Mailbox.egress_proxy_id == proxy_id)
        .order_by(Mailbox.primary_email.asc())
    ).all()
    return [
        ProxyBoundMailboxResponse(
            id=mailbox.id,
            primary_email=mailbox.primary_email,
            status=mailbox.status.value,
            proxy_bound_at=mailbox.proxy_bound_at,
            proxy_last_switch_at=mailbox.proxy_last_switch_at,
        )
        for mailbox in mailboxes
    ]


@app.delete("/api/v1/admin/egress-proxies/{proxy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_egress_proxy(
    proxy_id: str,
    session: SessionDependency,
    admin_id: AdminDependency,
    force: bool = Query(default=False),
) -> Response:
    """Delete an unused proxy, or explicitly unbind mailboxes before force deletion."""
    proxy = get_proxy_or_404(session, proxy_id)
    affected_mailboxes = session.scalars(
        select(Mailbox).where(Mailbox.egress_proxy_id == proxy_id).with_for_update()
    ).all()
    if affected_mailboxes and not force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "EGRESS_PROXY_HAS_BOUND_MAILBOXES",
                "message": "出口代理仍有绑定邮箱；请确认后使用 force 删除",
            },
        )
    for mailbox in affected_mailboxes:
        mailbox.egress_proxy_id = None
        mailbox.proxy_bound_at = None
        mailbox.proxy_last_switch_at = utc_now()
    create_audit_log(
        session,
        admin_id,
        "egress_proxy.deleted",
        "egress_proxy",
        proxy.id,
        {"unbound_mailbox_count": len(affected_mailboxes)},
    )
    session.delete(proxy)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/v1/admin/egress-proxy-policy", response_model=ProxyPolicyResponse)
def get_proxy_policy(
    proxy_service: ProxyServiceDependency,
    _: AdminDependency,
) -> ProxyPolicyResponse:
    """Read the global routing policy used by OAuth and IMAP transports."""
    return serialize_policy(proxy_service.ensure_policy())


@app.patch("/api/v1/admin/egress-proxy-policy", response_model=ProxyPolicyResponse)
def update_proxy_policy(
    payload: ProxyPolicyUpdate,
    session: SessionDependency,
    proxy_service: ProxyServiceDependency,
    admin_id: AdminDependency,
) -> ProxyPolicyResponse:
    """Persist global proxy policy changes and audit only non-sensitive fields."""
    policy = proxy_service.ensure_policy()
    changed_fields = payload.model_fields_set
    for field_name in changed_fields:
        value = getattr(payload, field_name)
        if field_name == "allowed_protocols" and value is not None:
            value = [protocol.value for protocol in value]
        setattr(policy, field_name, value)
    create_audit_log(
        session,
        admin_id,
        "egress_proxy.policy_updated",
        "egress_proxy_policy",
        "1",
        {"updated_fields": sorted(changed_fields)},
    )
    return serialize_policy(policy)


@app.put("/api/v1/admin/mailboxes/{mailbox_id}/egress-proxy", status_code=status.HTTP_204_NO_CONTENT)
def update_mailbox_proxy_binding(
    mailbox_id: str,
    payload: ProxyBindingUpdate,
    proxy_service: ProxyServiceDependency,
    _: AdminDependency,
) -> Response:
    """Manually bind a mailbox to a healthy proxy or request direct routing."""
    try:
        proxy_service.bind_mailbox_to_proxy(mailbox_id, payload.egress_proxy_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "RESOURCE_NOT_FOUND", "message": str(error)},
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "EGRESS_PROXY_UNAVAILABLE", "message": str(error)},
        ) from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/v1/admin/dashboard/proxies")
def get_proxy_dashboard(
    session: SessionDependency,
    _: AdminDependency,
) -> dict[str, int]:
    """Return compact proxy health metrics for the admin Dashboard."""
    total_proxy_count = session.scalar(select(func.count(EgressProxy.id))) or 0
    enabled_proxy_count = session.scalar(
        select(func.count(EgressProxy.id)).where(EgressProxy.enabled.is_(True))
    ) or 0
    cooldown_proxy_count = session.scalar(
        select(func.count(EgressProxy.id)).where(EgressProxy.status == EgressProxyStatus.COOLDOWN)
    ) or 0
    bound_mailbox_count = session.scalar(
        select(func.count(Mailbox.id)).where(Mailbox.egress_proxy_id.is_not(None))
    ) or 0
    return {
        "total_proxy_count": total_proxy_count,
        "enabled_proxy_count": enabled_proxy_count,
        "cooldown_proxy_count": cooldown_proxy_count,
        "bound_mailbox_count": bound_mailbox_count,
    }


@app.exception_handler(NoHealthyEgressProxyError)
def handle_no_healthy_egress_proxy(
    _: Any,
    error: NoHealthyEgressProxyError,
) -> JSONResponse:
    """Expose the required stable error code without operational internals."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": {"code": error.error_code, "message": "没有可用的全局出口代理"}},
    )


def _resolve_frontend_dist_directory() -> Path | None:
    """Locate baked-in admin SPA assets (Docker image) or a local frontend/dist build."""
    candidate_directories = (
        Path(__file__).resolve().parent.parent / "frontend_dist",
        Path(__file__).resolve().parent.parent / "frontend" / "dist",
    )
    for directory in candidate_directories:
        if (directory / "index.html").is_file():
            return directory
    return None


FRONTEND_DIST_DIRECTORY = _resolve_frontend_dist_directory()
if FRONTEND_DIST_DIRECTORY is not None:
    frontend_assets_directory = FRONTEND_DIST_DIRECTORY / "assets"
    if frontend_assets_directory.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=frontend_assets_directory),
            name="frontend-assets",
        )

    @app.get("/", include_in_schema=False)
    def get_admin_spa_index() -> FileResponse:
        """Serve the React admin console when static assets are packaged with the service."""
        return FileResponse(FRONTEND_DIST_DIRECTORY / "index.html")

    @app.get("/{spa_path:path}", include_in_schema=False)
    def get_admin_spa_fallback(spa_path: str) -> FileResponse:
        """SPA fallback for client-side routes; API routes registered above take precedence."""
        if spa_path.startswith("api/") or spa_path in {
            "health",
            "docs",
            "redoc",
            "openapi.json",
            "openapi-viewer",
        }:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        candidate_file = FRONTEND_DIST_DIRECTORY / spa_path
        if spa_path and candidate_file.is_file():
            return FileResponse(candidate_file)
        return FileResponse(FRONTEND_DIST_DIRECTORY / "index.html")
