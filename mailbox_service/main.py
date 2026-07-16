"""FastAPI application exposing the global egress proxy administration API."""

from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import APIKeyHeader
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mailbox_service.config import Settings, get_settings
from mailbox_service.client_key_service import (
    ClientKeyAuthenticationError,
    ClientKeyService,
    ClientKeyScopeError,
    ClientPrincipal,
)
from mailbox_service.database import get_session
from mailbox_service.lease_service import (
    LeaseInactiveError,
    LeaseModeError,
    LeaseNotFoundError,
    LeaseService,
    LeaseUnavailableError,
    TokenVersionConflictError,
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
    MailboxAcquireRequest,
    MailboxAcquireResponse,
    MailboxAccessTokenRefreshRequest,
    MailboxAccessTokenRefreshResponse,
    MailboxAccessTokenResponse,
    MailboxImportLineError,
    MailboxImportRequest,
    MailboxImportResponse,
    MailboxListItemResponse,
    MailboxListResponse,
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
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.proxy_service import (
    MicrosoftIMAPClient,
    MicrosoftOAuthClient,
    MicrosoftInvalidGrantError,
    MicrosoftOAuthError,
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
    {"name": "Client Key 管理", "description": "外部调用方 Client API Key 的创建、查询和停用。"},
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
        "领取一个 status=active 的邮箱并创建 mail_read 租约；"
        "可选择生成 plus alias 作为 allocated_email，只返回邮箱地址与租约信息，不返回 Token。",
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
    "MailboxAccessTokenRefreshItemResponse": "单个邮箱的 Token 刷新结果。",
    "MailboxAccessTokenRefreshRequest": "批量刷新请求；邮箱 ID 为空时刷新全部可用邮箱。",
    "MailboxAccessTokenRefreshResponse": "批量刷新汇总响应，不返回 Token 明文。",
    "MailboxAccessTokenResponse": "受保护接口返回的可用 Access Token。",
    "MailboxImportLineError": "邮箱导入内容中的单行错误。",
    "MailboxImportRequest": "四段文本格式的邮箱批量导入请求。",
    "MailboxImportResponse": "邮箱批量导入结果汇总。",
    "MailboxListItemResponse": "邮箱管理列表项，不包含敏感凭证明文。",
    "MailboxListResponse": "邮箱分页查询响应。",
    "MailboxStatus": "邮箱健康状态，与当前是否存在租约相互独立。",
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
    """Run process-local background jobs for the selected single instance."""
    settings = get_settings()
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
async def prevent_api_response_caching(request: Request, call_next):
    """Prevent all API success and error responses from being retained by caches."""
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
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


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
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
    proxy_service: ProxyServiceDependency,
) -> MailboxAccessTokenService:
    """Provide request-local AT cache services backed by encrypted storage."""
    cipher = get_credential_cipher(settings)
    if cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )
    capability_prober = MailboxCapabilityProbeService(
        settings,
        MicrosoftIMAPClient(proxy_service, settings),
        MicrosoftGraphMailProbeClient(proxy_service, settings),
    )
    return MailboxAccessTokenService(
        session,
        settings,
        cipher,
        MicrosoftOAuthClient(proxy_service, settings),
        capability_prober=capability_prober,
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
    return LeaseService(session, credential_cipher, access_token_service)


LeaseServiceDependency = Annotated[LeaseService, Depends(get_lease_service)]


def get_verification_code_service(
    settings: SettingsDependency,
    proxy_service: ProxyServiceDependency,
    access_token_service: AccessTokenServiceDependency,
) -> VerificationCodeService:
    """Provide request-local verification-code extraction with proxy-aware mail readers."""
    return VerificationCodeService(
        access_token_service,
        MicrosoftIMAPClient(proxy_service, settings),
        MicrosoftGraphMailReader(
            proxy_service,
            settings.proxy_connect_timeout_seconds,
            settings.proxy_read_timeout_seconds,
        ),
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
    if isinstance(error, ClientKeyScopeError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CLIENT_SCOPE_REQUIRED", "message": str(error)},
        )
    if isinstance(error, LeaseNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "LEASE_NOT_FOUND", "message": str(error)},
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
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "MICROSOFT_REFRESH_TOKEN_INVALID", "message": str(error)},
        )
    if isinstance(error, MicrosoftOAuthError):
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "MICROSOFT_TOKEN_REFRESH_FAILED", "message": str(error)},
        )
    if isinstance(error, VerificationCodeReadError):
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "MAILBOX_INBOX_READ_FAILED", "message": str(error)},
        )
    if isinstance(error, ValueError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_REQUEST", "message": str(error)},
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
) -> None:
    """Persist an Admin audit event after callers have already removed secret values."""
    session.add(
        AuditLog(
            actor_type="admin",
            actor_id=actor_id,
            event_type=event_type,
            target_type=target_type,
            target_id=target_id,
            metadata_json=metadata,
        )
    )


def serialize_proxy(proxy: EgressProxy, bound_mailbox_count: int = 0) -> EgressProxyResponse:
    """Build the only proxy response shape exposed by Admin APIs."""
    return EgressProxyResponse(
        id=proxy.id,
        name=proxy.name,
        protocol=proxy.protocol,
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
    """Return a side-effect-free readiness response for local deployment checks."""
    return {"status": "ok"}


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
        result = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=payload.lease_ttl_seconds,
            preferred_email=payload.preferred_email,
            client_tag=payload.client_tag,
            purpose=payload.purpose,
            use_plus_alias=payload.use_plus_alias,
            preferred_alias_suffix=payload.alias_suffix,
        )
    except Exception as error:
        raise to_external_http_exception(error) from error
    return MailboxAcquireResponse(
        lease_id=result.lease_id,
        mailbox_id=result.mailbox_id,
        primary_email=result.primary_email,
        allocated_email=result.allocated_email or result.primary_email,
        mode=LeaseMode.MAIL_READ,
        expires_at=result.expires_at,
        created_at=result.created_at,
    )


@app.post(
    "/api/v1/leases/{lease_id}/verification-code",
    response_model=LeaseVerificationCodeResponse,
)
def get_lease_verification_code(
    lease_id: str,
    payload: LeaseVerificationCodeRequest,
    principal: ClientPrincipalDependency,
    lease_service: LeaseServiceDependency,
    verification_code_service: VerificationCodeServiceDependency,
) -> LeaseVerificationCodeResponse:
    """Extract a verification code from recent inbox mail for an owned mail_read lease."""
    try:
        lease, mailbox = lease_service.load_active_mail_read_lease(principal, lease_id)
        # Prefer request override, then lease allocated alias/primary, then mailbox primary.
        default_recipient = lease.allocated_email or mailbox.primary_email
        lookup_result = verification_code_service.wait_for_verification_code(
            mailbox,
            VerificationCodeLookupOptions(
                timeout_seconds=payload.timeout_seconds,
                since_seconds=payload.since_seconds,
                poll_interval_seconds=payload.poll_interval_seconds,
                from_address=payload.from_address,
                subject_contains=payload.subject_contains,
                body_contains=payload.body_contains,
                code_regex=payload.code_regex,
                recipient=payload.recipient or default_recipient,
                require_recipient_match=payload.require_recipient_match,
            ),
        )
    except Exception as error:
        raise to_external_http_exception(error) from error
    return LeaseVerificationCodeResponse(
        lease_id=lease.id,
        mailbox_id=mailbox.id,
        primary_email=mailbox.primary_email,
        allocated_email=lease.allocated_email or mailbox.primary_email,
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
        result = lease_service.acquire_lease(
            principal,
            mode=LeaseMode(payload.mode),
            ttl_seconds=payload.lease_ttl_seconds,
            preferred_email=payload.preferred_email,
            client_tag=payload.client_tag,
            purpose=payload.purpose,
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
) -> LeaseReleaseResponse:
    """Idempotently release an active lease owned by the authenticated Client Key."""
    try:
        result = lease_service.release_lease(principal, lease_id)
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
        if existing_mailbox is not None and payload.on_conflict == "skip":
            skipped_count += 1
            continue
        if existing_mailbox is not None and payload.on_conflict == "error":
            errors.append(MailboxImportLineError(line_number=line_number, message="邮箱已存在。"))
            continue

        encrypted_mail_password = cipher.encrypt(mail_password)
        encrypted_refresh_token = cipher.encrypt(refresh_token)
        if existing_mailbox is None:
            session.add(
                Mailbox(
                    primary_email=primary_email,
                    status=MailboxStatus.ACTIVE,
                    client_id=client_id,
                    mail_password_ciphertext=encrypted_mail_password,
                    refresh_token_ciphertext=encrypted_refresh_token,
                )
            )
            created_count += 1
        else:
            existing_mailbox.status = MailboxStatus.ACTIVE
            existing_mailbox.client_id = client_id
            existing_mailbox.mail_password_ciphertext = encrypted_mail_password
            existing_mailbox.refresh_token_ciphertext = encrypted_refresh_token
            existing_mailbox.access_token_ciphertext = None
            existing_mailbox.access_token_expires_at = None
            existing_mailbox.access_token_refreshed_at = None
            existing_mailbox.scope = None
            existing_mailbox.capability = None
            existing_mailbox.capability_probed_at = None
            existing_mailbox.capability_probe_error = None
            existing_mailbox.token_version += 1
            existing_mailbox.updated_at = utc_now()
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
    if (payload.username is not None or payload.password is not None) and cipher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "CREDENTIAL_ENCRYPTION_NOT_CONFIGURED", "message": "未配置凭证加密密钥"},
        )

    proxy = EgressProxy(
        name=payload.name,
        protocol=payload.protocol,
        host=payload.host,
        port=payload.port,
        username_ciphertext=cipher.encrypt(payload.username) if payload.username is not None and cipher else None,
        password_ciphertext=cipher.encrypt(payload.password) if payload.password is not None and cipher else None,
        credential_fingerprint=resolve_proxy_credential_fingerprint(payload.username, payload.password, cipher),
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
            error_summary="代理连接测试失败。",
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
