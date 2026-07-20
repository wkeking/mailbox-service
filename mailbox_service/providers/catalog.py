"""Static catalog of supported mailbox providers and admin form field schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderFieldSchema:
    """One admin-configurable field for a provider instance."""

    key: str
    label: str
    field_type: str  # text | password | number | boolean | string_list | textarea
    required: bool = False
    secret: bool = False
    description: str = ""
    default: Any = None
    placeholder: str = ""


@dataclass(frozen=True)
class ProviderTypeDefinition:
    """Static description of one provider_type for catalog and settings validation."""

    provider_type: str
    display_name: str
    supply_mode: str  # inventory_import | inventory_replenish | on_demand
    supported_modes: tuple[str, ...]
    configurable_in_ui: bool
    requires_acquire_scope: bool
    notes: str = ""
    default_instance_id: str = "default"
    fields: tuple[ProviderFieldSchema, ...] = field(default_factory=tuple)
    primary_secret_key: str = "api_key"


def _secret(key: str, label: str, **kwargs: Any) -> ProviderFieldSchema:
    return ProviderFieldSchema(key=key, label=label, field_type="password", secret=True, **kwargs)


def _text(key: str, label: str, **kwargs: Any) -> ProviderFieldSchema:
    return ProviderFieldSchema(key=key, label=label, field_type="text", **kwargs)


def _list(key: str, label: str, **kwargs: Any) -> ProviderFieldSchema:
    return ProviderFieldSchema(key=key, label=label, field_type="string_list", **kwargs)


def _bool(key: str, label: str, **kwargs: Any) -> ProviderFieldSchema:
    return ProviderFieldSchema(key=key, label=label, field_type="boolean", **kwargs)


def _number(key: str, label: str, **kwargs: Any) -> ProviderFieldSchema:
    return ProviderFieldSchema(key=key, label=label, field_type="number", **kwargs)


PROVIDER_DEFINITIONS: tuple[ProviderTypeDefinition, ...] = (
    ProviderTypeDefinition(
        provider_type="microsoft",
        display_name="Microsoft Outlook / Hotmail",
        supply_mode="inventory_import",
        supported_modes=("access_token", "refresh_token", "mail_read"),
        configurable_in_ui=False,
        requires_acquire_scope=False,
        notes="通过四段文本导入维护；省略 provider 时默认领取。",
    ),
    ProviderTypeDefinition(
        provider_type="smsbower_gmail",
        display_name="SMSBower Gmail",
        supply_mode="inventory_replenish",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        notes="Admin 补货 + 显式 provider 领取。",
        fields=(
            _text("api_base", "API Base", default="https://smsbower.page/api/mail"),
            _secret("api_key", "API Key", required=True),
            _text("service", "Service", default="openai"),
            _text("domain", "Domain", default="gmail.com"),
            _number("max_price", "Max Price"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="cloudflare_temp_email",
        display_name="Cloudflare Temp Email",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        notes="领取时即时开箱；需要 admin 密码与域名。",
        primary_secret_key="admin_password",
        fields=(
            _text("api_base", "API Base", required=True),
            _secret("admin_password", "Admin Password", required=True),
            _list("domain", "域名列表", required=True, description="逗号或换行分隔"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="ddg_mail",
        display_name="DuckDuckGo + CF Reader",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        notes="DDG 生成 @duck.com 别名，经 Cloudflare 兼容收件箱读信。",
        primary_secret_key="ddg_token",
        fields=(
            _secret("ddg_token", "DDG Token", required=True),
            _text("api_base", "CF API Base", required=True),
            _secret("cf_inbox_jwt", "CF Inbox JWT"),
            _secret("admin_password", "CF Admin Password"),
            _secret("cf_api_key", "CF API Key"),
            _text("cf_auth_mode", "CF Auth Mode", default="none"),
            _list("cf_domain", "CF Domain 列表"),
            _text("cf_create_path", "Create Path", default="/api/new_address"),
            _text("cf_messages_path", "Messages Path", default="/api/mails"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="cloudmail_gen",
        display_name="CloudMail Gen",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        primary_secret_key="admin_password",
        fields=(
            _text("api_base", "API Base", required=True),
            _text("admin_email", "Admin Email", required=True),
            _secret("admin_password", "Admin Password", required=True),
            _list("domain", "域名列表", required=True),
            _list("subdomain", "子域列表"),
            _text("email_prefix", "邮箱前缀"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="tempmail_lol",
        display_name="TempMail.lol",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        fields=(
            _secret("api_key", "API Key"),
            _list("domain", "域名列表"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="duckmail",
        display_name="DuckMail",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        fields=(
            _secret("api_key", "API Key", required=True),
            _text("default_domain", "默认域名", default="duckmail.sbs"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="gptmail",
        display_name="GPTMail",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        fields=(
            _secret("api_key", "API Key", required=True),
            _text("default_domain", "默认域名"),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="moemail",
        display_name="MoeMail",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        fields=(
            _text("api_base", "API Base", required=True),
            _secret("api_key", "API Key", required=True),
            _list("domain", "域名列表"),
            _number("expiry_time", "过期时间", default=0),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="inbucket",
        display_name="Inbucket",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        notes="本地/自建 Inbucket；无密钥，按域名生成地址。",
        fields=(
            _text("api_base", "API Base", required=True),
            _list("domain", "域名列表", required=True),
            _bool("random_subdomain", "随机子域", default=True),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
    ProviderTypeDefinition(
        provider_type="yyds_mail",
        display_name="YYDS Mail",
        supply_mode="on_demand",
        supported_modes=("mail_read",),
        configurable_in_ui=True,
        requires_acquire_scope=True,
        fields=(
            _text("api_base", "API Base", default="https://maliapi.215.im/v1"),
            _secret("api_key", "API Key", required=True),
            _list("domain", "域名列表"),
            _text("subdomain", "子域"),
            _bool("wildcard", "Wildcard 账号", default=False),
            _number("request_timeout_seconds", "超时秒数", default=30),
        ),
    ),
)

PROVIDER_DEFINITION_BY_TYPE: dict[str, ProviderTypeDefinition] = {
    item.provider_type: item for item in PROVIDER_DEFINITIONS
}

ON_DEMAND_PROVIDER_TYPES = frozenset(
    item.provider_type for item in PROVIDER_DEFINITIONS if item.supply_mode == "on_demand"
)

INVENTORY_PROVIDER_TYPES = frozenset(
    item.provider_type
    for item in PROVIDER_DEFINITIONS
    if item.supply_mode in ("inventory_import", "inventory_replenish")
)

ALL_PROVIDER_TYPES = frozenset(item.provider_type for item in PROVIDER_DEFINITIONS)


def get_provider_definition(provider_type: str) -> ProviderTypeDefinition:
    definition = PROVIDER_DEFINITION_BY_TYPE.get(provider_type)
    if definition is None:
        raise KeyError(f"unknown provider: {provider_type}")
    return definition
