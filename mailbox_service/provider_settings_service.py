"""Load and update admin-editable Provider instance settings.

DB rows override environment defaults. API keys are encrypted at rest and never
returned in plaintext on read APIs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from mailbox_service.config import Settings
from mailbox_service.models import ProviderInstanceSettings, utc_now
from mailbox_service.providers.catalog import (
    PROVIDER_DEFINITIONS,
    ProviderTypeDefinition,
    get_provider_definition,
)
from mailbox_service.providers.ondemand_adapters import OnDemandRuntimeConfig
from mailbox_service.providers.smsbower_contracts import (
    SMSBOWER_DEFAULT_BASE_URL,
    SMSBOWER_DEFAULT_DOMAIN,
    SMSBOWER_DEFAULT_INSTANCE_ID,
    SMSBOWER_DEFAULT_SERVICE,
    SMSBOWER_PROVIDER_TYPE,
    normalize_smsbower_base_url,
)
from mailbox_service.security import CredentialCipher


@dataclass(frozen=True)
class SmsBowerRuntimeConfig:
    """Resolved SMSBower knobs used by transport (includes plaintext key for in-process use only)."""

    enabled: bool
    instance_id: str
    api_base: str
    api_key: str | None
    service: str
    domain: str
    max_price: float | None
    request_timeout_seconds: float
    has_api_key: bool
    source: str  # "database" | "environment" | "merged"


@dataclass(frozen=True)
class SmsBowerAdminView:
    """Admin-safe SMSBower settings (no secret plaintext)."""

    provider_type: str
    instance_id: str
    enabled: bool
    api_base: str
    service: str
    domain: str
    max_price: float | None
    request_timeout_seconds: float
    has_api_key: bool
    source: str
    env_enabled_default: bool
    updated_at: object | None = None


class ProviderSettingsService:
    """CRUD for provider_instance_settings with env fallback."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        credential_cipher: CredentialCipher | None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._credential_cipher = credential_cipher

    def get_smsbower_admin_view(self) -> SmsBowerAdminView:
        runtime = self.resolve_smsbower_runtime()
        row = self._get_smsbower_row()
        return SmsBowerAdminView(
            provider_type=SMSBOWER_PROVIDER_TYPE,
            instance_id=runtime.instance_id,
            enabled=runtime.enabled,
            api_base=runtime.api_base,
            service=runtime.service,
            domain=runtime.domain,
            max_price=runtime.max_price,
            request_timeout_seconds=runtime.request_timeout_seconds,
            has_api_key=runtime.has_api_key,
            source=runtime.source,
            env_enabled_default=bool(self._settings.smsbower_enabled),
            updated_at=row.updated_at if row is not None else None,
        )

    def resolve_smsbower_runtime(self) -> SmsBowerRuntimeConfig:
        """Merge DB overrides over env defaults; decrypt API key when present."""
        env_instance = (self._settings.smsbower_instance_id or SMSBOWER_DEFAULT_INSTANCE_ID).strip()
        row = self._get_smsbower_row(instance_id=env_instance)
        # Prefer DB instance_id when a row exists under default lookup.
        if row is None:
            row = self._session.get(
                ProviderInstanceSettings,
                (SMSBOWER_PROVIDER_TYPE, env_instance),
            )

        if row is None:
            api_key = (self._settings.smsbower_api_key or "").strip() or None
            return SmsBowerRuntimeConfig(
                enabled=bool(self._settings.smsbower_enabled),
                instance_id=env_instance,
                api_base=normalize_smsbower_base_url(self._settings.smsbower_api_base),
                api_key=api_key,
                service=(self._settings.smsbower_service or SMSBOWER_DEFAULT_SERVICE).strip(),
                domain=(self._settings.smsbower_domain or SMSBOWER_DEFAULT_DOMAIN).strip(),
                max_price=self._settings.smsbower_max_price,
                request_timeout_seconds=float(self._settings.smsbower_request_timeout_seconds),
                has_api_key=bool(api_key),
                source="environment",
            )

        api_key: str | None = None
        if row.api_key_ciphertext and self._credential_cipher is not None:
            try:
                api_key = self._credential_cipher.decrypt(row.api_key_ciphertext).strip() or None
            except Exception:
                api_key = None
        if not api_key:
            api_key = (self._settings.smsbower_api_key or "").strip() or None

        api_base = normalize_smsbower_base_url(
            row.api_base or self._settings.smsbower_api_base or SMSBOWER_DEFAULT_BASE_URL
        )
        service = (row.service_code or self._settings.smsbower_service or SMSBOWER_DEFAULT_SERVICE).strip()
        domain = (row.domain or self._settings.smsbower_domain or SMSBOWER_DEFAULT_DOMAIN).strip()
        max_price = row.max_price if row.max_price is not None else self._settings.smsbower_max_price
        timeout = float(row.request_timeout_seconds or self._settings.smsbower_request_timeout_seconds)

        return SmsBowerRuntimeConfig(
            enabled=bool(row.enabled),
            instance_id=(row.instance_id or env_instance).strip(),
            api_base=api_base,
            api_key=api_key,
            service=service,
            domain=domain,
            max_price=max_price,
            request_timeout_seconds=timeout,
            has_api_key=bool(api_key),
            source="database",
        )

    def update_smsbower(
        self,
        *,
        enabled: bool | None = None,
        api_base: str | None = None,
        service: str | None = None,
        domain: str | None = None,
        max_price: float | None = None,
        clear_max_price: bool = False,
        request_timeout_seconds: float | None = None,
        api_key: str | None = None,
        clear_api_key: bool = False,
    ) -> SmsBowerAdminView:
        """Upsert SMSBower settings. Omit api_key to keep existing; clear_api_key removes it."""
        instance_id = (self._settings.smsbower_instance_id or SMSBOWER_DEFAULT_INSTANCE_ID).strip()
        row = self._session.get(ProviderInstanceSettings, (SMSBOWER_PROVIDER_TYPE, instance_id))
        if row is None:
            # Seed from env so partial updates do not wipe other knobs.
            runtime = self.resolve_smsbower_runtime()
            row = ProviderInstanceSettings(
                provider_type=SMSBOWER_PROVIDER_TYPE,
                instance_id=instance_id,
                enabled=runtime.enabled,
                api_base=runtime.api_base,
                service_code=runtime.service,
                domain=runtime.domain,
                max_price=runtime.max_price,
                request_timeout_seconds=runtime.request_timeout_seconds,
            )
            if runtime.api_key and self._credential_cipher is not None:
                row.api_key_ciphertext = self._credential_cipher.encrypt(runtime.api_key)
            self._session.add(row)

        if enabled is not None:
            row.enabled = enabled
        if api_base is not None:
            normalized = api_base.strip()
            row.api_base = normalize_smsbower_base_url(normalized) if normalized else SMSBOWER_DEFAULT_BASE_URL
        if service is not None:
            row.service_code = service.strip() or SMSBOWER_DEFAULT_SERVICE
        if domain is not None:
            row.domain = domain.strip() or SMSBOWER_DEFAULT_DOMAIN
        if clear_max_price:
            row.max_price = None
        elif max_price is not None:
            row.max_price = float(max_price)
        if request_timeout_seconds is not None:
            row.request_timeout_seconds = float(request_timeout_seconds)
        if clear_api_key:
            row.api_key_ciphertext = None
        elif api_key is not None:
            plaintext = api_key.strip()
            if not plaintext:
                row.api_key_ciphertext = None
            else:
                if self._credential_cipher is None:
                    raise RuntimeError("凭证加密密钥未配置，无法保存 API Key")
                row.api_key_ciphertext = self._credential_cipher.encrypt(plaintext)

        row.updated_at = utc_now()
        self._session.flush()
        return self.get_smsbower_admin_view()

    def list_provider_summaries(self) -> list[dict]:
        """Catalog of all known providers for admin UI."""
        items: list[dict] = []
        for definition in PROVIDER_DEFINITIONS:
            if definition.provider_type == SMSBOWER_PROVIDER_TYPE:
                smsbower = self.get_smsbower_admin_view()
                items.append(
                    {
                        "provider_type": definition.provider_type,
                        "display_name": definition.display_name,
                        "supply_mode": definition.supply_mode,
                        "supported_modes": list(definition.supported_modes),
                        "configurable_in_ui": definition.configurable_in_ui,
                        "enabled": smsbower.enabled,
                        "has_api_key": smsbower.has_api_key,
                        "instance_id": smsbower.instance_id,
                        "source": smsbower.source,
                        "notes": definition.notes,
                        "fields": [self._field_schema_dict(field) for field in definition.fields],
                    }
                )
                continue
            if definition.provider_type == "microsoft":
                items.append(
                    {
                        "provider_type": definition.provider_type,
                        "display_name": definition.display_name,
                        "supply_mode": definition.supply_mode,
                        "supported_modes": list(definition.supported_modes),
                        "configurable_in_ui": False,
                        "enabled": True,
                        "has_api_key": False,
                        "instance_id": definition.default_instance_id,
                        "source": "import",
                        "notes": definition.notes,
                        "fields": [],
                    }
                )
                continue
            view = self.get_provider_admin_view(definition.provider_type)
            items.append(
                {
                    "provider_type": definition.provider_type,
                    "display_name": definition.display_name,
                    "supply_mode": definition.supply_mode,
                    "supported_modes": list(definition.supported_modes),
                    "configurable_in_ui": definition.configurable_in_ui,
                    "enabled": view["enabled"],
                    "has_api_key": view["has_any_secret"],
                    "instance_id": view["instance_id"],
                    "source": view["source"],
                    "notes": definition.notes,
                    "fields": [self._field_schema_dict(field) for field in definition.fields],
                }
            )
        return items

    def get_provider_admin_view(self, provider_type: str, instance_id: str | None = None) -> dict[str, Any]:
        """Admin-safe view for one provider instance (no secret plaintext)."""
        if provider_type == SMSBOWER_PROVIDER_TYPE:
            view = self.get_smsbower_admin_view()
            return {
                "provider_type": view.provider_type,
                "instance_id": view.instance_id,
                "enabled": view.enabled,
                "source": view.source,
                "has_any_secret": view.has_api_key,
                "secret_flags": {"api_key": view.has_api_key},
                "values": {
                    "api_base": view.api_base,
                    "service": view.service,
                    "domain": view.domain,
                    "max_price": view.max_price,
                    "request_timeout_seconds": view.request_timeout_seconds,
                },
                "updated_at": view.updated_at,
            }
        definition = get_provider_definition(provider_type)
        effective_instance = (instance_id or definition.default_instance_id).strip()
        row = self._session.get(ProviderInstanceSettings, (provider_type, effective_instance))
        values, secret_flags, source, enabled, timeout = self._read_instance_fields(definition, row)
        return {
            "provider_type": provider_type,
            "instance_id": effective_instance,
            "enabled": enabled,
            "source": source,
            "has_any_secret": any(secret_flags.values()),
            "secret_flags": secret_flags,
            "values": values,
            "request_timeout_seconds": timeout,
            "updated_at": row.updated_at if row is not None else None,
            "fields": [self._field_schema_dict(field) for field in definition.fields],
        }

    def resolve_on_demand_runtime(
        self, provider_type: str, instance_id: str | None = None
    ) -> OnDemandRuntimeConfig:
        definition = get_provider_definition(provider_type)
        effective_instance = (instance_id or definition.default_instance_id).strip()
        row = self._session.get(ProviderInstanceSettings, (provider_type, effective_instance))
        values, secret_flags, _source, enabled, timeout = self._read_instance_fields(definition, row)
        secrets = self._decrypt_secrets(definition, row)
        # Ensure primary secret key is present under its field name.
        primary = definition.primary_secret_key
        if primary and primary not in secrets and row is not None and row.api_key_ciphertext:
            if self._credential_cipher is not None:
                try:
                    secrets[primary] = self._credential_cipher.decrypt(row.api_key_ciphertext)
                except Exception:
                    pass
        return OnDemandRuntimeConfig(
            provider_type=provider_type,
            instance_id=effective_instance,
            enabled=enabled,
            values=values,
            secrets=secrets,
            timeout_seconds=timeout,
        )

    def update_provider_instance(
        self,
        provider_type: str,
        *,
        instance_id: str | None = None,
        enabled: bool | None = None,
        values: dict[str, Any] | None = None,
        secrets: dict[str, str] | None = None,
        clear_secrets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Upsert one provider instance. Secrets never returned in response."""
        if provider_type == SMSBOWER_PROVIDER_TYPE:
            payload = values or {}
            self.update_smsbower(
                enabled=enabled,
                api_base=payload.get("api_base"),
                service=payload.get("service"),
                domain=payload.get("domain"),
                max_price=payload.get("max_price"),
                clear_max_price=bool(payload.get("clear_max_price")),
                request_timeout_seconds=payload.get("request_timeout_seconds"),
                api_key=(secrets or {}).get("api_key"),
                clear_api_key="api_key" in (clear_secrets or []),
            )
            return self.get_provider_admin_view(SMSBOWER_PROVIDER_TYPE, instance_id)

        definition = get_provider_definition(provider_type)
        effective_instance = (instance_id or definition.default_instance_id).strip()
        row = self._session.get(ProviderInstanceSettings, (provider_type, effective_instance))
        if row is None:
            row = ProviderInstanceSettings(
                provider_type=provider_type,
                instance_id=effective_instance,
                enabled=False,
                request_timeout_seconds=30.0,
                config_json={},
            )
            self._session.add(row)

        if enabled is not None:
            row.enabled = bool(enabled)

        config = dict(row.config_json) if isinstance(row.config_json, dict) else {}
        if values:
            for field in definition.fields:
                if field.secret or field.key not in values:
                    continue
                config[field.key] = self._normalize_field_value(field.field_type, values[field.key])
            if "request_timeout_seconds" in values and values["request_timeout_seconds"] is not None:
                row.request_timeout_seconds = float(values["request_timeout_seconds"])
            if "api_base" in values and values["api_base"] is not None:
                row.api_base = str(values["api_base"]).strip() or None
            if "domain" in values and not any(f.key == "domain" and f.field_type == "string_list" for f in definition.fields):
                row.domain = str(values.get("domain") or "").strip() or None
        row.config_json = config

        secret_map = self._decrypt_secrets(definition, row)
        for key in clear_secrets or []:
            secret_map.pop(key, None)
            if key == definition.primary_secret_key:
                row.api_key_ciphertext = None
        if secrets:
            if self._credential_cipher is None:
                raise RuntimeError("凭证加密密钥未配置，无法保存密钥")
            for key, plaintext in secrets.items():
                text = str(plaintext or "").strip()
                if not text:
                    secret_map.pop(key, None)
                    if key == definition.primary_secret_key:
                        row.api_key_ciphertext = None
                    continue
                secret_map[key] = text
                if key == definition.primary_secret_key:
                    row.api_key_ciphertext = self._credential_cipher.encrypt(text)

        # Secondary secrets bag excludes primary if also stored in api_key_ciphertext.
        secondary = {
            key: value
            for key, value in secret_map.items()
            if key != definition.primary_secret_key
        }
        if secondary:
            if self._credential_cipher is None:
                raise RuntimeError("凭证加密密钥未配置，无法保存密钥")
            row.secrets_ciphertext = self._credential_cipher.encrypt(
                json.dumps(secondary, ensure_ascii=False)
            )
        else:
            row.secrets_ciphertext = None

        row.updated_at = utc_now()
        self._session.flush()
        return self.get_provider_admin_view(provider_type, effective_instance)

    def _read_instance_fields(
        self,
        definition: ProviderTypeDefinition,
        row: ProviderInstanceSettings | None,
    ) -> tuple[dict[str, Any], dict[str, bool], str, bool, float]:
        values: dict[str, Any] = {}
        for field in definition.fields:
            if field.secret:
                continue
            if field.default is not None:
                values[field.key] = field.default
        secret_flags = {field.key: False for field in definition.fields if field.secret}
        if row is None:
            return values, secret_flags, "default", False, 30.0

        config = row.config_json if isinstance(row.config_json, dict) else {}
        for field in definition.fields:
            if field.secret:
                continue
            if field.key in config:
                values[field.key] = config[field.key]
        if row.api_base and "api_base" in values:
            values["api_base"] = row.api_base
        elif row.api_base:
            values["api_base"] = row.api_base
        if row.domain and "domain" not in values:
            values["domain"] = row.domain
        timeout = float(row.request_timeout_seconds or 30.0)
        values["request_timeout_seconds"] = timeout

        if row.api_key_ciphertext:
            primary = definition.primary_secret_key
            if primary in secret_flags:
                secret_flags[primary] = True
        if row.secrets_ciphertext and self._credential_cipher is not None:
            try:
                bag = json.loads(self._credential_cipher.decrypt(row.secrets_ciphertext))
                if isinstance(bag, dict):
                    for key, value in bag.items():
                        if key in secret_flags and str(value or "").strip():
                            secret_flags[key] = True
            except Exception:
                pass
        return values, secret_flags, "database", bool(row.enabled), timeout

    def _decrypt_secrets(
        self,
        definition: ProviderTypeDefinition,
        row: ProviderInstanceSettings | None,
    ) -> dict[str, str]:
        secrets: dict[str, str] = {}
        if row is None or self._credential_cipher is None:
            return secrets
        if row.api_key_ciphertext:
            try:
                secrets[definition.primary_secret_key] = self._credential_cipher.decrypt(
                    row.api_key_ciphertext
                )
            except Exception:
                pass
        if row.secrets_ciphertext:
            try:
                bag = json.loads(self._credential_cipher.decrypt(row.secrets_ciphertext))
                if isinstance(bag, dict):
                    for key, value in bag.items():
                        text = str(value or "").strip()
                        if text:
                            secrets[str(key)] = text
            except Exception:
                pass
        return secrets

    @staticmethod
    def _normalize_field_value(field_type: str, value: Any) -> Any:
        if field_type == "string_list":
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
            text = str(value or "")
            return [part.strip() for part in re.split(r"[\n,]", text) if part.strip()]
        if field_type == "boolean":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in {"1", "true", "yes", "on"}
        if field_type == "number":
            if value in (None, ""):
                return None
            return float(value)
        return str(value).strip() if value is not None else None

    @staticmethod
    def _field_schema_dict(field) -> dict[str, Any]:
        return {
            "key": field.key,
            "label": field.label,
            "field_type": field.field_type,
            "required": field.required,
            "secret": field.secret,
            "description": field.description,
            "default": field.default,
            "placeholder": field.placeholder,
        }

    def _get_smsbower_row(
        self, *, instance_id: str | None = None
    ) -> ProviderInstanceSettings | None:
        effective_id = (
            instance_id
            or (self._settings.smsbower_instance_id or SMSBOWER_DEFAULT_INSTANCE_ID)
        ).strip()
        return self._session.get(ProviderInstanceSettings, (SMSBOWER_PROVIDER_TYPE, effective_id))
