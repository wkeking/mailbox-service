"""Provider-instance connectivity probes for Admin health and domain listing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence
import time

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, MailboxCapability, MailboxStatus, utc_now
from mailbox_service.providers.catalog import (
    ON_DEMAND_PROVIDER_TYPES,
    PROVIDER_DEFINITIONS,
    get_provider_definition,
)
from mailbox_service.providers.http_client import HttpxJsonHttpClient, JsonHttpClient, ProviderHttpError
from mailbox_service.providers.ondemand_adapters import OnDemandRuntimeConfig
from mailbox_service.security import CredentialCipher, summarize_exception, summarize_text


OPERATOR_DEBUG_PURPOSE = "operator_debug"


@dataclass(frozen=True)
class ProviderHealthResult:
    """One provider instance connectivity snapshot."""

    provider_type: str
    provider_instance_id: str
    enabled: bool
    status: str  # ok | degraded | down | skipped | unknown
    latency_ms: int | None = None
    checked_at: datetime | None = None
    domains_preview: list[str] = field(default_factory=list)
    error_summary: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    display_name: str | None = None
    supply_mode: str | None = None


class ProviderHealthService:
    """Probe configured provider instances without holding DB sessions across I/O."""

    def __init__(
        self,
        settings: Settings,
        *,
        credential_cipher: CredentialCipher | None,
        session_factory: sessionmaker[Session],
        http_client: JsonHttpClient | None = None,
        probe_timeout_seconds: float = 10.0,
    ) -> None:
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._session_factory = session_factory
        self._http_client = http_client
        self._probe_timeout_seconds = probe_timeout_seconds

    def check_all(self, *, check: bool = True) -> list[ProviderHealthResult]:
        """Return health for every known provider type (default instance)."""
        results: list[ProviderHealthResult] = []
        for definition in PROVIDER_DEFINITIONS:
            results.append(
                self.check_one(
                    definition.provider_type,
                    definition.default_instance_id,
                    check=check,
                )
            )
        return results

    def check_one(
        self,
        provider_type: str,
        instance_id: str | None = None,
        *,
        check: bool = True,
    ) -> ProviderHealthResult:
        """Probe one provider instance."""
        try:
            definition = get_provider_definition(provider_type)
        except KeyError:
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=(instance_id or "default").strip(),
                enabled=False,
                status="skipped",
                error_summary="unknown provider",
                checked_at=utc_now() if check else None,
            )

        effective_instance = (instance_id or definition.default_instance_id).strip()
        if not check:
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=effective_instance,
                enabled=True if provider_type == "microsoft" else False,
                status="unknown",
                display_name=definition.display_name,
                supply_mode=definition.supply_mode,
            )

        if provider_type == "microsoft":
            return self._probe_microsoft_inventory(definition.display_name)
        if provider_type == "smsbower_gmail":
            return self._probe_smsbower(effective_instance, definition.display_name)
        if provider_type in ON_DEMAND_PROVIDER_TYPES:
            return self._probe_on_demand(provider_type, effective_instance, definition.display_name)
        return ProviderHealthResult(
            provider_type=provider_type,
            provider_instance_id=effective_instance,
            enabled=False,
            status="skipped",
            error_summary="no probe for provider",
            checked_at=utc_now(),
            display_name=definition.display_name,
            supply_mode=definition.supply_mode,
        )

    def list_domains(self, provider_type: str, instance_id: str | None = None) -> list[str]:
        """Return available domains for providers that support domain listing."""
        if provider_type == "microsoft":
            return []
        if provider_type == "smsbower_gmail":
            runtime_view = self._resolve_smsbower_admin_domain()
            return [runtime_view] if runtime_view else []
        if provider_type not in ON_DEMAND_PROVIDER_TYPES:
            return []
        runtime = self._resolve_on_demand_runtime(provider_type, instance_id)
        if not runtime.enabled:
            raise RuntimeError(f"{provider_type} is not enabled")
        domains = self._list_on_demand_domains(runtime)
        return domains

    def _probe_microsoft_inventory(self, display_name: str) -> ProviderHealthResult:
        started = time.monotonic()
        checked_at = utc_now()
        try:
            session = self._session_factory()
            try:
                total = session.scalar(select(func.count()).select_from(Mailbox)) or 0
                active = (
                    session.scalar(
                        select(func.count()).select_from(Mailbox).where(
                            Mailbox.status == MailboxStatus.ACTIVE
                        )
                    )
                    or 0
                )
                usable = (
                    session.scalar(
                        select(func.count())
                        .select_from(Mailbox)
                        .where(
                            Mailbox.status == MailboxStatus.ACTIVE,
                            Mailbox.capability.in_(
                                [MailboxCapability.IMAP, MailboxCapability.GRAPH]
                            ),
                        )
                    )
                    or 0
                )
                unprobed = (
                    session.scalar(
                        select(func.count())
                        .select_from(Mailbox)
                        .where(
                            Mailbox.status == MailboxStatus.ACTIVE,
                            or_(
                                Mailbox.capability.is_(None),
                                Mailbox.capability == MailboxCapability.UNKNOWN,
                            ),
                        )
                    )
                    or 0
                )
            finally:
                session.close()
            latency_ms = int((time.monotonic() - started) * 1000)
            status = "ok" if usable > 0 or total == 0 else "degraded"
            return ProviderHealthResult(
                provider_type="microsoft",
                provider_instance_id="default",
                enabled=True,
                status=status,
                latency_ms=latency_ms,
                checked_at=checked_at,
                detail={
                    "total": int(total),
                    "active": int(active),
                    "usable": int(usable),
                    "unprobed": int(unprobed),
                },
                display_name=display_name,
                supply_mode="inventory_import",
            )
        except Exception as error:  # noqa: BLE001
            return ProviderHealthResult(
                provider_type="microsoft",
                provider_instance_id="default",
                enabled=True,
                status="down",
                latency_ms=int((time.monotonic() - started) * 1000),
                checked_at=checked_at,
                error_summary=summarize_exception(error),
                display_name=display_name,
                supply_mode="inventory_import",
            )

    def _probe_smsbower(self, instance_id: str, display_name: str) -> ProviderHealthResult:
        started = time.monotonic()
        checked_at = utc_now()
        session = self._session_factory()
        try:
            from mailbox_service.provider_settings_service import ProviderSettingsService

            runtime = ProviderSettingsService(
                session, self._settings, self._credential_cipher
            ).resolve_smsbower_runtime()
        finally:
            session.close()
        if not runtime.enabled:
            return ProviderHealthResult(
                provider_type="smsbower_gmail",
                provider_instance_id=instance_id,
                enabled=False,
                status="skipped",
                checked_at=checked_at,
                error_summary="provider disabled",
                display_name=display_name,
                supply_mode="inventory_replenish",
            )
        if not (runtime.api_key or "").strip():
            return ProviderHealthResult(
                provider_type="smsbower_gmail",
                provider_instance_id=instance_id,
                enabled=True,
                status="degraded",
                checked_at=checked_at,
                error_summary="api_key not configured",
                domains_preview=[runtime.domain] if runtime.domain else [],
                display_name=display_name,
                supply_mode="inventory_replenish",
            )
        # SMSBower has no dedicated lightweight ping in this codebase; treat configured+enabled as ok.
        return ProviderHealthResult(
            provider_type="smsbower_gmail",
            provider_instance_id=instance_id,
            enabled=True,
            status="ok",
            latency_ms=int((time.monotonic() - started) * 1000),
            checked_at=checked_at,
            domains_preview=[runtime.domain] if runtime.domain else [],
            detail={"api_base": runtime.api_base, "service": runtime.service},
            display_name=display_name,
            supply_mode="inventory_replenish",
        )

    def _probe_on_demand(
        self,
        provider_type: str,
        instance_id: str,
        display_name: str,
    ) -> ProviderHealthResult:
        started = time.monotonic()
        checked_at = utc_now()
        try:
            runtime = self._resolve_on_demand_runtime(provider_type, instance_id)
        except Exception as error:  # noqa: BLE001
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=instance_id,
                enabled=False,
                status="down",
                latency_ms=int((time.monotonic() - started) * 1000),
                checked_at=checked_at,
                error_summary=summarize_exception(error),
                display_name=display_name,
                supply_mode="on_demand",
            )
        if not runtime.enabled:
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=instance_id,
                enabled=False,
                status="skipped",
                checked_at=checked_at,
                error_summary="provider disabled",
                display_name=display_name,
                supply_mode="on_demand",
            )
        try:
            domains = self._list_on_demand_domains(runtime)
            latency_ms = int((time.monotonic() - started) * 1000)
            status = "ok" if domains else "degraded"
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=instance_id,
                enabled=True,
                status=status,
                latency_ms=latency_ms,
                checked_at=checked_at,
                domains_preview=list(domains[:5]),
                detail={"domain_count": len(domains)},
                display_name=display_name,
                supply_mode="on_demand",
                error_summary=None if domains else "domains empty",
            )
        except Exception as error:  # noqa: BLE001
            return ProviderHealthResult(
                provider_type=provider_type,
                provider_instance_id=instance_id,
                enabled=True,
                status="down",
                latency_ms=int((time.monotonic() - started) * 1000),
                checked_at=checked_at,
                error_summary=summarize_text(str(error), maximum_length=240)
                or summarize_exception(error),
                display_name=display_name,
                supply_mode="on_demand",
            )

    def _resolve_on_demand_runtime(
        self, provider_type: str, instance_id: str | None
    ) -> OnDemandRuntimeConfig:
        from mailbox_service.provider_settings_service import ProviderSettingsService

        session = self._session_factory()
        try:
            return ProviderSettingsService(
                session, self._settings, self._credential_cipher
            ).resolve_on_demand_runtime(provider_type, instance_id)
        finally:
            session.close()

    def _resolve_smsbower_admin_domain(self) -> str:
        from mailbox_service.provider_settings_service import ProviderSettingsService

        session = self._session_factory()
        try:
            runtime = ProviderSettingsService(
                session, self._settings, self._credential_cipher
            ).resolve_smsbower_runtime()
            return (runtime.domain or "").strip()
        finally:
            session.close()

    def _http(self, timeout_seconds: float | None = None) -> JsonHttpClient:
        if self._http_client is not None:
            return self._http_client
        return HttpxJsonHttpClient(
            timeout_seconds=timeout_seconds or self._probe_timeout_seconds
        )

    def _list_on_demand_domains(self, runtime: OnDemandRuntimeConfig) -> list[str]:
        """Best-effort domain discovery from configured values or remote APIs."""
        configured = _string_list_from_runtime(runtime, "domain") or _string_list_from_runtime(
            runtime, "cf_domain"
        )
        if configured:
            return configured
        default_domain = str(runtime.values.get("default_domain") or "").strip()
        if default_domain:
            return [default_domain]

        provider_type = runtime.provider_type
        http = self._http(runtime.timeout_seconds)
        api_base = str(runtime.values.get("api_base") or "").rstrip("/")

        if provider_type in {"duckmail", "gptmail"}:
            # Public mail.tm-compatible domain endpoints when used.
            base = "https://api.duckmail.sbs" if provider_type == "duckmail" else ""
            if not base:
                return []
            data = http.request_json("GET", f"{base}/domains")
            return _domains_from_payload(data)

        if provider_type == "tempmail_lol":
            # TempMail.lol does not always require domain list; empty is degraded not down.
            return []

        if not api_base:
            return []

        # freemail / cloudflare-like
        headers = _auth_headers_for_runtime(runtime)
        candidates = [
            f"{api_base}/api/domains",
            f"{api_base}/domains",
            f"{api_base}/admin/domains",
        ]
        last_error: Exception | None = None
        for url in candidates:
            try:
                data = http.request_json("GET", url, headers=headers or None)
                domains = _domains_from_payload(data)
                if domains:
                    return domains
            except ProviderHttpError as error:
                last_error = error
                continue
            except Exception as error:  # noqa: BLE001
                last_error = error
                continue
        if last_error is not None and not configured:
            raise last_error
        return configured


def _string_list_from_runtime(runtime: OnDemandRuntimeConfig, key: str) -> list[str]:
    raw = runtime.values.get(key)
    if isinstance(raw, str):
        return [part.strip() for part in raw.replace("\n", ",").split(",") if part.strip()]
    if isinstance(raw, list):
        return [str(part).strip() for part in raw if str(part).strip()]
    return []


def _auth_headers_for_runtime(runtime: OnDemandRuntimeConfig) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    for secret_key in ("api_key", "admin_password", "jwt", "token"):
        value = (runtime.secrets.get(secret_key) or "").strip()
        if not value:
            continue
        if secret_key == "admin_password":
            headers["x-admin-auth"] = value
            headers["Authorization"] = f"Bearer {value}"
        else:
            headers["Authorization"] = f"Bearer {value}"
            headers["X-API-Key"] = value
        break
    return headers


def _domains_from_payload(data: Any) -> list[str]:
    if isinstance(data, list):
        domains: list[str] = []
        for item in data:
            if isinstance(item, str) and item.strip():
                domains.append(item.strip())
            elif isinstance(item, dict):
                domain = item.get("domain") or item.get("name") or item.get("id")
                if domain:
                    domains.append(str(domain).strip())
        return [item for item in domains if item]
    if isinstance(data, dict):
        for key in ("domains", "items", "data", "results"):
            nested = data.get(key)
            if nested is not None:
                return _domains_from_payload(nested)
        domain = data.get("domain")
        if isinstance(domain, str) and domain.strip():
            return [domain.strip()]
    return []
