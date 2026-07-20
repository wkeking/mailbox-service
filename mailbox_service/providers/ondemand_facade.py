"""Runtime factory for on-demand providers (settings + adapters, no long-lived Session)."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.providers.catalog import ON_DEMAND_PROVIDER_TYPES, get_provider_definition
from mailbox_service.providers.http_client import JsonHttpClient
from mailbox_service.providers.ondemand_adapters import (
    OnDemandProviderError,
    OnDemandProviderFacade,
    OnDemandRuntimeConfig,
)
from mailbox_service.providers.ports import (
    OnDemandProvisionRequest,
    OnDemandProvisionResult,
    VerificationAllocationSnapshot,
    VerificationEvidence,
    VerificationQuery,
)
from mailbox_service.security import CredentialCipher


class OnDemandProviderService:
    """Resolve settings and delegate provision/evidence to adapters."""

    def __init__(
        self,
        settings: Settings,
        *,
        credential_cipher: CredentialCipher,
        session_factory: sessionmaker[Session],
        http_client: JsonHttpClient | None = None,
        runtime_overrides: dict[str, OnDemandRuntimeConfig] | None = None,
    ) -> None:
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._session_factory = session_factory
        self._http_client = http_client
        self._runtime_overrides = runtime_overrides or {}

    def is_supported(self, provider_type: str) -> bool:
        return provider_type in ON_DEMAND_PROVIDER_TYPES

    def resolve_runtime(self, provider_type: str, instance_id: str | None = None) -> OnDemandRuntimeConfig:
        if provider_type in self._runtime_overrides:
            return self._runtime_overrides[provider_type]
        from mailbox_service.provider_settings_service import ProviderSettingsService

        definition = get_provider_definition(provider_type)
        effective_instance = (instance_id or definition.default_instance_id).strip()
        session = self._session_factory()
        try:
            return ProviderSettingsService(
                session, self._settings, self._credential_cipher
            ).resolve_on_demand_runtime(provider_type, effective_instance)
        finally:
            session.close()

    def require_configured_facade(self, provider_type: str) -> OnDemandProviderFacade:
        runtime = self.resolve_runtime(provider_type)
        if not runtime.enabled:
            raise OnDemandProviderError(f"{provider_type} is not enabled")
        definition = get_provider_definition(provider_type)
        for field in definition.fields:
            if not field.required:
                continue
            if field.secret:
                if not (runtime.secrets.get(field.key) or "").strip():
                    raise OnDemandProviderError(f"{provider_type} missing required secret: {field.key}")
            else:
                value = runtime.values.get(field.key)
                if value in (None, "", []):
                    raise OnDemandProviderError(f"{provider_type} missing required field: {field.key}")
        return OnDemandProviderFacade(runtime, http_client=self._http_client)

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        facade = self.require_configured_facade(request.provider_type)
        return facade.provision(request)

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        facade = self.require_configured_facade(allocation.provider_type)
        return facade.fetch_evidence(allocation, query)
