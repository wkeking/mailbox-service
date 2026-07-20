"""Build the process-wide ProviderRegistry used by web and scheduler."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.providers.catalog import ON_DEMAND_PROVIDER_TYPES
from mailbox_service.providers.microsoft import (
    MicrosoftFourSegmentImportDecoder,
    MicrosoftVerificationEvidenceSource,
)
from mailbox_service.providers.ondemand_facade import OnDemandProviderService
from mailbox_service.providers.ports import (
    OnDemandProvisionRequest,
    OnDemandProvisionResult,
    VerificationAllocationSnapshot,
    VerificationEvidence,
    VerificationQuery,
)
from mailbox_service.providers.registry import ProviderDescriptor, ProviderRegistry
from mailbox_service.proxy_service import MicrosoftIMAPClient
from mailbox_service.security import CredentialCipher
from mailbox_service.verification_code_service import MicrosoftGraphMailReader


class _OnDemandPortBridge:
    """Adapter that exposes OnDemandProviderService as provisioner + evidence source."""

    def __init__(self, service: OnDemandProviderService, provider_type: str) -> None:
        self._service = service
        self._provider_type = provider_type

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        return self._service.provision(request)

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        return self._service.fetch_evidence(allocation, query)


def build_provider_registry(
    *,
    graph_reader: MicrosoftGraphMailReader | None = None,
    imap_client: MicrosoftIMAPClient | None = None,
    settings: Settings | None = None,
    credential_cipher: CredentialCipher | None = None,
    session_factory: sessionmaker[Session] | None = None,
    on_demand_service: OnDemandProviderService | None = None,
) -> ProviderRegistry:
    """Create registry with Microsoft + optional on-demand providers."""
    registry = ProviderRegistry()
    microsoft_evidence = MicrosoftVerificationEvidenceSource(
        graph_reader=graph_reader,
        imap_client=imap_client,
    )
    registry.register(
        ProviderDescriptor(
            provider_type="microsoft",
            supply_mode="inventory",
            supported_lease_modes=frozenset({"refresh_token", "access_token", "mail_read"}),
            evidence_source=microsoft_evidence,
            import_decoder=MicrosoftFourSegmentImportDecoder(),
        )
    )

    service = on_demand_service
    if service is None and settings is not None and credential_cipher is not None and session_factory is not None:
        service = OnDemandProviderService(
            settings,
            credential_cipher=credential_cipher,
            session_factory=session_factory,
        )
    if service is not None:
        for provider_type in sorted(ON_DEMAND_PROVIDER_TYPES):
            bridge = _OnDemandPortBridge(service, provider_type)
            registry.register(
                ProviderDescriptor(
                    provider_type=provider_type,
                    supply_mode="on_demand",
                    supported_lease_modes=frozenset({"mail_read"}),
                    evidence_source=bridge,
                    on_demand_provisioner=bridge,
                )
            )
    return registry
