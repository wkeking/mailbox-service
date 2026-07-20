"""Provider descriptor registry shared by web and scheduler."""

from __future__ import annotations

from dataclasses import dataclass

from mailbox_service.providers.catalog import ALL_PROVIDER_TYPES, ON_DEMAND_PROVIDER_TYPES
from mailbox_service.providers.ports import (
    InventoryReplenisher,
    MailboxImportDecoder,
    OnDemandProvisioner,
    RemoteResourceFinalizer,
    VerificationEvidenceSource,
)

SUPPORTED_PROVIDER_TYPES = frozenset(ALL_PROVIDER_TYPES)
DEFAULT_PROVIDER_TYPE = "microsoft"


@dataclass(frozen=True)
class ProviderDescriptor:
    """Static description of one provider type."""

    provider_type: str
    supported_lease_modes: frozenset[str]
    supply_mode: str = "inventory"
    evidence_source: VerificationEvidenceSource | None = None
    import_decoder: MailboxImportDecoder | None = None
    inventory_replenisher: InventoryReplenisher | None = None
    remote_finalizer: RemoteResourceFinalizer | None = None
    on_demand_provisioner: OnDemandProvisioner | None = None


class ProviderRegistry:
    """Resolve providers by type; fail closed on unknown IDs."""

    def __init__(self, descriptors: dict[str, ProviderDescriptor] | None = None) -> None:
        self._descriptors: dict[str, ProviderDescriptor] = dict(descriptors or {})

    def register(self, descriptor: ProviderDescriptor) -> None:
        normalized = normalize_provider_type(descriptor.provider_type)
        if normalized in self._descriptors:
            raise ValueError(f"duplicate provider registration: {normalized}")
        self._descriptors[normalized] = ProviderDescriptor(
            provider_type=normalized,
            supported_lease_modes=descriptor.supported_lease_modes,
            supply_mode=descriptor.supply_mode,
            evidence_source=descriptor.evidence_source,
            import_decoder=descriptor.import_decoder,
            inventory_replenisher=descriptor.inventory_replenisher,
            remote_finalizer=descriptor.remote_finalizer,
            on_demand_provisioner=descriptor.on_demand_provisioner,
        )

    def get(self, provider_type: str) -> ProviderDescriptor:
        normalized = normalize_provider_type(provider_type)
        descriptor = self._descriptors.get(normalized)
        if descriptor is None:
            raise KeyError(f"unknown provider: {normalized}")
        return descriptor

    def require_evidence_source(self, provider_type: str) -> VerificationEvidenceSource:
        descriptor = self.get(provider_type)
        if descriptor.evidence_source is None:
            raise KeyError(f"provider has no evidence source: {descriptor.provider_type}")
        return descriptor.evidence_source

    def require_on_demand_provisioner(self, provider_type: str) -> OnDemandProvisioner:
        descriptor = self.get(provider_type)
        if descriptor.on_demand_provisioner is None:
            raise KeyError(f"provider has no on-demand provisioner: {descriptor.provider_type}")
        return descriptor.on_demand_provisioner

    def is_on_demand(self, provider_type: str) -> bool:
        normalized = normalize_provider_type(provider_type)
        if normalized in ON_DEMAND_PROVIDER_TYPES:
            return True
        descriptor = self._descriptors.get(normalized)
        return bool(descriptor and descriptor.supply_mode == "on_demand")

    def known_types(self) -> frozenset[str]:
        return frozenset(self._descriptors.keys())


def normalize_provider_type(provider_type: str) -> str:
    """Normalize provider IDs to lowercase ASCII with length cap."""
    text = str(provider_type or "").strip().lower()
    if not text:
        raise ValueError("provider_type is required")
    if len(text) > 64:
        raise ValueError("provider_type exceeds 64 characters")
    if not all(("a" <= character <= "z") or ("0" <= character <= "9") or character in "_-" for character in text):
        raise ValueError(f"invalid provider_type: {provider_type!r}")
    return text
