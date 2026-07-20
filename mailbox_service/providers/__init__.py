"""Provider descriptors, narrow ports, and registry (CASE-20260720-001).

Not a public multi-vendor SPI. Operation-specific ports only.
"""

from mailbox_service.providers.ports import (
    InventoryReplenisher,
    MailboxImportDecoder,
    RemoteResourceFinalizer,
    VerificationEvidenceSource,
)
from mailbox_service.providers.registry import ProviderDescriptor, ProviderRegistry

__all__ = [
    "InventoryReplenisher",
    "MailboxImportDecoder",
    "ProviderDescriptor",
    "ProviderRegistry",
    "RemoteResourceFinalizer",
    "VerificationEvidenceSource",
]
