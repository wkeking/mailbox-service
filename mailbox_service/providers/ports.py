"""Narrow internal ports for multi-provider operations.

Implementations must accept only immutable/detached DTOs. They must never receive a
SQLAlchemy Session or ORM instance, and must never commit/rollback caller transactions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence


@dataclass(frozen=True)
class VerificationAllocationSnapshot:
    """Detached lease allocation used for verification-code evidence fetch."""

    lease_id: str
    mailbox_id: str
    provider_type: str
    provider_instance_id: str | None
    primary_email: str
    allocated_email: str | None
    # Opaque credentials for the provider (never logged). Microsoft uses AT;
    # SMSBower uses activation / mail id material from encrypted resource secret.
    access_context: dict[str, str]


@dataclass(frozen=True)
class VerificationQuery:
    """Caller filters for verification evidence."""

    from_address: str | None = None
    subject_contains: str | None = None
    body_contains: str | None = None
    recipient: str | None = None
    newer_than: datetime | None = None
    max_messages: int = 20


@dataclass(frozen=True)
class InboxMessageEvidence:
    """One message candidate returned by a verification evidence source."""

    from_address: str | None
    subject: str | None
    body_text: str | None
    received_at: datetime | None
    recipient_addresses: frozenset[str]
    # Microsoft: imap | graph. Non-Microsoft: leave None (do not overload channel).
    channel: str | None = None
    # Optional direct code when provider returns OTP without message list.
    direct_code: str | None = None


@dataclass(frozen=True)
class VerificationEvidence:
    """Evidence batch: messages and/or a direct code."""

    messages: tuple[InboxMessageEvidence, ...]
    direct_code: str | None = None
    read_method: str | None = None


class VerificationEvidenceSource(Protocol):
    """Fetch inbox evidence or direct codes for an active allocation."""

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence: ...


@dataclass(frozen=True)
class MailboxDraft:
    """Normalized import draft (Microsoft four-segment, etc.)."""

    primary_email: str
    client_id: str | None
    mail_password: str | None
    refresh_token: str | None
    provider_type: str = "microsoft"


class MailboxImportDecoder(Protocol):
    """Parse import payload into drafts. Does not touch Lease/Verification."""

    def decode(self, content: str) -> Sequence[MailboxDraft]: ...


@dataclass(frozen=True)
class ReplenishRequest:
    provider_type: str
    provider_instance_id: str
    operation_id: str
    count: int = 1


@dataclass(frozen=True)
class ReplenishResult:
    operation_id: str
    status: str
    external_resource_id: str | None = None
    primary_email: str | None = None
    cost: float | None = None
    error_class: str | None = None


class InventoryReplenisher(Protocol):
    def replenish(self, request: ReplenishRequest) -> ReplenishResult: ...


@dataclass(frozen=True)
class ReleaseOperationSnapshot:
    operation_id: str
    provider_type: str
    provider_instance_id: str
    external_resource_id: str
    resource_generation: int
    expected_state_version: int
    lease_id: str | None
    # Non-secret status intent for remote finalizer (e.g. setStatus=3 success close).
    remote_status: int


@dataclass(frozen=True)
class ExternalOperationResult:
    operation_id: str
    outcome: str  # succeeded | failed | unknown
    error_class: str | None = None
    raw_summary: str | None = None


class RemoteResourceFinalizer(Protocol):
    def finalize(self, request: ReleaseOperationSnapshot) -> ExternalOperationResult: ...


@dataclass(frozen=True)
class OnDemandProvisionRequest:
    """Request to open a temporary mailbox at an external provider (no Session)."""

    provider_type: str
    provider_instance_id: str
    preferred_local_part: str | None = None


@dataclass(frozen=True)
class OnDemandProvisionResult:
    """Detached provision outcome for ephemeral inventory rows."""

    address: str
    external_resource_id: str
    # Opaque secret material encrypted into mailbox_provider_resources.encrypted_secret.
    secret_payload: dict[str, str]
    metadata: dict[str, str] | None = None


class OnDemandProvisioner(Protocol):
    """Create a temporary mailbox address and inbox credentials without DB access."""

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult: ...
