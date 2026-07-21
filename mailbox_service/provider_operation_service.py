"""Durable provider operations for replenish and remote release (short DB UoW only)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.models import (
    AuditLog,
    MailboxProviderOperation,
    MailboxProviderResource,
    ProviderOperationStatus,
    ProviderOperationType,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
    utc_now,
)
from mailbox_service.security import CredentialCipher


@dataclass(frozen=True)
class ProviderOperationSnapshot:
    operation_id: str
    operation_type: str
    provider_type: str
    provider_instance_id: str
    status: str
    mailbox_id: str | None
    provider_resource_id: str | None
    lease_id: str | None
    external_resource_id: str | None
    resource_generation: int | None
    expected_state_version: int | None
    idempotency_key: str


class ProviderOperationService:
    """Create and finalize durable operations without holding locks across network I/O."""

    def __init__(
        self,
        session: Session,
        *,
        session_factory: sessionmaker[Session] | None = None,
        credential_cipher: CredentialCipher | None = None,
    ) -> None:
        self._session = session
        self._session_factory = session_factory
        self._credential_cipher = credential_cipher

    def create_pending_operation(
        self,
        *,
        operation_type: str,
        provider_type: str,
        provider_instance_id: str,
        idempotency_key: str,
        mailbox_id: str | None = None,
        provider_resource_id: str | None = None,
        lease_id: str | None = None,
        external_resource_id: str | None = None,
        resource_generation: int | None = None,
        expected_state_version: int | None = None,
    ) -> ProviderOperationSnapshot:
        existing = self._session.scalar(
            select(MailboxProviderOperation).where(
                MailboxProviderOperation.idempotency_key == idempotency_key
            )
        )
        if existing is not None:
            return self._to_snapshot(existing)

        operation = MailboxProviderOperation(
            id=str(uuid.uuid4()),
            operation_type=operation_type,
            provider_type=provider_type,
            provider_instance_id=provider_instance_id,
            mailbox_id=mailbox_id,
            provider_resource_id=provider_resource_id,
            lease_id=lease_id,
            external_resource_id=external_resource_id,
            resource_generation=resource_generation,
            expected_state_version=expected_state_version,
            status=ProviderOperationStatus.PENDING.value,
            idempotency_key=idempotency_key,
            attempt_count=0,
        )
        self._session.add(operation)
        self._session.flush()
        return self._to_snapshot(operation)

    def mark_running(self, operation_id: str) -> ProviderOperationSnapshot | None:
        operation = self._session.get(MailboxProviderOperation, operation_id)
        if operation is None:
            return None
        operation.status = ProviderOperationStatus.RUNNING.value
        operation.attempt_count = int(operation.attempt_count or 0) + 1
        operation.updated_at = utc_now()
        self._session.flush()
        return self._to_snapshot(operation)

    def finalize_operation(
        self,
        operation_id: str,
        *,
        status: str,
        error_class: str | None = None,
        result_summary: dict | None = None,
    ) -> ProviderOperationSnapshot | None:
        operation = self._session.get(MailboxProviderOperation, operation_id)
        if operation is None:
            return None
        operation.status = status
        operation.last_error_class = error_class
        operation.result_summary_json = result_summary
        operation.updated_at = utc_now()
        self._session.flush()
        return self._to_snapshot(operation)

    def finalize_smsbower_replenish_success(
        self,
        *,
        operation_id: str,
        provider_instance_id: str,
        external_resource_id: str,
        primary_email: str,
        encrypted_secret: str | None,
        cost: float | None,
        actor_id: str = "admin",
    ) -> str:
        """Idempotent insert of provider resource only (never writes mailboxes)."""
        existing_resource = self._session.scalar(
            select(MailboxProviderResource).where(
                MailboxProviderResource.provider_instance_id == provider_instance_id,
                MailboxProviderResource.external_resource_id == external_resource_id,
            )
        )
        if existing_resource is not None:
            self.finalize_operation(
                operation_id,
                status=ProviderOperationStatus.SUCCEEDED.value,
                result_summary={
                    "provider_resource_id": existing_resource.id,
                    "external_resource_id": external_resource_id,
                    "deduplicated": True,
                    "cost": cost,
                },
            )
            return existing_resource.id

        resource_id = str(uuid.uuid4())
        resource = MailboxProviderResource(
            id=resource_id,
            provider_type="smsbower_gmail",
            provider_instance_id=provider_instance_id,
            external_resource_id=external_resource_id,
            primary_email=primary_email.strip().lower(),
            lifecycle_state=ProviderResourceLifecycle.AVAILABLE.value,
            readiness=ProviderResourceReadiness.READY.value,
            state_version=0,
            resource_generation=0,
            encrypted_secret=encrypted_secret,
            metadata_json={"cost": cost} if cost is not None else None,
        )
        self._session.add(resource)
        self._session.add(
            AuditLog(
                actor_type="admin",
                actor_id=actor_id,
                event_type="provider.replenish.succeeded",
                target_type="provider_resource",
                target_id=resource_id,
                metadata_json={
                    "operation_id": operation_id,
                    "provider_type": "smsbower_gmail",
                    "provider_instance_id": provider_instance_id,
                    "external_resource_id": external_resource_id,
                    "primary_email": primary_email.strip().lower(),
                    "cost": cost,
                },
            )
        )
        operation = self._session.get(MailboxProviderOperation, operation_id)
        if operation is not None:
            operation.provider_resource_id = resource_id
            operation.mailbox_id = None
            operation.external_resource_id = external_resource_id
            operation.status = ProviderOperationStatus.SUCCEEDED.value
            operation.result_summary_json = {
                "provider_resource_id": resource_id,
                "external_resource_id": external_resource_id,
                "cost": cost,
            }
            operation.updated_at = utc_now()
        self._session.flush()
        return resource_id

    def begin_release_operation(
        self,
        *,
        lease_id: str,
        provider_resource_id: str,
        provider_type: str,
        provider_instance_id: str,
        external_resource_id: str,
        resource_generation: int,
        expected_state_version: int,
        principal_id: str,
        mailbox_id: str | None = None,
    ) -> ProviderOperationSnapshot:
        """Mark resource releasing and create pending release operation (same short txn)."""
        idempotency_key = f"release:{lease_id}:{resource_generation}"
        existing = self._session.scalar(
            select(MailboxProviderOperation).where(
                MailboxProviderOperation.idempotency_key == idempotency_key
            )
        )
        if existing is not None:
            return self._to_snapshot(existing)

        resource = self._session.get(MailboxProviderResource, provider_resource_id)
        if resource is None:
            raise RuntimeError("provider resource missing for release")
        if resource.lifecycle_state not in (
            ProviderResourceLifecycle.CLAIMED.value,
            ProviderResourceLifecycle.RELEASING.value,
            ProviderResourceLifecycle.RELEASE_UNKNOWN.value,
        ):
            # Already terminal or available — still create idempotent pending release.
            pass
        resource.lifecycle_state = ProviderResourceLifecycle.RELEASING.value
        resource.state_version = int(resource.state_version or 0) + 1
        resource.updated_at = utc_now()
        snapshot = self.create_pending_operation(
            operation_type=ProviderOperationType.RELEASE.value,
            provider_type=provider_type,
            provider_instance_id=provider_instance_id,
            idempotency_key=idempotency_key,
            mailbox_id=mailbox_id,
            provider_resource_id=provider_resource_id,
            lease_id=lease_id,
            external_resource_id=external_resource_id,
            resource_generation=resource_generation,
            expected_state_version=expected_state_version,
        )
        self._session.add(
            AuditLog(
                actor_type="client",
                actor_id=principal_id,
                event_type="provider.release.pending",
                target_type="lease",
                target_id=lease_id,
                metadata_json={
                    "operation_id": snapshot.operation_id,
                    "provider_resource_id": provider_resource_id,
                    "external_resource_id": external_resource_id,
                    "resource_generation": resource_generation,
                },
            )
        )
        self._session.flush()
        return snapshot

    def finalize_release_cas(
        self,
        *,
        operation_id: str,
        provider_resource_id: str,
        expected_generation: int,
        expected_state_version: int,
        outcome: str,
        clear_secret: bool = False,
        mailbox_id: str | None = None,
    ) -> bool:
        """CAS finalize resource lifecycle after setStatus. Returns whether applied."""
        del mailbox_id  # retained for call-site compatibility; lookup is by resource id
        resource = self._session.get(MailboxProviderResource, provider_resource_id)
        operation = self._session.get(MailboxProviderOperation, operation_id)
        if resource is None or operation is None:
            return False
        if int(resource.resource_generation or 0) != int(expected_generation):
            return False
        if resource.lifecycle_state not in (
            ProviderResourceLifecycle.RELEASING.value,
            ProviderResourceLifecycle.RELEASE_UNKNOWN.value,
        ):
            if operation.status in (
                ProviderOperationStatus.SUCCEEDED.value,
                ProviderOperationStatus.FAILED.value,
            ):
                return True
            return False

        if outcome == "succeeded":
            resource.lifecycle_state = ProviderResourceLifecycle.AVAILABLE.value
            resource.readiness = ProviderResourceReadiness.READY.value
            resource.resource_generation = int(resource.resource_generation or 0) + 1
            resource.state_version = int(resource.state_version or 0) + 1
            if clear_secret:
                resource.encrypted_secret = None
            operation.status = ProviderOperationStatus.SUCCEEDED.value
        elif outcome == "failed":
            resource.lifecycle_state = ProviderResourceLifecycle.COOLDOWN.value
            resource.readiness = ProviderResourceReadiness.NOT_READY.value
            resource.state_version = int(resource.state_version or 0) + 1
            operation.status = ProviderOperationStatus.FAILED.value
            operation.last_error_class = "remote_failed"
        else:
            resource.lifecycle_state = ProviderResourceLifecycle.RELEASE_UNKNOWN.value
            resource.readiness = ProviderResourceReadiness.NOT_READY.value
            resource.state_version = int(resource.state_version or 0) + 1
            operation.status = ProviderOperationStatus.UNKNOWN.value
            operation.last_error_class = "remote_unknown"

        resource.updated_at = utc_now()
        operation.updated_at = utc_now()
        self._session.flush()
        return True

    @staticmethod
    def _to_snapshot(operation: MailboxProviderOperation) -> ProviderOperationSnapshot:
        return ProviderOperationSnapshot(
            operation_id=operation.id,
            operation_type=operation.operation_type,
            provider_type=operation.provider_type,
            provider_instance_id=operation.provider_instance_id,
            status=operation.status,
            mailbox_id=operation.mailbox_id,
            provider_resource_id=getattr(operation, "provider_resource_id", None),
            lease_id=operation.lease_id,
            external_resource_id=operation.external_resource_id,
            resource_generation=operation.resource_generation,
            expected_state_version=operation.expected_state_version,
            idempotency_key=operation.idempotency_key,
        )
