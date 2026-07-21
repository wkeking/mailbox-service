"""Admin mailbox import/delete operations with claim-aware concurrency (SEC-08/11)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import uuid

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from mailbox_service.audit_service import new_operation_id, write_audit_event
from mailbox_service.models import (
    Lease,
    Mailbox,
    MailboxLeaseClaim,
    MailboxStatus,
    is_expired,
    utc_now,
)
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import stamp_refresh_token_lifetime


class ActiveLeaseClaimConflictError(Exception):
    """Raised when delete/replace is blocked by an active lease claim."""

    def __init__(self, *, mailbox_ids: list[str]) -> None:
        self.mailbox_ids = mailbox_ids
        super().__init__(f"active lease claims block operation: {','.join(mailbox_ids)}")


@dataclass(frozen=True)
class AdminDeleteResult:
    deleted: int
    deleted_mailbox_ids: list[str]
    missing_mailbox_ids: list[str]
    blocked_mailbox_ids: list[str]
    operation_id: str


@dataclass(frozen=True)
class AdminDeleteInvalidResult:
    deleted: int
    deleted_mailbox_ids: list[str]
    deleted_primary_emails: list[str]
    operation_id: str


class MailboxAdminService:
    """Admin destructive mailbox operations with claim checks and chunk audits."""

    def __init__(self, session: Session, credential_cipher: CredentialCipher | None = None) -> None:
        self._session = session
        self._credential_cipher = credential_cipher

    def delete_mailboxes_by_ids(
        self,
        mailbox_ids: list[str],
        *,
        admin_id: str,
        force_release_active_leases: bool = False,
    ) -> AdminDeleteResult:
        """Delete selected mailboxes; default rejects rows with active claims."""
        operation_id = new_operation_id()
        unique_ids = list(dict.fromkeys(mailbox_ids))
        mailboxes = list(
            self._session.scalars(
                select(Mailbox).where(Mailbox.id.in_(unique_ids)).order_by(Mailbox.id.asc()).with_for_update()
            )
        )
        found_ids = {mailbox.id for mailbox in mailboxes}
        missing_mailbox_ids = [mailbox_id for mailbox_id in unique_ids if mailbox_id not in found_ids]

        active_claim_mailbox_ids = self._active_claim_mailbox_ids([mailbox.id for mailbox in mailboxes])
        if active_claim_mailbox_ids and not force_release_active_leases:
            raise ActiveLeaseClaimConflictError(mailbox_ids=active_claim_mailbox_ids)

        deleted_mailbox_ids: list[str] = []
        deleted_primary_emails: list[str] = []
        for mailbox in mailboxes:
            if force_release_active_leases:
                self._force_release_claims_and_leases(mailbox.id, admin_id=admin_id, operation_id=operation_id)
            deleted_mailbox_ids.append(mailbox.id)
            deleted_primary_emails.append(mailbox.primary_email)

        if deleted_mailbox_ids:
            # Explicit child cleanup so SQLite test engines without FK pragma still pass.
            self._session.execute(
                delete(MailboxLeaseClaim).where(MailboxLeaseClaim.mailbox_id.in_(deleted_mailbox_ids))
            )
            self._session.execute(delete(Lease).where(Lease.mailbox_id.in_(deleted_mailbox_ids)))
            self._session.execute(delete(Mailbox).where(Mailbox.id.in_(deleted_mailbox_ids)))
            self._session.flush()
            write_audit_event(
                self._session,
                actor_type="admin",
                actor_id=admin_id,
                event_type="mailbox.deleted",
                target_type="mailbox",
                target_id=None,
                operation_id=operation_id,
                metadata={
                    "deleted": len(deleted_mailbox_ids),
                    "deleted_mailbox_ids": deleted_mailbox_ids,
                    "deleted_primary_emails": deleted_primary_emails,
                    "missing_mailbox_ids": missing_mailbox_ids,
                    "force_release_active_leases": force_release_active_leases,
                },
            )

        return AdminDeleteResult(
            deleted=len(deleted_mailbox_ids),
            deleted_mailbox_ids=deleted_mailbox_ids,
            missing_mailbox_ids=missing_mailbox_ids,
            blocked_mailbox_ids=[],
            operation_id=operation_id,
        )

    def delete_invalid_mailboxes_in_chunks(
        self,
        *,
        admin_id: str,
        batch_size: int = 25,
        force_release_active_leases: bool = False,
    ) -> AdminDeleteInvalidResult:
        """Delete invalid mailboxes in SKIP LOCKED chunks with per-chunk audit."""
        operation_id = new_operation_id()
        deleted_mailbox_ids: list[str] = []
        deleted_primary_emails: list[str] = []
        chunk_index = 0

        while True:
            locked_rows = list(
                self._session.execute(
                    select(Mailbox.id, Mailbox.primary_email)
                    .where(Mailbox.status == MailboxStatus.INVALID)
                    .order_by(Mailbox.id.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                ).all()
            )
            if not locked_rows:
                break

            chunk_ids = [row[0] for row in locked_rows]
            # Re-confirm status under lock.
            still_invalid = list(
                self._session.scalars(
                    select(Mailbox).where(
                        Mailbox.id.in_(chunk_ids),
                        Mailbox.status == MailboxStatus.INVALID,
                    )
                )
            )
            chunk_mailbox_ids = [mailbox.id for mailbox in still_invalid]
            chunk_emails = [mailbox.primary_email for mailbox in still_invalid]
            if not chunk_mailbox_ids:
                break

            if not force_release_active_leases:
                blocked = self._active_claim_mailbox_ids(chunk_mailbox_ids)
                if blocked:
                    raise ActiveLeaseClaimConflictError(mailbox_ids=blocked)
            else:
                for mailbox_id in chunk_mailbox_ids:
                    self._force_release_claims_and_leases(
                        mailbox_id, admin_id=admin_id, operation_id=operation_id
                    )

            self._session.execute(
                delete(MailboxLeaseClaim).where(MailboxLeaseClaim.mailbox_id.in_(chunk_mailbox_ids))
            )
            self._session.execute(delete(Lease).where(Lease.mailbox_id.in_(chunk_mailbox_ids)))
            self._session.execute(delete(Mailbox).where(Mailbox.id.in_(chunk_mailbox_ids)))
            write_audit_event(
                self._session,
                actor_type="admin",
                actor_id=admin_id,
                event_type="mailbox.invalid_deleted_chunk",
                target_type="mailbox",
                target_id=None,
                operation_id=f"{operation_id}:{chunk_index}",
                metadata={
                    "operation_id": operation_id,
                    "chunk_index": chunk_index,
                    "deleted_mailbox_ids": chunk_mailbox_ids,
                    "deleted_primary_emails": chunk_emails,
                },
            )
            self._session.flush()
            # Caller may commit per chunk; we only flush here.
            deleted_mailbox_ids.extend(chunk_mailbox_ids)
            deleted_primary_emails.extend(chunk_emails)
            chunk_index += 1
            if len(locked_rows) < batch_size:
                break

        if deleted_mailbox_ids:
            write_audit_event(
                self._session,
                actor_type="admin",
                actor_id=admin_id,
                event_type="mailbox.invalid_deleted",
                target_type="mailbox",
                target_id=None,
                operation_id=operation_id,
                metadata={
                    "deleted": len(deleted_mailbox_ids),
                    "deleted_mailbox_ids": deleted_mailbox_ids,
                    "deleted_primary_emails": deleted_primary_emails,
                    "chunks": chunk_index,
                },
            )

        return AdminDeleteInvalidResult(
            deleted=len(deleted_mailbox_ids),
            deleted_mailbox_ids=deleted_mailbox_ids,
            deleted_primary_emails=deleted_primary_emails,
            operation_id=operation_id,
        )

    def list_active_claim_mailbox_ids(self, mailbox_ids: list[str]) -> list[str]:
        """Return mailbox IDs that currently hold a non-expired lease claim."""
        return self._active_claim_mailbox_ids(mailbox_ids)

    def force_release_active_claims(
        self,
        mailbox_id: str,
        *,
        admin_id: str,
        operation_id: str | None = None,
    ) -> None:
        """Release active leases and claim for one mailbox (admin force path)."""
        self._force_release_claims_and_leases(
            mailbox_id,
            admin_id=admin_id,
            operation_id=operation_id or new_operation_id(),
        )

    def _active_claim_mailbox_ids(self, mailbox_ids: list[str]) -> list[str]:
        if not mailbox_ids:
            return []
        current_time = utc_now()
        claims = list(
            self._session.scalars(
                select(MailboxLeaseClaim).where(MailboxLeaseClaim.mailbox_id.in_(mailbox_ids))
            )
        )
        return [
            claim.mailbox_id
            for claim in claims
            if not is_expired(claim.expires_at, current_time=current_time)
        ]

    def _force_release_claims_and_leases(
        self,
        mailbox_id: str,
        *,
        admin_id: str,
        operation_id: str,
    ) -> None:
        current_time = utc_now()
        sql_now = current_time.replace(tzinfo=None)
        active_leases = list(
            self._session.scalars(
                select(Lease)
                .where(
                    Lease.mailbox_id == mailbox_id,
                    Lease.released_at.is_(None),
                    Lease.expires_at > sql_now,
                )
                .with_for_update()
            )
        )
        for lease in active_leases:
            lease.released_at = current_time
        # Multiple plus-alias claims may share one mailbox; delete all of them.
        claims = list(
            self._session.scalars(
                select(MailboxLeaseClaim).where(MailboxLeaseClaim.mailbox_id == mailbox_id)
            )
        )
        for claim in claims:
            self._session.delete(claim)
        write_audit_event(
            self._session,
            actor_type="admin",
            actor_id=admin_id,
            event_type="lease.force_released_for_delete",
            target_type="mailbox",
            target_id=mailbox_id,
            operation_id=operation_id,
            metadata={"released_lease_ids": [lease.id for lease in active_leases]},
        )
        self._session.flush()
