"""Authorization checkpoints for verification-code long polling (SEC-09)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from mailbox_service.client_key_service import ClientKeyScopeError, ClientPrincipal
from mailbox_service.models import (
    ClientKey,
    Lease,
    LeaseMode,
    Mailbox,
    MailboxStatus,
    ensure_utc,
    is_expired,
    utc_now,
)


class VerificationAuthorizationError(Exception):
    """Raised when a poll checkpoint fails authorization."""

    def __init__(self, *, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class VerificationLookupAuthorization:
    """Snapshot of identities revalidated on each poll checkpoint."""

    lease_id: str
    mailbox_id: str
    client_key_id: str
    primary_email: str
    allocated_email: str | None


def revalidate_verification_authorization(
    session: Session,
    *,
    principal: ClientPrincipal,
    lease_id: str,
) -> VerificationLookupAuthorization:
    """Re-check Client Key, lease ownership/status, and mailbox readability.

    Call at request start, before each scan, before forced AT refresh, and before
    returning a found verification code.
    """
    try:
        principal.require_scope("mail:verification-code:read")
    except ClientKeyScopeError as error:
        raise VerificationAuthorizationError(
            code="CLIENT_KEY_SCOPE_DENIED",
            message=str(error),
        ) from error

    current_time = utc_now()
    client_key = session.get(ClientKey, principal.client_key_id)
    if client_key is None or not client_key.enabled:
        raise VerificationAuthorizationError(
            code="CLIENT_KEY_INACTIVE",
            message="Client Key 已停用或不存在",
        )
    if client_key.expires_at is not None and is_expired(
        client_key.expires_at, current_time=current_time
    ):
        raise VerificationAuthorizationError(
            code="CLIENT_KEY_EXPIRED",
            message="Client Key 已过期",
        )
    if "mail:verification-code:read" not in set(client_key.scopes or []):
        raise VerificationAuthorizationError(
            code="CLIENT_KEY_SCOPE_DENIED",
            message="Client Key 缺少权限：mail:verification-code:read",
        )

    lease = session.scalar(select(Lease).where(Lease.id == lease_id))
    if lease is None or lease.client_key_id != principal.client_key_id:
        raise VerificationAuthorizationError(
            code="LEASE_NOT_FOUND",
            message="租约不存在或不属于当前调用方",
        )
    if lease.mode != LeaseMode.MAIL_READ:
        raise VerificationAuthorizationError(
            code="LEASE_MODE_MISMATCH",
            message="该租约不是 mail_read mode",
        )
    if lease.released_at is not None:
        raise VerificationAuthorizationError(
            code="LEASE_INACTIVE",
            message="租约已释放",
        )
    if is_expired(lease.expires_at, current_time=current_time):
        raise VerificationAuthorizationError(
            code="LEASE_INACTIVE",
            message="租约已过期",
        )

    mailbox = session.get(Mailbox, lease.mailbox_id)
    if mailbox is None or mailbox.status != MailboxStatus.ACTIVE:
        raise VerificationAuthorizationError(
            code="LEASE_INACTIVE",
            message="租约邮箱当前不可用",
        )

    return VerificationLookupAuthorization(
        lease_id=lease.id,
        mailbox_id=mailbox.id,
        client_key_id=principal.client_key_id,
        primary_email=mailbox.primary_email,
        allocated_email=lease.allocated_email or mailbox.primary_email,
    )


def authorization_still_valid_timestamp(expires_at) -> str:
    """Helper for audit metadata without secrets."""
    return ensure_utc(expires_at).isoformat()
