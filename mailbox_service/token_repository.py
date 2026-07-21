"""Database-level Token claim and RT CAS helpers shared by all RT writers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from mailbox_service.models import (
    LeaseMode,
    Mailbox,
    MailboxLeaseClaim,
    MailboxStatus,
    ensure_utc,
    is_expired,
    utc_now,
)


class TokenVersionConflictError(Exception):
    """Raised when a Refresh Token CAS update uses a stale version."""


class RefreshAlreadyClaimedError(Exception):
    """Raised when another worker holds an unexpired token-refresh claim."""

    def __init__(self, *, mailbox_id: str, claim_id: str, expires_at: datetime) -> None:
        self.mailbox_id = mailbox_id
        self.claim_id = claim_id
        self.expires_at = expires_at
        super().__init__(f"token refresh already claimed for mailbox {mailbox_id}")


class ActiveRefreshTokenLeaseError(Exception):
    """Raised when background refresh is blocked by an active RT lease claim."""


@dataclass(frozen=True, slots=True)
class TokenRefreshClaim:
    """Immutable claim payload used outside any database transaction."""

    claim_id: str
    mailbox_id: str
    primary_email: str
    client_id: str
    refresh_token: str
    expected_token_version: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CachedAccessTokenSnapshot:
    """Cached AT that is safe to return without network refresh."""

    mailbox_id: str
    primary_email: str
    access_token: str
    expires_at: datetime
    token_version: int
    scope: str | None


def compare_and_swap_refresh_token(
    session: Session,
    *,
    mailbox_id: str,
    expected_token_version: int,
    encrypted_refresh_token: str,
    refresh_token_updated_at: datetime,
    refresh_token_expires_at: datetime,
    clear_access_token_cache: bool = True,
) -> int:
    """Atomically replace RT when ``token_version`` still matches.

    Returns the new token_version on success. Raises TokenVersionConflictError
    when the row was updated by another writer.
    """
    values: dict[str, object] = {
        "refresh_token_ciphertext": encrypted_refresh_token,
        "refresh_token_updated_at": refresh_token_updated_at,
        "refresh_token_expires_at": refresh_token_expires_at,
        "token_version": expected_token_version + 1,
        "updated_at": refresh_token_updated_at,
    }
    if clear_access_token_cache:
        values.update(
            {
                "access_token_ciphertext": None,
                "access_token_expires_at": None,
                "access_token_refreshed_at": None,
                "access_token_source_version": None,
            }
        )
    result = session.execute(
        update(Mailbox)
        .where(
            Mailbox.id == mailbox_id,
            Mailbox.token_version == expected_token_version,
        )
        .values(**values)
    )
    if result.rowcount != 1:
        raise TokenVersionConflictError("Refresh Token 版本冲突")
    return expected_token_version + 1


def increment_token_version_under_lock(
    session: Session,
    *,
    mailbox_id: str,
    encrypted_refresh_token: str,
    refresh_token_updated_at: datetime,
    refresh_token_expires_at: datetime,
    clear_access_token_cache: bool = True,
) -> int:
    """Admin last-write-wins RT replace using database-side version increment.

    Caller must already hold the Mailbox row lock. Uses ``token_version = token_version + 1``
    so concurrent replaces each advance the counter instead of lost updates in Python.
    """
    if clear_access_token_cache:
        session.execute(
            text(
                """
                UPDATE mailboxes
                SET refresh_token_ciphertext = :encrypted_refresh_token,
                    refresh_token_updated_at = :refresh_token_updated_at,
                    refresh_token_expires_at = :refresh_token_expires_at,
                    token_version = token_version + 1,
                    access_token_ciphertext = NULL,
                    access_token_expires_at = NULL,
                    access_token_refreshed_at = NULL,
                    access_token_source_version = NULL,
                    updated_at = :refresh_token_updated_at
                WHERE id = :mailbox_id
                """
            ),
            {
                "mailbox_id": mailbox_id,
                "encrypted_refresh_token": encrypted_refresh_token,
                "refresh_token_updated_at": refresh_token_updated_at.replace(tzinfo=None)
                if refresh_token_updated_at.tzinfo
                else refresh_token_updated_at,
                "refresh_token_expires_at": refresh_token_expires_at.replace(tzinfo=None)
                if refresh_token_expires_at.tzinfo
                else refresh_token_expires_at,
            },
        )
    else:
        session.execute(
            text(
                """
                UPDATE mailboxes
                SET refresh_token_ciphertext = :encrypted_refresh_token,
                    refresh_token_updated_at = :refresh_token_updated_at,
                    refresh_token_expires_at = :refresh_token_expires_at,
                    token_version = token_version + 1,
                    updated_at = :refresh_token_updated_at
                WHERE id = :mailbox_id
                """
            ),
            {
                "mailbox_id": mailbox_id,
                "encrypted_refresh_token": encrypted_refresh_token,
                "refresh_token_updated_at": refresh_token_updated_at.replace(tzinfo=None)
                if refresh_token_updated_at.tzinfo
                else refresh_token_updated_at,
                "refresh_token_expires_at": refresh_token_expires_at.replace(tzinfo=None)
                if refresh_token_expires_at.tzinfo
                else refresh_token_expires_at,
            },
        )
    mailbox = session.get(Mailbox, mailbox_id)
    if mailbox is None:
        raise LookupError("邮箱不存在")
    session.refresh(mailbox)
    return mailbox.token_version


def has_active_refresh_token_lease_claim(session: Session, mailbox_id: str) -> bool:
    """Return whether the mailbox currently has an active refresh_token lease claim."""
    current_time = utc_now()
    sql_current_time = current_time.replace(tzinfo=None)
    claim = session.scalar(
        select(MailboxLeaseClaim)
        .where(
            MailboxLeaseClaim.mailbox_id == mailbox_id,
            MailboxLeaseClaim.mode == LeaseMode.REFRESH_TOKEN,
            MailboxLeaseClaim.expires_at > sql_current_time,
        )
        .limit(1)
    )
    return claim is not None


def claim_token_refresh(
    session: Session,
    *,
    mailbox_id: str,
    decrypt_refresh_token,
    claim_ttl_seconds: int,
    skip_active_rt_lease_check: bool = False,
) -> TokenRefreshClaim:
    """Phase A: lock mailbox, ensure no concurrent claim, write claim, return immutable payload.

    Uses a conditional UPDATE so only one writer can install an unexpired claim even under
    concurrent short transactions. Does not commit; caller owns the short transaction.
    """
    mailbox = session.scalar(select(Mailbox).where(Mailbox.id == mailbox_id).with_for_update())
    if mailbox is None:
        raise LookupError("邮箱不存在")
    if mailbox.status == MailboxStatus.INVALID:
        raise RuntimeError("邮箱状态为 invalid，无法刷新 access token")
    if not mailbox.client_id or not mailbox.refresh_token_ciphertext:
        raise RuntimeError("邮箱缺少 Client ID 或 refresh token")

    current_time = utc_now()
    # Persist naive UTC for MySQL DATETIME(6) so later readers compare consistently.
    current_time_naive = current_time.replace(tzinfo=None)
    if (
        mailbox.token_refresh_claim_id is not None
        and mailbox.token_refresh_claim_expires_at is not None
        and not is_expired(mailbox.token_refresh_claim_expires_at, current_time=current_time)
    ):
        raise RefreshAlreadyClaimedError(
            mailbox_id=mailbox.id,
            claim_id=mailbox.token_refresh_claim_id,
            expires_at=ensure_utc(mailbox.token_refresh_claim_expires_at),
        )

    if not skip_active_rt_lease_check and has_active_refresh_token_lease_claim(session, mailbox_id):
        raise ActiveRefreshTokenLeaseError("存在活跃 refresh_token 租约，跳过后台刷新")

    claim_id = str(uuid.uuid4())
    expires_at = current_time + timedelta(seconds=claim_ttl_seconds)
    expires_at_naive = expires_at.replace(tzinfo=None)
    # Atomic install: only succeed when no live claim remains after the row lock.
    result = session.execute(
        update(Mailbox)
        .where(
            Mailbox.id == mailbox_id,
            (Mailbox.token_refresh_claim_id.is_(None))
            | (Mailbox.token_refresh_claim_expires_at.is_(None))
            | (Mailbox.token_refresh_claim_expires_at <= current_time_naive),
        )
        .values(
            token_refresh_claim_id=claim_id,
            token_refresh_claim_expires_at=expires_at_naive,
            updated_at=current_time_naive,
        )
    )
    if result.rowcount != 1:
        session.refresh(mailbox)
        existing_claim_id = mailbox.token_refresh_claim_id or "unknown"
        existing_expires = (
            ensure_utc(mailbox.token_refresh_claim_expires_at)
            if mailbox.token_refresh_claim_expires_at is not None
            else current_time
        )
        raise RefreshAlreadyClaimedError(
            mailbox_id=mailbox_id,
            claim_id=existing_claim_id,
            expires_at=existing_expires,
        )
    session.refresh(mailbox)

    return TokenRefreshClaim(
        claim_id=claim_id,
        mailbox_id=mailbox.id,
        primary_email=mailbox.primary_email,
        client_id=mailbox.client_id,
        refresh_token=decrypt_refresh_token(mailbox.refresh_token_ciphertext),
        expected_token_version=mailbox.token_version,
        expires_at=expires_at,
    )


def _as_naive_utc(value: datetime | None) -> datetime | None:
    """Persist DATETIME-compatible naive UTC (MySQL/SQLite both prefer this)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return ensure_utc(value).replace(tzinfo=None)


def complete_token_refresh(
    session: Session,
    *,
    claim: TokenRefreshClaim,
    encrypted_access_token: str,
    access_token_expires_at: datetime,
    access_token_refreshed_at: datetime,
    scope: str | None,
    encrypted_refresh_token: str | None,
    refresh_token_rotated: bool,
    refresh_token_updated_at: datetime | None,
    refresh_token_expires_at: datetime | None,
) -> int | None:
    """Phase C success finalize with claim + version CAS. Returns new token_version or None."""
    access_token_expires_at = _as_naive_utc(access_token_expires_at)  # type: ignore[assignment]
    access_token_refreshed_at = _as_naive_utc(access_token_refreshed_at)  # type: ignore[assignment]
    refresh_token_updated_at = _as_naive_utc(refresh_token_updated_at)
    refresh_token_expires_at = _as_naive_utc(refresh_token_expires_at)

    if refresh_token_rotated:
        if (
            encrypted_refresh_token is None
            or refresh_token_updated_at is None
            or refresh_token_expires_at is None
        ):
            raise ValueError("rotated refresh requires encrypted RT and lifetime stamps")
        result = session.execute(
            update(Mailbox)
            .where(
                Mailbox.id == claim.mailbox_id,
                Mailbox.token_version == claim.expected_token_version,
                Mailbox.token_refresh_claim_id == claim.claim_id,
            )
            .values(
                refresh_token_ciphertext=encrypted_refresh_token,
                refresh_token_updated_at=refresh_token_updated_at,
                refresh_token_expires_at=refresh_token_expires_at,
                token_version=claim.expected_token_version + 1,
                access_token_ciphertext=encrypted_access_token,
                access_token_expires_at=access_token_expires_at,
                access_token_refreshed_at=access_token_refreshed_at,
                access_token_source_version=claim.expected_token_version + 1,
                scope=scope,
                token_refresh_claim_id=None,
                token_refresh_claim_expires_at=None,
                updated_at=access_token_refreshed_at,
            )
        )
        session.flush()
        if result.rowcount == 1:
            return claim.expected_token_version + 1
        # SQLite/DB-API may report unreliable rowcount; confirm CAS by re-reading.
        return _confirm_completed_token_version(
            session,
            claim=claim,
            expected_source_version=claim.expected_token_version + 1,
            expect_token_version=claim.expected_token_version + 1,
        )

    result = session.execute(
        update(Mailbox)
        .where(
            Mailbox.id == claim.mailbox_id,
            Mailbox.token_version == claim.expected_token_version,
            Mailbox.token_refresh_claim_id == claim.claim_id,
        )
        .values(
            access_token_ciphertext=encrypted_access_token,
            access_token_expires_at=access_token_expires_at,
            access_token_refreshed_at=access_token_refreshed_at,
            access_token_source_version=claim.expected_token_version,
            scope=scope,
            refresh_token_updated_at=refresh_token_updated_at,
            refresh_token_expires_at=refresh_token_expires_at,
            token_refresh_claim_id=None,
            token_refresh_claim_expires_at=None,
            updated_at=access_token_refreshed_at,
        )
    )
    session.flush()
    if result.rowcount == 1:
        return claim.expected_token_version
    return _confirm_completed_token_version(
        session,
        claim=claim,
        expected_source_version=claim.expected_token_version,
        expect_token_version=claim.expected_token_version,
    )


def _confirm_completed_token_version(
    session: Session,
    *,
    claim: TokenRefreshClaim,
    expected_source_version: int,
    expect_token_version: int,
) -> int | None:
    """Confirm a CAS UPDATE landed when driver rowcount is unreliable."""
    # Prefer a column-level SELECT: ORM refresh can break after bulk UPDATE on SQLite.
    row = session.execute(
        select(
            Mailbox.token_version,
            Mailbox.access_token_source_version,
            Mailbox.token_refresh_claim_id,
            Mailbox.access_token_ciphertext,
        ).where(Mailbox.id == claim.mailbox_id)
    ).one_or_none()
    if row is None:
        return None
    token_version, source_version, refresh_claim_id, access_token_ciphertext = row
    if (
        token_version == expect_token_version
        and source_version == expected_source_version
        and refresh_claim_id is None
        and access_token_ciphertext is not None
    ):
        return expect_token_version
    return None


def fail_token_refresh_invalid_grant(
    session: Session,
    *,
    claim: TokenRefreshClaim,
) -> bool:
    """Mark mailbox invalid only when claim + version still match. Returns True if applied."""
    result = session.execute(
        update(Mailbox)
        .where(
            Mailbox.id == claim.mailbox_id,
            Mailbox.token_version == claim.expected_token_version,
            Mailbox.token_refresh_claim_id == claim.claim_id,
        )
        .values(
            status=MailboxStatus.INVALID,
            token_refresh_claim_id=None,
            token_refresh_claim_expires_at=None,
            updated_at=utc_now(),
        )
    )
    return result.rowcount == 1


def release_token_refresh_claim(
    session: Session,
    *,
    claim: TokenRefreshClaim,
) -> None:
    """Clear claim when refresh failed without invalid_grant, only if still owned."""
    session.execute(
        update(Mailbox)
        .where(
            Mailbox.id == claim.mailbox_id,
            Mailbox.token_refresh_claim_id == claim.claim_id,
        )
        .values(
            token_refresh_claim_id=None,
            token_refresh_claim_expires_at=None,
            updated_at=utc_now(),
        )
    )
