"""External mailbox lease ownership and Token consistency operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import string

from sqlalchemy import exists, select, update
from sqlalchemy.orm import Session

from mailbox_service.client_key_service import ClientPrincipal
from mailbox_service.models import (
    AuditLog,
    Lease,
    LeaseMode,
    Mailbox,
    MailboxCapability,
    MailboxStatus,
    utc_now,
)
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenResult, MailboxAccessTokenService

PLUS_ALIAS_SUFFIX_ALPHABET = string.ascii_lowercase + string.digits
DEFAULT_PLUS_ALIAS_SUFFIX_LENGTH = 8
MAX_PLUS_ALIAS_GENERATION_ATTEMPTS = 32


class LeaseNotFoundError(Exception):
    """Raised when a lease does not exist or does not belong to the caller."""


class LeaseUnavailableError(Exception):
    """Raised when no mailbox can satisfy a lease request."""


class LeaseInactiveError(Exception):
    """Raised when a lease was released or has expired."""


class LeaseModeError(Exception):
    """Raised when a credential operation is incompatible with the lease mode."""


class TokenVersionConflictError(Exception):
    """Raised when a Refresh Token CAS update uses a stale version."""


class LeaseEmailNotFoundError(Exception):
    """Raised when reacquire cannot resolve email ownership for the caller.

    Used for unknown addresses, other clients' history, and unresolvable plus
    aliases. Callers should map this to a uniform 404 without leaking existence.
    """


class LeaseMailboxBusyError(Exception):
    """Raised when the target mailbox already has an active lease that blocks reacquire."""


@dataclass(frozen=True)
class LeaseAcquireResult:
    """Lease metadata plus the credential selected by its mode."""

    lease_id: str
    mailbox_id: str
    primary_email: str
    mode: LeaseMode
    expires_at: datetime
    created_at: datetime
    # Business address for this lease (primary or plus alias). mail_read only.
    allocated_email: str | None = None
    # primary | plus_alias when the lease has a business recipient address.
    address_kind: str | None = None
    access_token: str | None = None
    access_token_expires_at: datetime | None = None
    access_token_refreshed: bool | None = None
    client_id: str | None = None
    refresh_token: str | None = None
    token_version: int | None = None


@dataclass(frozen=True)
class LeaseReleaseResult:
    """Idempotent lease release result."""

    lease_id: str
    released_at: datetime


@dataclass(frozen=True)
class RefreshTokenUpdateResult:
    """Refresh Token CAS update result without secret material."""

    lease_id: str
    mailbox_id: str
    updated: bool
    token_version: int


class LeaseService:
    """Reserve mailboxes and enforce Client Key ownership around Token operations."""

    def __init__(
        self,
        session: Session,
        credential_cipher: CredentialCipher,
        access_token_service: MailboxAccessTokenService,
    ) -> None:
        self._session = session
        self._credential_cipher = credential_cipher
        self._access_token_service = access_token_service

    def acquire_lease(
        self,
        principal: ClientPrincipal,
        *,
        mode: LeaseMode,
        ttl_seconds: int,
        preferred_email: str | None = None,
        client_tag: str | None = None,
        purpose: str | None = None,
        use_plus_alias: bool = False,
        preferred_alias_suffix: str | None = None,
    ) -> LeaseAcquireResult:
        """Reserve one active mailbox that has no other unexpired lease."""
        if mode == LeaseMode.MAIL_READ:
            principal.require_scope("mailboxes:acquire")
        else:
            principal.require_scope("leases:acquire")
            if mode == LeaseMode.ACCESS_TOKEN:
                principal.require_scope("tokens:access:read")
            elif mode == LeaseMode.REFRESH_TOKEN:
                principal.require_scope("tokens:refresh:read")
            else:
                raise LeaseModeError(f"不支持的租约模式：{mode}")
            if use_plus_alias or preferred_alias_suffix:
                raise LeaseModeError("仅 mail_read 租约支持 plus alias 分配")

        current_time = utc_now()
        # MySQL DATETIME is typically naive; compare with a naive UTC value in SQL.
        sql_current_time = current_time.replace(tzinfo=None)
        active_lease_exists = exists(
            select(Lease.id).where(
                Lease.mailbox_id == Mailbox.id,
                Lease.released_at.is_(None),
                Lease.expires_at > sql_current_time,
            )
        )
        mailbox_query = select(Mailbox).where(
            Mailbox.status == MailboxStatus.ACTIVE,
            Mailbox.client_id.is_not(None),
            Mailbox.refresh_token_ciphertext.is_not(None),
            ~active_lease_exists,
        )
        if mode == LeaseMode.MAIL_READ:
            # Only hand out mailboxes with a proven mail channel; skip unprobed/unknown/unusable.
            mailbox_query = mailbox_query.where(
                Mailbox.capability.in_((MailboxCapability.IMAP, MailboxCapability.GRAPH))
            )
        if preferred_email:
            mailbox_query = mailbox_query.where(Mailbox.primary_email == preferred_email.strip().lower())
        mailbox_query = mailbox_query.order_by(Mailbox.updated_at.asc(), Mailbox.primary_email.asc()).with_for_update(
            skip_locked=True
        )
        mailbox = self._session.scalar(mailbox_query)
        if mailbox is None:
            raise LeaseUnavailableError("没有可用邮箱")

        allocated_email: str | None = None
        if mode == LeaseMode.MAIL_READ:
            if use_plus_alias or preferred_alias_suffix:
                allocated_email = self._allocate_plus_alias(
                    mailbox.primary_email,
                    preferred_alias_suffix=preferred_alias_suffix,
                )
            else:
                allocated_email = mailbox.primary_email.strip().lower()

        lease = Lease(
            mailbox_id=mailbox.id,
            client_key_id=principal.client_key_id,
            client_tag=client_tag,
            purpose=purpose,
            allocated_email=allocated_email,
            mode=mode,
            expires_at=current_time + timedelta(seconds=ttl_seconds),
            created_at=current_time,
        )
        self._session.add(lease)
        self._session.flush()

        address_kind = self._classify_address_kind(
            primary_email=mailbox.primary_email,
            allocated_email=allocated_email,
        )
        result_arguments = {
            "lease_id": lease.id,
            "mailbox_id": mailbox.id,
            "primary_email": mailbox.primary_email,
            "allocated_email": allocated_email,
            "address_kind": address_kind,
            "mode": lease.mode,
            "expires_at": lease.expires_at,
            "created_at": lease.created_at,
        }
        if mode == LeaseMode.ACCESS_TOKEN:
            access_token_result = self._access_token_service.ensure_access_token(mailbox.id)
            result = LeaseAcquireResult(
                **result_arguments,
                access_token=access_token_result.access_token,
                access_token_expires_at=access_token_result.expires_at,
                access_token_refreshed=access_token_result.refreshed,
                token_version=access_token_result.token_version,
            )
        elif mode == LeaseMode.REFRESH_TOKEN:
            result = LeaseAcquireResult(
                **result_arguments,
                client_id=mailbox.client_id,
                refresh_token=self._credential_cipher.decrypt(mailbox.refresh_token_ciphertext or ""),
                token_version=mailbox.token_version,
            )
        else:
            # mail_read leases only expose mailbox identity; tokens stay server-side.
            result = LeaseAcquireResult(**result_arguments)

        self._write_audit_log(
            principal,
            "lease.acquired",
            lease.id,
            {
                "mailbox_id": mailbox.id,
                "mode": lease.mode.value,
                "allocated_email": allocated_email,
                "address_kind": address_kind,
                "expires_at": lease.expires_at.isoformat(),
            },
        )
        return result

    def reacquire_lease_by_email(
        self,
        principal: ClientPrincipal,
        *,
        email: str,
        ttl_seconds: int,
        client_tag: str | None = None,
        purpose: str | None = None,
    ) -> LeaseAcquireResult:
        """Re-open a mail_read lease for a historically owned primary or plus-alias address.

        The caller supplies the business recipient saved from a previous acquire
        (``allocated_email``). This method resolves primary vs plus alias, checks that
        the same Client Key previously held a mail_read lease for the exact address,
        then creates a new lease (or renews an identical active one) without issuing tokens.
        """
        principal.require_scope("mailboxes:reacquire")
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise ValueError("email 不能为空")

        resolved_mailbox_id, allocated_email, address_kind = self._resolve_reacquire_email(normalized_email)
        if not self._client_has_mail_read_history(
            principal.client_key_id,
            allocated_email=allocated_email,
        ):
            # Uniform not-found: do not reveal whether the mailbox or history exists.
            raise LeaseEmailNotFoundError("邮箱地址不可用或不属于当前调用方")

        current_time = utc_now()
        sql_current_time = current_time.replace(tzinfo=None)
        mailbox = self._session.scalar(
            select(Mailbox)
            .where(Mailbox.id == resolved_mailbox_id)
            .with_for_update(skip_locked=True)
        )
        if mailbox is None:
            # skip_locked returns None when another transaction holds the row lock.
            existing_mailbox = self._session.get(Mailbox, resolved_mailbox_id)
            if existing_mailbox is None:
                raise LeaseEmailNotFoundError("邮箱地址不可用或不属于当前调用方")
            raise LeaseMailboxBusyError("目标邮箱当前被其他租约占用")
        if mailbox.status != MailboxStatus.ACTIVE:
            raise LeaseUnavailableError("目标邮箱当前不可用")
        if mailbox.capability not in (MailboxCapability.IMAP, MailboxCapability.GRAPH):
            raise LeaseUnavailableError("目标邮箱尚无可用的邮件读取通道")
        if mailbox.client_id is None or not mailbox.refresh_token_ciphertext:
            raise LeaseUnavailableError("目标邮箱凭证不完整")

        active_leases = list(
            self._session.scalars(
                select(Lease)
                .where(
                    Lease.mailbox_id == mailbox.id,
                    Lease.released_at.is_(None),
                    Lease.expires_at > sql_current_time,
                )
                .with_for_update()
            )
        )
        matching_owned_lease: Lease | None = None
        for active_lease in active_leases:
            same_owner = active_lease.client_key_id == principal.client_key_id
            same_mode = active_lease.mode == LeaseMode.MAIL_READ
            same_allocated = (active_lease.allocated_email or "").strip().lower() == allocated_email
            if same_owner and same_mode and same_allocated:
                matching_owned_lease = active_lease
                continue
            raise LeaseMailboxBusyError("目标邮箱当前被其他租约占用")

        if matching_owned_lease is not None:
            matching_owned_lease.expires_at = current_time + timedelta(seconds=ttl_seconds)
            if client_tag is not None:
                matching_owned_lease.client_tag = client_tag
            if purpose is not None:
                matching_owned_lease.purpose = purpose
            self._session.flush()
            self._write_audit_log(
                principal,
                "lease.reacquired",
                matching_owned_lease.id,
                {
                    "mailbox_id": mailbox.id,
                    "mode": matching_owned_lease.mode.value,
                    "allocated_email": allocated_email,
                    "address_kind": address_kind,
                    "renewed": True,
                    "expires_at": matching_owned_lease.expires_at.isoformat(),
                },
            )
            return LeaseAcquireResult(
                lease_id=matching_owned_lease.id,
                mailbox_id=mailbox.id,
                primary_email=mailbox.primary_email,
                allocated_email=allocated_email,
                address_kind=address_kind,
                mode=LeaseMode.MAIL_READ,
                expires_at=matching_owned_lease.expires_at,
                created_at=matching_owned_lease.created_at,
            )

        lease = Lease(
            mailbox_id=mailbox.id,
            client_key_id=principal.client_key_id,
            client_tag=client_tag,
            purpose=purpose,
            allocated_email=allocated_email,
            mode=LeaseMode.MAIL_READ,
            expires_at=current_time + timedelta(seconds=ttl_seconds),
            created_at=current_time,
        )
        self._session.add(lease)
        self._session.flush()
        self._write_audit_log(
            principal,
            "lease.reacquired",
            lease.id,
            {
                "mailbox_id": mailbox.id,
                "mode": lease.mode.value,
                "allocated_email": allocated_email,
                "address_kind": address_kind,
                "renewed": False,
                "expires_at": lease.expires_at.isoformat(),
            },
        )
        return LeaseAcquireResult(
            lease_id=lease.id,
            mailbox_id=mailbox.id,
            primary_email=mailbox.primary_email,
            allocated_email=allocated_email,
            address_kind=address_kind,
            mode=LeaseMode.MAIL_READ,
            expires_at=lease.expires_at,
            created_at=lease.created_at,
        )

    def release_lease(self, principal: ClientPrincipal, lease_id: str) -> LeaseReleaseResult:
        """Release an owned lease idempotently without deleting its audit trail."""
        principal.require_scope("leases:release")
        lease = self._load_owned_lease(principal, lease_id, require_active=False)
        if lease.released_at is None:
            lease.released_at = utc_now()
            self._write_audit_log(principal, "lease.released", lease.id, {"mailbox_id": lease.mailbox_id})
            self._session.flush()
        return LeaseReleaseResult(
            lease_id=lease.id,
            released_at=self._as_utc(lease.released_at),
        )

    def get_access_token(self, principal: ClientPrincipal, lease_id: str) -> MailboxAccessTokenResult:
        """Return a cached or refreshed Access Token for an owned active AT lease."""
        principal.require_scope("tokens:access:read")
        lease = self._load_owned_lease(principal, lease_id, require_active=True)
        if lease.mode != LeaseMode.ACCESS_TOKEN:
            raise LeaseModeError("该租约不是 access_token mode")
        mailbox = self._session.get(Mailbox, lease.mailbox_id)
        if mailbox is None or mailbox.status != MailboxStatus.ACTIVE:
            raise LeaseInactiveError("租约邮箱当前不可用")
        return self._access_token_service.ensure_access_token(mailbox.id)

    def load_active_mail_read_lease(
        self,
        principal: ClientPrincipal,
        lease_id: str,
    ) -> tuple[Lease, Mailbox]:
        """Return an owned active mail_read lease and its mailbox row.

        Intentionally loads without ``FOR UPDATE`` so verification-code polling can
        release the request transaction before long waits and avoid blocking admin
        cleanup (e.g. delete-invalid) for the whole timeout window.
        """
        principal.require_scope("mail:verification-code:read")
        lease = self._load_owned_lease(
            principal,
            lease_id,
            require_active=True,
            for_update=False,
        )
        if lease.mode != LeaseMode.MAIL_READ:
            raise LeaseModeError("该租约不是 mail_read mode")
        mailbox = self._session.get(Mailbox, lease.mailbox_id)
        if mailbox is None or mailbox.status != MailboxStatus.ACTIVE:
            raise LeaseInactiveError("租约邮箱当前不可用")
        return lease, mailbox

    def update_refresh_token(
        self,
        principal: ClientPrincipal,
        lease_id: str,
        *,
        expected_token_version: int,
        refresh_token: str,
    ) -> RefreshTokenUpdateResult:
        """CAS-update the Refresh Token for an owned active RT lease."""
        principal.require_scope("tokens:refresh:write")
        lease = self._load_owned_lease(principal, lease_id, require_active=True)
        if lease.mode != LeaseMode.REFRESH_TOKEN:
            raise LeaseModeError("该租约不是 refresh_token mode")

        mailbox = self._session.scalar(select(Mailbox).where(Mailbox.id == lease.mailbox_id).with_for_update())
        if mailbox is None or mailbox.status != MailboxStatus.ACTIVE:
            raise LeaseInactiveError("租约邮箱当前不可用")
        if mailbox.token_version != expected_token_version:
            raise TokenVersionConflictError("Refresh Token 版本冲突")

        existing_refresh_token = self._credential_cipher.decrypt(mailbox.refresh_token_ciphertext or "")
        if hmac_compare(existing_refresh_token, refresh_token):
            return RefreshTokenUpdateResult(
                lease_id=lease.id,
                mailbox_id=mailbox.id,
                updated=False,
                token_version=mailbox.token_version,
            )

        encrypted_refresh_token = self._credential_cipher.encrypt(refresh_token)
        update_result = self._session.execute(
            update(Mailbox)
            .where(Mailbox.id == mailbox.id, Mailbox.token_version == expected_token_version)
            .values(
                refresh_token_ciphertext=encrypted_refresh_token,
                access_token_ciphertext=None,
                access_token_expires_at=None,
                access_token_refreshed_at=None,
                token_version=Mailbox.token_version + 1,
                updated_at=utc_now(),
            )
        )
        if update_result.rowcount != 1:
            raise TokenVersionConflictError("Refresh Token 版本冲突")

        self._session.expire(mailbox)
        self._write_audit_log(
            principal,
            "mailbox.refresh_token.updated",
            mailbox.id,
            {"lease_id": lease.id, "token_version": expected_token_version + 1},
        )
        return RefreshTokenUpdateResult(
            lease_id=lease.id,
            mailbox_id=mailbox.id,
            updated=True,
            token_version=expected_token_version + 1,
        )

    def _load_owned_lease(
        self,
        principal: ClientPrincipal,
        lease_id: str,
        *,
        require_active: bool,
        for_update: bool = True,
    ) -> Lease:
        lease_query = select(Lease).where(
            Lease.id == lease_id,
            Lease.client_key_id == principal.client_key_id,
        )
        if for_update:
            lease_query = lease_query.with_for_update()
        lease = self._session.scalar(lease_query)
        if lease is None:
            raise LeaseNotFoundError("租约不存在")
        if require_active and (lease.released_at is not None or self._is_expired(lease.expires_at)):
            raise LeaseInactiveError("租约已释放或已过期")
        return lease

    def _resolve_reacquire_email(self, normalized_email: str) -> tuple[str, str, str]:
        """Map a business email to mailbox id, allocated address, and address kind.

        Resolution order:
        1. Exact match on ``Mailbox.primary_email`` → primary
        2. Plus-alias form ``local+suffix@domain`` → strip suffix and match primary
        """
        local_part, separator, domain_part = normalized_email.partition("@")
        if not separator or not local_part or not domain_part:
            raise ValueError(f"邮箱地址格式无效：{normalized_email}")
        if " " in normalized_email:
            raise ValueError(f"邮箱地址格式无效：{normalized_email}")

        primary_mailbox = self._session.scalar(
            select(Mailbox).where(Mailbox.primary_email == normalized_email)
        )
        if primary_mailbox is not None:
            return primary_mailbox.id, normalized_email, "primary"

        if "+" not in local_part:
            raise LeaseEmailNotFoundError("邮箱地址不可用或不属于当前调用方")

        base_local_part, _plus_marker, alias_suffix = local_part.partition("+")
        if not base_local_part or not alias_suffix:
            raise LeaseEmailNotFoundError("邮箱地址不可用或不属于当前调用方")
        if not all(character in PLUS_ALIAS_SUFFIX_ALPHABET for character in alias_suffix):
            raise ValueError("plus alias 后缀仅允许小写字母与数字")
        if len(alias_suffix) > 32:
            raise ValueError("plus alias 后缀最长 32 个字符")

        base_primary_email = f"{base_local_part}@{domain_part}"
        alias_mailbox = self._session.scalar(
            select(Mailbox).where(Mailbox.primary_email == base_primary_email)
        )
        if alias_mailbox is None:
            raise LeaseEmailNotFoundError("邮箱地址不可用或不属于当前调用方")
        return alias_mailbox.id, normalized_email, "plus_alias"

    def _client_has_mail_read_history(
        self,
        client_key_id: str,
        *,
        allocated_email: str,
    ) -> bool:
        """Return whether this Client Key previously held a mail_read lease for the address."""
        historical_lease_id = self._session.scalar(
            select(Lease.id)
            .where(
                Lease.client_key_id == client_key_id,
                Lease.allocated_email == allocated_email,
                Lease.mode == LeaseMode.MAIL_READ,
            )
            .limit(1)
        )
        return historical_lease_id is not None

    @staticmethod
    def _classify_address_kind(
        *,
        primary_email: str,
        allocated_email: str | None,
    ) -> str | None:
        """Classify allocated business address relative to the mailbox primary identity."""
        if allocated_email is None:
            return None
        normalized_allocated = allocated_email.strip().lower()
        normalized_primary = primary_email.strip().lower()
        if normalized_allocated == normalized_primary:
            return "primary"
        return "plus_alias"

    def _allocate_plus_alias(
        self,
        primary_email: str,
        *,
        preferred_alias_suffix: str | None = None,
    ) -> str:
        """Build a plus alias under the primary mailbox local-part."""
        local_part, separator, domain_part = primary_email.strip().partition("@")
        if not separator or not local_part or not domain_part:
            raise ValueError(f"主邮箱地址格式无效：{primary_email}")

        base_local_part = local_part.split("+", 1)[0]
        if preferred_alias_suffix is not None:
            normalized_suffix = preferred_alias_suffix.strip().lower()
            if not normalized_suffix:
                raise ValueError("alias_suffix 不能为空")
            if not all(character in PLUS_ALIAS_SUFFIX_ALPHABET for character in normalized_suffix):
                raise ValueError("alias_suffix 仅允许小写字母与数字")
            if len(normalized_suffix) > 32:
                raise ValueError("alias_suffix 最长 32 个字符")
            candidate_email = f"{base_local_part}+{normalized_suffix}@{domain_part.lower()}"
            # Explicit suffixes must honor the same uniqueness guard as random ones so two
            # concurrent leases cannot claim the same allocated address.
            if self._is_allocated_email_in_use(candidate_email):
                raise LeaseUnavailableError("该 plus alias 地址已被占用")
            return candidate_email

        for _attempt in range(MAX_PLUS_ALIAS_GENERATION_ATTEMPTS):
            random_suffix = "".join(
                secrets.choice(PLUS_ALIAS_SUFFIX_ALPHABET)
                for _index in range(DEFAULT_PLUS_ALIAS_SUFFIX_LENGTH)
            )
            candidate_email = f"{base_local_part}+{random_suffix}@{domain_part.lower()}"
            if not self._is_allocated_email_in_use(candidate_email):
                return candidate_email
        raise LeaseUnavailableError("无法生成可用的 plus alias 地址")

    def _is_allocated_email_in_use(self, allocated_email: str) -> bool:
        """Return whether an active lease already holds this allocated address."""
        sql_current_time = utc_now().replace(tzinfo=None)
        existing_lease_id = self._session.scalar(
            select(Lease.id).where(
                Lease.allocated_email == allocated_email.strip().lower(),
                Lease.released_at.is_(None),
                Lease.expires_at > sql_current_time,
            )
        )
        return existing_lease_id is not None

    def _write_audit_log(
        self,
        principal: ClientPrincipal,
        event_type: str,
        target_id: str,
        metadata: dict[str, object],
    ) -> None:
        self._session.add(
            AuditLog(
                actor_type="client",
                actor_id=principal.client_key_id,
                event_type=event_type,
                target_type="lease" if event_type.startswith("lease.") else "mailbox",
                target_id=target_id,
                metadata_json=metadata,
            )
        )

    @staticmethod
    def _is_expired(expires_at: datetime) -> bool:
        from mailbox_service.models import is_expired

        return is_expired(expires_at)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        from mailbox_service.models import ensure_utc

        return ensure_utc(value)


def hmac_compare(current_value: str, candidate_value: str) -> bool:
    """Compare credential values without data-dependent early exit."""
    import hmac

    return hmac.compare_digest(current_value, candidate_value)
