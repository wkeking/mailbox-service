"""Mailbox access-token cache and refresh orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import logging
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from mailbox_service.access_token_scopes import extract_oauth_scopes_from_access_token
from mailbox_service.capability_probe_service import (
    MailboxCapabilityProberProtocol,
    apply_capability_probe_result,
)
from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, MailboxStatus, utc_now
from mailbox_service.proxy_service import MicrosoftInvalidGrantError, MicrosoftOAuthError, MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher, summarize_exception


token_diagnostic_logger = logging.getLogger("uvicorn.error")


def build_token_diagnostic_summary(token: str | None) -> str:
    """Return a comparison-friendly Token summary without exposing the full credential."""
    if token is None:
        return "present=false"

    token_length = len(token)
    masked_token = "<redacted>"
    if token_length > 12:
        masked_token = f"{token[:4]}...{token[-4:]}"
    token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return (
        f"present=true mask={masked_token} length={token_length} "
        f"sha256={token_fingerprint}"
    )


class MicrosoftOAuthClientProtocol(Protocol):
    """Minimal protocol shared by the real OAuth client and test doubles."""

    def refresh_access_token(self, mailbox: Mailbox, refresh_token: str) -> MicrosoftTokenResponse:
        """Return a Microsoft token response for one mailbox refresh token."""


@dataclass(frozen=True)
class MailboxAccessTokenResult:
    """Access-token result returned by the internal token cache service."""

    mailbox_id: str
    primary_email: str
    access_token: str
    expires_at: datetime
    token_version: int
    refreshed: bool
    refresh_token_rotated: bool


@dataclass(frozen=True)
class MailboxAccessTokenRefreshItem:
    """One mailbox result in an administrative batch AT refresh operation."""

    mailbox_id: str
    primary_email: str | None
    successful: bool
    refreshed: bool
    refresh_token_rotated: bool
    access_token_expires_at: datetime | None
    error_summary: str | None = None


@dataclass(frozen=True)
class MailboxAccessTokenRefreshResult:
    """Batch AT refresh result safe for admin UI display."""

    successful: int
    failed: int
    results: list[MailboxAccessTokenRefreshItem]


class MailboxAccessTokenService:
    """Provide cached access tokens and force-refresh batches without exposing RT values."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        credential_cipher: CredentialCipher,
        oauth_client: MicrosoftOAuthClientProtocol,
        capability_prober: MailboxCapabilityProberProtocol | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._oauth_client = oauth_client
        self._capability_prober = capability_prober

    def ensure_access_token(self, mailbox_id: str, *, force_refresh: bool = False) -> MailboxAccessTokenResult:
        """Return a usable AT, refreshing only when absent, stale, or explicitly forced."""
        mailbox = self._load_mailbox(mailbox_id)
        if not force_refresh and self._has_usable_cached_access_token(mailbox):
            cached_access_token = self._credential_cipher.decrypt(mailbox.access_token_ciphertext or "")
            self._persist_scope_if_missing(mailbox, cached_access_token)
            self._probe_capability_if_needed(mailbox, cached_access_token, force_refresh=False)
            return MailboxAccessTokenResult(
                mailbox_id=mailbox.id,
                primary_email=mailbox.primary_email,
                access_token=cached_access_token,
                expires_at=mailbox.access_token_expires_at,
                token_version=mailbox.token_version,
                refreshed=False,
                refresh_token_rotated=False,
            )

        if not mailbox.client_id:
            raise MicrosoftOAuthError("邮箱缺少 Client ID，无法刷新 access token")
        if not mailbox.refresh_token_ciphertext:
            raise MicrosoftOAuthError("邮箱缺少 refresh token，无法刷新 access token")

        refresh_token = self._credential_cipher.decrypt(mailbox.refresh_token_ciphertext)
        previous_access_token, previous_access_token_summary = (
            self._read_previous_access_token_for_diagnostics(mailbox)
        )
        if self._settings.token_diagnostic_logging_enabled:
            token_diagnostic_logger.info(
                "development_token_refresh_request mailbox_id=%s primary_email=%s "
                "old_refresh_token=(%s) old_access_token=(%s)",
                mailbox.id,
                mailbox.primary_email,
                build_token_diagnostic_summary(refresh_token),
                previous_access_token_summary,
            )

        refresh_started_at = utc_now()
        try:
            token_response = self._oauth_client.refresh_access_token(mailbox, refresh_token)
        except MicrosoftInvalidGrantError:
            mailbox.status = MailboxStatus.INVALID
            raise

        effective_refresh_token = token_response.rotated_refresh_token or refresh_token
        refresh_token_rotated = bool(
            token_response.rotated_refresh_token and token_response.rotated_refresh_token != refresh_token
        )
        if self._settings.token_diagnostic_logging_enabled:
            token_diagnostic_logger.info(
                "development_token_refresh_response mailbox_id=%s primary_email=%s "
                "old_refresh_token=(%s) returned_refresh_token=(%s) "
                "effective_refresh_token=(%s) refresh_token_changed=%s "
                "old_access_token=(%s) new_access_token=(%s) access_token_changed=%s "
                "expires_in_seconds=%s",
                mailbox.id,
                mailbox.primary_email,
                build_token_diagnostic_summary(refresh_token),
                build_token_diagnostic_summary(token_response.rotated_refresh_token),
                build_token_diagnostic_summary(effective_refresh_token),
                str(refresh_token_rotated).lower(),
                previous_access_token_summary,
                build_token_diagnostic_summary(token_response.access_token),
                str(previous_access_token != token_response.access_token).lower(),
                token_response.expires_in,
            )

        if refresh_token_rotated:
            mailbox.refresh_token_ciphertext = self._credential_cipher.encrypt(token_response.rotated_refresh_token or "")
            mailbox.token_version += 1

        expires_at = refresh_started_at + timedelta(seconds=token_response.expires_in)
        mailbox.access_token_ciphertext = self._credential_cipher.encrypt(token_response.access_token)
        mailbox.access_token_expires_at = expires_at
        mailbox.access_token_refreshed_at = refresh_started_at
        mailbox.scope = token_response.scope or extract_oauth_scopes_from_access_token(token_response.access_token)
        mailbox.updated_at = refresh_started_at
        self._session.flush()
        self._probe_capability_if_needed(mailbox, token_response.access_token, force_refresh=True)
        return MailboxAccessTokenResult(
            mailbox_id=mailbox.id,
            primary_email=mailbox.primary_email,
            access_token=token_response.access_token,
            expires_at=expires_at,
            token_version=mailbox.token_version,
            refreshed=True,
            refresh_token_rotated=refresh_token_rotated,
        )

    def refresh_access_tokens(self, mailbox_ids: list[str] | None = None) -> MailboxAccessTokenRefreshResult:
        """Force-refresh selected mailboxes or all active mailboxes and keep per-row failures.

        Refreshing through Microsoft's token endpoint updates the cached access token and
        also persists a rotated refresh token whenever Microsoft returns one.
        """
        target_mailbox_ids = (
            list(dict.fromkeys(mailbox_ids)) if mailbox_ids else self._load_all_active_mailbox_ids()
        )
        if self._settings.token_diagnostic_logging_enabled:
            token_diagnostic_logger.info(
                "development_token_batch_refresh_started mailbox_count=%s",
                len(target_mailbox_ids),
            )
        results: list[MailboxAccessTokenRefreshItem] = []
        successful_count = 0
        failed_count = 0

        for mailbox_id in target_mailbox_ids:
            try:
                access_token_result = self.ensure_access_token(mailbox_id, force_refresh=True)
            except Exception as error:  # noqa: BLE001 - batch processing must preserve later rows.
                failed_count += 1
                mailbox = self._session.get(Mailbox, mailbox_id)
                results.append(
                    MailboxAccessTokenRefreshItem(
                        mailbox_id=mailbox_id,
                        primary_email=mailbox.primary_email if mailbox is not None else None,
                        successful=False,
                        refreshed=False,
                        refresh_token_rotated=False,
                        access_token_expires_at=None,
                        error_summary=self._safe_error_summary(error),
                    )
                )
                continue

            successful_count += 1
            results.append(
                MailboxAccessTokenRefreshItem(
                    mailbox_id=access_token_result.mailbox_id,
                    primary_email=access_token_result.primary_email,
                    successful=True,
                    refreshed=access_token_result.refreshed,
                    refresh_token_rotated=access_token_result.refresh_token_rotated,
                    access_token_expires_at=access_token_result.expires_at,
                )
            )

        if self._settings.token_diagnostic_logging_enabled:
            token_diagnostic_logger.info(
                "development_token_batch_refresh_completed successful=%s failed=%s",
                successful_count,
                failed_count,
            )
        return MailboxAccessTokenRefreshResult(successful=successful_count, failed=failed_count, results=results)

    def _read_previous_access_token_for_diagnostics(self, mailbox: Mailbox) -> tuple[str | None, str]:
        """Read the previous AT only when diagnostics are enabled without blocking refreshes."""
        if not self._settings.token_diagnostic_logging_enabled:
            return None, "diagnostics=disabled"
        if not mailbox.access_token_ciphertext:
            return None, "present=false"

        try:
            access_token = self._credential_cipher.decrypt(mailbox.access_token_ciphertext)
        except Exception as error:  # noqa: BLE001 - diagnostics must not break Token refreshes.
            return None, f"present=true readable=false error_type={type(error).__name__}"
        return access_token, build_token_diagnostic_summary(access_token)

    def _load_mailbox(self, mailbox_id: str) -> Mailbox:
        mailbox = self._session.scalar(select(Mailbox).where(Mailbox.id == mailbox_id).with_for_update())
        if mailbox is None:
            raise LookupError("邮箱不存在")
        return mailbox

    def _load_all_active_mailbox_ids(self) -> list[str]:
        return list(
            self._session.scalars(
                select(Mailbox.id).where(Mailbox.status == MailboxStatus.ACTIVE).order_by(Mailbox.primary_email.asc())
            )
        )

    def _has_usable_cached_access_token(self, mailbox: Mailbox) -> bool:
        if not mailbox.access_token_ciphertext or mailbox.access_token_expires_at is None:
            return False
        refresh_deadline = utc_now() + timedelta(seconds=self._settings.access_token_refresh_skew_seconds)
        access_token_expires_at = mailbox.access_token_expires_at
        if access_token_expires_at.tzinfo is None and refresh_deadline.tzinfo is not None:
            refresh_deadline = refresh_deadline.replace(tzinfo=None)
        return access_token_expires_at > refresh_deadline

    def _persist_scope_if_missing(self, mailbox: Mailbox, access_token: str) -> None:
        """Backfill scope from a cached AT when the mailbox has never been classified."""
        if mailbox.scope:
            return
        decoded_scope = extract_oauth_scopes_from_access_token(access_token)
        if decoded_scope is None:
            return
        mailbox.scope = decoded_scope
        mailbox.updated_at = utc_now()
        self._session.flush()

    def _probe_capability_if_needed(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        force_refresh: bool,
    ) -> None:
        """Run prefer-by-scope IMAP/Graph probes when capability is unknown or AT just refreshed."""
        if self._capability_prober is None:
            return
        if mailbox.capability is not None and not force_refresh:
            return
        probe_result = self._capability_prober.probe_mailbox_capability(mailbox, access_token)
        apply_capability_probe_result(mailbox, probe_result)
        self._session.flush()

    @staticmethod
    def _safe_error_summary(error: Exception) -> str:
        if isinstance(error, MicrosoftOAuthError):
            return str(error)
        if isinstance(error, LookupError):
            return str(error)
        return summarize_exception(error)
