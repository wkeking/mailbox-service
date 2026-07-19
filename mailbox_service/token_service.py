"""Mailbox access-token cache and refresh orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import logging
from types import SimpleNamespace
from typing import Protocol

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from mailbox_service.access_token_scopes import (
    MailAccessChannel,
    cached_token_matches_mail_channel,
    extract_oauth_scopes_from_access_token,
    resolve_oauth_refresh_scope_for_channel,
)
from mailbox_service.capability_probe_service import (
    CapabilityProbeResult,
    MailboxCapabilityProbeService,
    MailboxCapabilityProberProtocol,
    MicrosoftGraphMailProbeClient,
    apply_capability_probe_result,
)
from mailbox_service.config import Settings
from mailbox_service.database import SessionFactory
from mailbox_service.models import (
    EgressProxy,
    EgressProxyStatus,
    Lease,
    Mailbox,
    MailboxCapability,
    MailboxStatus,
    utc_now,
)
from mailbox_service.proxy_service import (
    EgressProxyService,
    MicrosoftIMAPClient,
    MicrosoftInvalidGrantError,
    MicrosoftOAuthClient,
    MicrosoftOAuthError,
    MicrosoftTokenResponse,
)
from mailbox_service.security import CredentialCipher, summarize_exception
from mailbox_service.token_repository import (
    ActiveRefreshTokenLeaseError,
    RefreshAlreadyClaimedError,
    TokenRefreshClaim,
    TokenVersionConflictError as RepoTokenVersionConflictError,
    claim_token_refresh,
    complete_token_refresh,
    fail_token_refresh_invalid_grant,
    release_token_refresh_claim,
)

token_diagnostic_logger = logging.getLogger("uvicorn.error")

# Process-wide budget so concurrent admin batch requests cannot each open full worker pools.
import threading
_BATCH_WORKER_SEMAPHORE: threading.Semaphore | None = None
_BATCH_WORKER_SEMAPHORE_LOCK = threading.Lock()


def _get_batch_worker_semaphore(max_workers: int) -> threading.Semaphore:
    global _BATCH_WORKER_SEMAPHORE
    with _BATCH_WORKER_SEMAPHORE_LOCK:
        if _BATCH_WORKER_SEMAPHORE is None:
            _BATCH_WORKER_SEMAPHORE = threading.Semaphore(max_workers)
        return _BATCH_WORKER_SEMAPHORE



def stamp_refresh_token_lifetime(
    mailbox: Mailbox,
    *,
    lifetime_days: int,
    touched_at: datetime | None = None,
) -> datetime:
    """Record RT updated/expiry times after a successful OAuth refresh or RT write.

    Microsoft identity platform typically uses a sliding refresh-token lifetime (about 90 days
    for non-SPA flows). This service estimates expiry as ``touched_at + lifetime_days`` and
    rewrites both timestamps whenever the RT is written or successfully used to obtain a new AT.
    """
    effective_touched_at = touched_at or utc_now()
    mailbox.refresh_token_updated_at = effective_touched_at
    mailbox.refresh_token_expires_at = effective_touched_at + timedelta(days=lifetime_days)
    return effective_touched_at


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

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
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

@dataclass(frozen=True)
class MailboxUnprobedRefreshResult:
    """Batch result for probing mailboxes that still lack a known usable capability."""

    candidate_total: int
    processed: int
    successful: int
    failed: int
    remaining_candidates: int
    batch_size: int
    worker_count: int
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
        session_factory=SessionFactory,
    ) -> None:
        self._session = session
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._oauth_client = oauth_client
        self._capability_prober = capability_prober
        # Worker threads must open independent sessions; injectable for unit tests.
        self._session_factory = session_factory

    @property
    def refresh_token_lifetime_days(self) -> int:
        """Configured sliding lifetime used when stamping RT updated/expiry timestamps."""
        return self._settings.refresh_token_lifetime_days

    def _uses_independent_short_units(self) -> bool:
        """Whether claim/cache/probe should open independent Sessions.

        Production injects the process-wide ``SessionFactory``. Unit tests inject a private
        sessionmaker over SQLite StaticPool and share uncommitted rows with the request
        session — those paths must keep working on ``self._session``.
        """
        return self._session_factory is SessionFactory

    def ensure_access_token_in_short_transaction(
        self,
        mailbox_id: str,
        *,
        force_refresh: bool = False,
        preferred_channel: MailAccessChannel | None = None,
        skip_active_rt_lease_check: bool = True,
    ) -> MailboxAccessTokenResult:
        """Force-refresh or return AT using independent short transactions for claim/CAS."""
        return self._ensure_access_token_with_claim(
            mailbox_id,
            force_refresh=force_refresh,
            preferred_channel=preferred_channel,
            skip_active_rt_lease_check=skip_active_rt_lease_check,
            stale_retry_allowed=True,
            use_short_units=True,
        )

    def ensure_access_token(
        self,
        mailbox_id: str,
        *,
        force_refresh: bool = False,
        preferred_channel: MailAccessChannel | None = None,
        skip_active_rt_lease_check: bool = True,
    ) -> MailboxAccessTokenResult:
        """Return a usable AT using claim -> network -> CAS finalize (SEC-02).

        Production uses independent short Units of Work so row locks are not held across
        Microsoft network I/O. Test doubles with a private session factory stay on the
        caller Session so uncommitted fixtures remain visible.
        """
        return self._ensure_access_token_with_claim(
            mailbox_id,
            force_refresh=force_refresh,
            preferred_channel=preferred_channel,
            skip_active_rt_lease_check=skip_active_rt_lease_check,
            stale_retry_allowed=True,
            use_short_units=self._uses_independent_short_units(),
        )

    def _ensure_access_token_with_claim(
        self,
        mailbox_id: str,
        *,
        force_refresh: bool,
        preferred_channel: MailAccessChannel | None,
        skip_active_rt_lease_check: bool,
        stale_retry_allowed: bool,
        use_short_units: bool,
    ) -> MailboxAccessTokenResult:
        def _cache_hit(session: Session) -> MailboxAccessTokenResult | None:
            """Return usable cached AT with pure reads only — no probe/flush/network.

            Capability probing and scope backfill flush must not run on a long-lived request
            Session: those UPDATE row locks would be held until the HTTP request ends, and
            concurrent proxy resolve FOR UPDATE would hit MySQL 1205 during IMAP/Graph I/O.
            """
            service = self._bind_session(session)
            mailbox = service._load_mailbox(mailbox_id)
            target_channel = service._resolve_preferred_mail_channel(mailbox, preferred_channel)
            if force_refresh or not service._has_usable_cached_access_token(mailbox):
                return None
            if not mailbox.scope:
                # Avoid flushing scope onto the caller's transaction; decode for audience check only.
                decoded_scope = extract_oauth_scopes_from_access_token(
                    service._credential_cipher.decrypt(mailbox.access_token_ciphertext or "")
                )
                if target_channel is not None and not cached_token_matches_mail_channel(
                    decoded_scope, target_channel
                ):
                    return None
            elif target_channel is not None and not cached_token_matches_mail_channel(
                mailbox.scope, target_channel
            ):
                return None
            cached_access_token = service._credential_cipher.decrypt(
                mailbox.access_token_ciphertext or ""
            )
            return MailboxAccessTokenResult(
                mailbox_id=mailbox.id,
                primary_email=mailbox.primary_email,
                access_token=cached_access_token,
                expires_at=mailbox.access_token_expires_at,
                token_version=mailbox.token_version,
                refreshed=False,
                refresh_token_rotated=False,
            )

        # Fast cache path: prefer a short independent Session so request Session stays clean.
        if not force_refresh:
            if use_short_units:
                with self._session_factory() as cache_session:
                    try:
                        cached = _cache_hit(cache_session)
                        # Scope backfill / first-time capability probe must finish inside this short
                        # transaction — never leave dirty state on the HTTP request Session.
                        if cached is not None:
                            service = self._bind_session(cache_session)
                            mailbox = service._load_mailbox(mailbox_id)
                            if not mailbox.scope:
                                service._persist_scope_if_missing(mailbox, cached.access_token)
                            if mailbox.capability is None:
                                probed_token = service._probe_capability_if_needed(
                                    mailbox,
                                    cached.access_token,
                                    force_refresh=False,
                                )
                                cache_session.commit()
                                self._session.expire_all()
                                return MailboxAccessTokenResult(
                                    mailbox_id=cached.mailbox_id,
                                    primary_email=cached.primary_email,
                                    access_token=probed_token,
                                    expires_at=cached.expires_at,
                                    token_version=cached.token_version,
                                    refreshed=False,
                                    refresh_token_rotated=False,
                                )
                            if cache_session.new or cache_session.dirty or cache_session.deleted:
                                cache_session.commit()
                                self._session.expire_all()
                            else:
                                cache_session.rollback()
                            return cached
                        cache_session.rollback()
                    except Exception:
                        cache_session.rollback()
                        raise
            else:
                cached = _cache_hit(self._session)
                if cached is not None:
                    # Inline-session callers (tests) may still probe/flush on the shared session.
                    service = self._bind_session(self._session)
                    mailbox = service._load_mailbox(mailbox_id)
                    service._persist_scope_if_missing(mailbox, cached.access_token)
                    if mailbox.capability is None:
                        probed_token = service._probe_capability_if_needed(
                            mailbox,
                            cached.access_token,
                            force_refresh=False,
                        )
                        return MailboxAccessTokenResult(
                            mailbox_id=cached.mailbox_id,
                            primary_email=cached.primary_email,
                            access_token=probed_token,
                            expires_at=cached.expires_at,
                            token_version=cached.token_version,
                            refreshed=False,
                            refresh_token_rotated=False,
                        )
                    return cached

        # --- Phase A: claim in a short transaction (or caller session) ---
        claim: TokenRefreshClaim | None = None
        target_channel: MailAccessChannel | None = None
        refresh_scope: str | None = None

        def _phase_a(session: Session) -> TokenRefreshClaim | MailboxAccessTokenResult:
            service = self._bind_session(session)
            mailbox = service._load_mailbox(mailbox_id)
            nonlocal target_channel, refresh_scope
            target_channel = service._resolve_preferred_mail_channel(mailbox, preferred_channel)
            refresh_scope = resolve_oauth_refresh_scope_for_channel(target_channel)
            if not force_refresh and service._has_usable_cached_access_token(mailbox):
                # Pure cache return inside Phase A — no probe/network while claim txn is open.
                cached_access_token = service._credential_cipher.decrypt(
                    mailbox.access_token_ciphertext or ""
                )
                scope_for_check = mailbox.scope
                if not scope_for_check:
                    scope_for_check = extract_oauth_scopes_from_access_token(cached_access_token)
                if target_channel is None or cached_token_matches_mail_channel(
                    scope_for_check, target_channel
                ):
                    return MailboxAccessTokenResult(
                        mailbox_id=mailbox.id,
                        primary_email=mailbox.primary_email,
                        access_token=cached_access_token,
                        expires_at=mailbox.access_token_expires_at,
                        token_version=mailbox.token_version,
                        refreshed=False,
                        refresh_token_rotated=False,
                    )
            try:
                return claim_token_refresh(
                    session,
                    mailbox_id=mailbox_id,
                    decrypt_refresh_token=self._credential_cipher.decrypt,
                    claim_ttl_seconds=self._settings.token_refresh_claim_ttl_seconds,
                    skip_active_rt_lease_check=skip_active_rt_lease_check,
                )
            except RefreshAlreadyClaimedError as error:
                winner = service._read_winner_access_token_if_usable(
                    mailbox_id,
                    preferred_channel=preferred_channel,
                )
                if winner is not None:
                    return winner
                raise MicrosoftOAuthError("邮箱 access token 正在刷新，请稍后重试") from error
            except ActiveRefreshTokenLeaseError as error:
                raise MicrosoftOAuthError(str(error)) from error
            except RuntimeError as error:
                raise MicrosoftOAuthError(str(error)) from error

        if use_short_units:
            with self._session_factory() as phase_a_session:
                try:
                    phase_a_result = _phase_a(phase_a_session)
                    phase_a_session.commit()
                except Exception:
                    phase_a_session.rollback()
                    raise
        else:
            phase_a_result = _phase_a(self._session)
            self._session.flush()

        if isinstance(phase_a_result, MailboxAccessTokenResult):
            return phase_a_result
        claim = phase_a_result

        # --- Phase B: network without DB transaction ---
        oauth_mailbox = SimpleNamespace(
            id=claim.mailbox_id,
            primary_email=claim.primary_email,
            client_id=claim.client_id,
        )
        refresh_started_at = utc_now()
        if self._settings.token_diagnostic_logging_enabled:
            # Read diagnostics on the current Session only. Opening another Session against a
            # StaticPool / shared SQLite connection can roll back uncommitted claim rows.
            previous_access_summary = "present=false"
            previous_mailbox = self._session.get(Mailbox, claim.mailbox_id)
            if previous_mailbox is not None and previous_mailbox.access_token_ciphertext:
                try:
                    previous_access = self._credential_cipher.decrypt(
                        previous_mailbox.access_token_ciphertext
                    )
                    previous_access_summary = build_token_diagnostic_summary(previous_access)
                except Exception:  # noqa: BLE001
                    previous_access_summary = "present=true readable=false"
            token_diagnostic_logger.info(
                "development_token_refresh_request mailbox_id=%s primary_email=%s "
                "preferred_channel=%s refresh_scope=%s claim_id=%s expected_token_version=%s "
                "old_refresh_token=(%s) old_access_token=(%s)",
                claim.mailbox_id,
                claim.primary_email,
                target_channel or "default",
                refresh_scope or "default",
                claim.claim_id,
                claim.expected_token_version,
                build_token_diagnostic_summary(claim.refresh_token),
                previous_access_summary,
            )
        try:
            token_response = self._oauth_client.refresh_access_token(
                oauth_mailbox,  # type: ignore[arg-type]
                claim.refresh_token,
                scope=refresh_scope,
            )
        except MicrosoftInvalidGrantError as error:
            token_diagnostic_logger.warning(
                "access_token_refresh_invalid_grant mailbox_id=%s claim_id=%s error=%s",
                claim.mailbox_id,
                claim.claim_id,
                summarize_exception(error),
            )

            def _fail(session: Session) -> None:
                applied = fail_token_refresh_invalid_grant(session, claim=claim)
                if applied:
                    from mailbox_service.audit_service import write_audit_event

                    write_audit_event(
                        session,
                        actor_type="system",
                        actor_id=None,
                        event_type="mailbox.invalidated",
                        target_type="mailbox",
                        target_id=claim.mailbox_id,
                        operation_id=claim.claim_id,
                        metadata={
                            "reason": "invalid_grant",
                            "expected_token_version": claim.expected_token_version,
                            "claim_id": claim.claim_id,
                        },
                    )

            self._run_short_or_inline(use_short_units, _fail)
            raise
        except Exception as error:
            if isinstance(error, MicrosoftOAuthError):
                token_diagnostic_logger.warning(
                    "access_token_refresh_failed mailbox_id=%s claim_id=%s error=%s",
                    claim.mailbox_id,
                    claim.claim_id,
                    summarize_exception(error),
                )

            def _release(session: Session) -> None:
                release_token_refresh_claim(session, claim=claim)

            self._run_short_or_inline(use_short_units, _release)
            raise

        refresh_token_rotated = bool(
            token_response.rotated_refresh_token
            and token_response.rotated_refresh_token != claim.refresh_token
        )
        lifetime_days = self._settings.refresh_token_lifetime_days
        refresh_token_updated_at = refresh_started_at
        refresh_token_expires_at = refresh_started_at + timedelta(days=lifetime_days)
        encrypted_refresh_token = None
        if refresh_token_rotated:
            encrypted_refresh_token = self._credential_cipher.encrypt(
                token_response.rotated_refresh_token or ""
            )
        scope_value = token_response.scope or extract_oauth_scopes_from_access_token(
            token_response.access_token
        )
        expires_at = refresh_started_at + timedelta(seconds=token_response.expires_in)
        encrypted_access_token = self._credential_cipher.encrypt(token_response.access_token)

        if self._settings.token_diagnostic_logging_enabled:
            token_diagnostic_logger.info(
                "development_token_refresh_response mailbox_id=%s claim_id=%s "
                "old_refresh_token=(%s) returned_refresh_token=(%s) "
                "refresh_token_changed=%s new_access_token=(%s) "
                "access_token_changed=true expires_in_seconds=%s",
                claim.mailbox_id,
                claim.claim_id,
                build_token_diagnostic_summary(claim.refresh_token),
                build_token_diagnostic_summary(token_response.rotated_refresh_token),
                str(refresh_token_rotated).lower(),
                build_token_diagnostic_summary(token_response.access_token),
                token_response.expires_in,
            )

        # --- Phase C: CAS finalize ---
        def _phase_c(session: Session) -> int | None:
            return complete_token_refresh(
                session,
                claim=claim,
                encrypted_access_token=encrypted_access_token,
                access_token_expires_at=expires_at,
                access_token_refreshed_at=refresh_started_at,
                scope=scope_value,
                encrypted_refresh_token=encrypted_refresh_token,
                refresh_token_rotated=refresh_token_rotated,
                refresh_token_updated_at=refresh_token_updated_at,
                refresh_token_expires_at=refresh_token_expires_at,
            )

        if use_short_units:
            with self._session_factory() as phase_c_session:
                try:
                    new_token_version = _phase_c(phase_c_session)
                    if new_token_version is not None:
                        from mailbox_service.audit_service import write_audit_event

                        write_audit_event(
                            phase_c_session,
                            actor_type="system",
                            actor_id=None,
                            event_type="mailbox.token_refreshed",
                            target_type="mailbox",
                            target_id=claim.mailbox_id,
                            operation_id=claim.claim_id,
                            metadata={
                                "token_version": new_token_version,
                                "refresh_token_rotated": refresh_token_rotated,
                                "claim_id": claim.claim_id,
                            },
                        )
                    phase_c_session.commit()
                except Exception:
                    phase_c_session.rollback()
                    raise
        else:
            new_token_version = _phase_c(self._session)
            if new_token_version is not None:
                from mailbox_service.audit_service import write_audit_event

                write_audit_event(
                    self._session,
                    actor_type="system",
                    actor_id=None,
                    event_type="mailbox.token_refreshed",
                    target_type="mailbox",
                    target_id=claim.mailbox_id,
                    operation_id=claim.claim_id,
                    metadata={
                        "token_version": new_token_version,
                        "refresh_token_rotated": refresh_token_rotated,
                        "claim_id": claim.claim_id,
                    },
                )
            self._session.flush()

        if new_token_version is None:
            winner = self._read_winner_access_token_if_usable(
                mailbox_id,
                preferred_channel=preferred_channel,
            )
            if winner is not None:
                return winner
            if stale_retry_allowed:
                return self._ensure_access_token_with_claim(
                    mailbox_id,
                    force_refresh=True,
                    preferred_channel=preferred_channel,
                    skip_active_rt_lease_check=skip_active_rt_lease_check,
                    stale_retry_allowed=False,
                    use_short_units=use_short_units,
                )
            raise MicrosoftOAuthError("Token 刷新版本冲突，请重试")

        # Post-refresh capability probe must use its own short transaction — never the request
        # Session — so IMAP/Graph network I/O cannot leave UPDATE row locks open across the
        # verification-code long-poll HTTP request.
        effective_access_token = token_response.access_token
        result_expires_at = expires_at
        result_token_version = new_token_version
        result_primary_email = claim.primary_email

        def _post_refresh_probe_and_reload(session: Session) -> MailboxAccessTokenResult:
            service = self._bind_session(session)
            # Phase C bulk UPDATE can leave a stale identity-map entry; re-sync before probe.
            session.expire_all()
            mailbox = session.get(Mailbox, mailbox_id)
            if mailbox is None:
                raise LookupError("邮箱不存在")
            token_version_before_probe = mailbox.token_version
            if mailbox.access_token_ciphertext:
                local_access_token = service._credential_cipher.decrypt(mailbox.access_token_ciphertext)
            else:
                local_access_token = token_response.access_token
            should_run_probe = force_refresh or mailbox.capability is None
            if target_channel == "graph" and cached_token_matches_mail_channel(mailbox.scope, "graph"):
                if mailbox.capability is None:
                    should_run_probe = True
                else:
                    should_run_probe = force_refresh and preferred_channel is None
            if should_run_probe:
                local_access_token = service._probe_capability_if_needed(
                    mailbox,
                    local_access_token,
                    force_refresh=True,
                )
            local_expires = mailbox.access_token_expires_at or expires_at
            local_rotated = refresh_token_rotated
            if mailbox.token_version > token_version_before_probe:
                local_rotated = True
            return MailboxAccessTokenResult(
                mailbox_id=mailbox.id,
                primary_email=mailbox.primary_email,
                access_token=local_access_token,
                expires_at=local_expires,
                token_version=mailbox.token_version,
                refreshed=True,
                refresh_token_rotated=local_rotated,
            )

        if use_short_units:
            with self._session_factory() as probe_session:
                try:
                    return_value = _post_refresh_probe_and_reload(probe_session)
                    probe_session.commit()
                    return return_value
                except Exception:
                    probe_session.rollback()
                    raise

        # Inline path (unit tests / private session factory): probe on the same Session.
        return_value = _post_refresh_probe_and_reload(self._session)
        self._session.flush()
        return return_value

    def _bind_session(self, session: Session) -> MailboxAccessTokenService:
        """Return a service instance bound to ``session`` sharing clients and settings."""
        return MailboxAccessTokenService(
            session,
            self._settings,
            self._credential_cipher,
            self._oauth_client,
            capability_prober=self._capability_prober,
            session_factory=self._session_factory,
        )

    def _read_winner_access_token_if_usable(
        self,
        mailbox_id: str,
        *,
        preferred_channel: MailAccessChannel | None,
    ) -> MailboxAccessTokenResult | None:
        """Re-read mailbox without claiming; return cache when a concurrent winner finished."""
        try:
            mailbox = self._session.get(Mailbox, mailbox_id)
            if mailbox is None:
                return None
            try:
                self._session.refresh(mailbox)
            except Exception:  # noqa: BLE001 - identity may be stale after bulk UPDATE; re-get.
                self._session.expire_all()
                mailbox = self._session.get(Mailbox, mailbox_id)
                if mailbox is None:
                    return None
            if not self._has_usable_cached_access_token(mailbox):
                return None
            target_channel = self._resolve_preferred_mail_channel(mailbox, preferred_channel)
            if target_channel is not None and not cached_token_matches_mail_channel(
                mailbox.scope, target_channel
            ):
                return None
            if mailbox.access_token_expires_at is None or not mailbox.access_token_ciphertext:
                return None
            access_token = self._credential_cipher.decrypt(mailbox.access_token_ciphertext)
            return MailboxAccessTokenResult(
                mailbox_id=mailbox.id,
                primary_email=mailbox.primary_email,
                access_token=access_token,
                expires_at=mailbox.access_token_expires_at,
                token_version=mailbox.token_version,
                refreshed=False,
                refresh_token_rotated=False,
            )
        except Exception:  # noqa: BLE001 - concurrent winner path is best-effort.
            return None

    def _run_short_or_inline(self, use_short_units: bool, operation) -> None:
        if use_short_units:
            with self._session_factory() as session:
                try:
                    operation(session)
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
            return
        operation(self._session)
        self._session.flush()

    @staticmethod
    def _resolve_preferred_mail_channel(
        mailbox: Mailbox,
        preferred_channel: MailAccessChannel | None,
    ) -> MailAccessChannel | None:
        """Prefer an explicit channel, otherwise use a proven mailbox capability label."""
        if preferred_channel is not None:
            return preferred_channel
        if mailbox.capability == MailboxCapability.GRAPH:
            return "graph"
        if mailbox.capability == MailboxCapability.IMAP:
            return "imap"
        return None

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

    def list_mailbox_ids_due_for_refresh_token_keepalive(self, *, batch_size: int) -> list[str]:
        """Select active mailboxes whose stored RT is approaching or past estimated expiry.

        Keepalive uses ``refresh_token_expires_at`` (set on import and every successful OAuth
        refresh as ``updated_at + refresh_token_lifetime_days``). Rows whose expiry falls within
        ``refresh_token_keepalive_lead_days`` of now are refreshed early. Rows missing the new
        columns fall back to ``coalesce(access_token_refreshed_at, created_at) + lifetime`` so
        partially migrated data still participates.

        Mailboxes holding an active lease are skipped to avoid rotating RT while a client still
        holds an older refresh_token mode lease credential.
        """
        lifetime_days = self._settings.refresh_token_lifetime_days
        lead_days = min(self._settings.refresh_token_keepalive_lead_days, lifetime_days)

        current_time = utc_now()
        sql_current_time = current_time.replace(tzinfo=None)
        # Due when estimated RT expiry is at or before now + lead_days (already expired or soon).
        due_expiry_before = (current_time + timedelta(days=lead_days)).replace(tzinfo=None)
        # Portable fallback when refresh_token_expires_at is still NULL (pre-migration rows):
        # last_refresh + lifetime <= now + lead  <=>  last_refresh <= now - (lifetime - lead).
        legacy_last_refresh_due_before = (
            current_time - timedelta(days=max(lifetime_days - lead_days, 0))
        ).replace(tzinfo=None)

        active_lease_exists = exists(
            select(Lease.id).where(
                Lease.mailbox_id == Mailbox.id,
                Lease.released_at.is_(None),
                Lease.expires_at > sql_current_time,
            )
        )
        last_refresh_expression = func.coalesce(Mailbox.access_token_refreshed_at, Mailbox.created_at)
        is_due_by_refresh_token_expiry = and_(
            Mailbox.refresh_token_expires_at.is_not(None),
            Mailbox.refresh_token_expires_at <= due_expiry_before,
        )
        is_due_by_legacy_last_refresh = and_(
            Mailbox.refresh_token_expires_at.is_(None),
            last_refresh_expression <= legacy_last_refresh_due_before,
        )
        # Order soonest-expiring first; fall back to last refresh for legacy NULL expiry rows.
        order_by_expiry_expression = func.coalesce(
            Mailbox.refresh_token_expires_at,
            last_refresh_expression,
        )
        return list(
            self._session.scalars(
                select(Mailbox.id)
                .where(
                    Mailbox.status == MailboxStatus.ACTIVE,
                    Mailbox.client_id.is_not(None),
                    Mailbox.refresh_token_ciphertext.is_not(None),
                    ~active_lease_exists,
                    or_(is_due_by_refresh_token_expiry, is_due_by_legacy_last_refresh),
                )
                .order_by(order_by_expiry_expression.asc(), Mailbox.primary_email.asc())
                .limit(batch_size)
            )
        )

    def run_refresh_token_keepalive_batch(self) -> MailboxAccessTokenRefreshResult:
        """Force-refresh due mailboxes so RT sliding lifetime is extended before expiry.

        Background path re-checks active RT lease claims inside Token Phase A
        (``skip_active_rt_lease_check=False``).
        """
        due_mailbox_ids = self.list_mailbox_ids_due_for_refresh_token_keepalive(
            batch_size=self._settings.refresh_token_keepalive_batch_size
        )
        if not due_mailbox_ids:
            return MailboxAccessTokenRefreshResult(successful=0, failed=0, results=[])
        results: list[MailboxAccessTokenRefreshItem] = []
        successful_count = 0
        failed_count = 0
        for mailbox_id in due_mailbox_ids:
            try:
                access_token_result = self.ensure_access_token(
                    mailbox_id,
                    force_refresh=True,
                    skip_active_rt_lease_check=False,
                )
            except Exception as error:  # noqa: BLE001 - batch must continue later rows.
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
        return MailboxAccessTokenRefreshResult(
            successful=successful_count,
            failed=failed_count,
            results=results,
        )

    def _unprobed_or_unknown_capability_filter(self):
        """Select active mailboxes that still need RT validation / capability probing.

        Targets freshly imported rows (capability IS NULL) and previous probe outcomes that
        stayed at ``unknown`` because transport mixed with auth failures. Requires client_id
        and refresh_token so the force-refresh path can actually call Microsoft.
        """
        return (
            Mailbox.status == MailboxStatus.ACTIVE,
            Mailbox.client_id.is_not(None),
            Mailbox.refresh_token_ciphertext.is_not(None),
            (Mailbox.capability.is_(None)) | (Mailbox.capability == MailboxCapability.UNKNOWN),
        )

    def count_unprobed_or_unknown_mailbox_ids(self) -> int:
        """Return how many active mailboxes still need capability/RT recognition."""
        return int(
            self._session.scalar(
                select(func.count(Mailbox.id)).where(*self._unprobed_or_unknown_capability_filter())
            )
            or 0
        )

    def list_unprobed_or_unknown_mailbox_ids(self, *, batch_size: int) -> list[str]:
        """Return one batch of unprobed/unknown active mailbox IDs for administrative probing."""
        return list(
            self._session.scalars(
                select(Mailbox.id)
                .where(*self._unprobed_or_unknown_capability_filter())
                .order_by(Mailbox.created_at.asc(), Mailbox.primary_email.asc())
                .limit(batch_size)
            )
        )

    def count_available_egress_proxies(self) -> int:
        """Return how many egress proxies are currently eligible for outbound work.

        Used to size concurrent unprobed recognition workers so concurrency tracks the
        effective proxy pool instead of unbounded fan-out.
        """
        proxy_service = EgressProxyService(self._session, self._settings, self._credential_cipher)
        policy = proxy_service.ensure_policy()
        if not policy.enabled:
            return 1

        current_time = utc_now()
        available_proxy_count = int(
            self._session.scalar(
                select(func.count(EgressProxy.id))
                .where(EgressProxy.enabled.is_(True))
                .where(EgressProxy.protocol.in_(policy.allowed_protocols))
                .where(
                    (EgressProxy.status != EgressProxyStatus.COOLDOWN)
                    | (EgressProxy.cooldown_until.is_(None))
                    | (EgressProxy.cooldown_until <= current_time)
                )
            )
            or 0
        )
        if available_proxy_count > 0:
            return available_proxy_count
        # No healthy proxy members: keep a single worker for direct-routing or fail-fast paths.
        return 1

    def refresh_unprobed_or_unknown_access_tokens(self, *, batch_size: int = 1000) -> MailboxUnprobedRefreshResult:
        """Force-refresh one batch of unprobed/unknown mailboxes to classify usable vs invalid RT.

        Successful rows get a fresh AT and capability probe (imap/graph/unusable/unknown).
        ``invalid_grant`` failures mark the mailbox ``invalid`` inside ``ensure_access_token``.

        Concurrency is sized to the number of currently available egress proxies so that
        outbound Microsoft traffic roughly matches the healthy proxy pool. Each worker uses
        an independent database session because SQLAlchemy sessions are not thread-safe.
        """
        # Keep in sync with MailboxUnprobedRefreshRequest.batch_size (default 1000, max 5000).
        bounded_batch_size = max(1, min(batch_size, 5000))
        candidate_total = self.count_unprobed_or_unknown_mailbox_ids()
        target_mailbox_ids = self.list_unprobed_or_unknown_mailbox_ids(batch_size=bounded_batch_size)
        available_proxy_count = self.count_available_egress_proxies()
        item_count = len(target_mailbox_ids) or 1
        worker_count = max(
            1,
            min(
                self._settings.batch_max_workers,
                available_proxy_count,
                self._settings.database_worker_budget,
                item_count,
            ),
        )
        if not target_mailbox_ids:
            return MailboxUnprobedRefreshResult(
                candidate_total=candidate_total,
                processed=0,
                successful=0,
                failed=0,
                remaining_candidates=0,
                batch_size=bounded_batch_size,
                worker_count=worker_count,
                results=[],
            )

        # Flush pending request-local work before workers open independent sessions.
        self._session.flush()
        batch_result = self._refresh_access_tokens_with_worker_pool(
            target_mailbox_ids,
            max_workers=worker_count,
        )
        # Worker sessions commit independently; sync remaining counts from the database.
        self._session.commit()
        self._session.expire_all()
        remaining_candidates = self.count_unprobed_or_unknown_mailbox_ids()
        self._log_unprobed_batch_failure_summary(
            candidate_total=candidate_total,
            processed=len(target_mailbox_ids),
            successful=batch_result.successful,
            failed=batch_result.failed,
            remaining_candidates=remaining_candidates,
            batch_size=bounded_batch_size,
            worker_count=worker_count,
            available_proxy_count=available_proxy_count,
            results=batch_result.results,
        )
        return MailboxUnprobedRefreshResult(
            candidate_total=candidate_total,
            processed=len(target_mailbox_ids),
            successful=batch_result.successful,
            failed=batch_result.failed,
            remaining_candidates=remaining_candidates,
            batch_size=bounded_batch_size,
            worker_count=worker_count,
            results=batch_result.results,
        )

    def _log_unprobed_batch_failure_summary(
        self,
        *,
        candidate_total: int,
        processed: int,
        successful: int,
        failed: int,
        remaining_candidates: int,
        batch_size: int,
        worker_count: int,
        available_proxy_count: int,
        results: list[MailboxAccessTokenRefreshItem],
    ) -> None:
        """Emit an operator-visible failure breakdown; per-row errors are not logged by default."""
        failure_reason_counts: dict[str, int] = {}
        for item in results:
            if item.successful:
                continue
            reason = (item.error_summary or "").strip() or "识别失败（无 error_summary）"
            failure_reason_counts[reason] = failure_reason_counts.get(reason, 0) + 1

        top_failure_reasons = sorted(
            failure_reason_counts.items(),
            key=lambda pair: pair[1],
            reverse=True,
        )[:10]
        token_diagnostic_logger.info(
            "mailbox.unprobed_refresh completed candidate_total=%s processed=%s successful=%s "
            "failed=%s remaining=%s batch_size=%s worker_count=%s available_proxy_count=%s "
            "top_failure_reasons=%s",
            candidate_total,
            processed,
            successful,
            failed,
            remaining_candidates,
            batch_size,
            worker_count,
            available_proxy_count,
            top_failure_reasons,
        )

    def _refresh_access_tokens_with_worker_pool(
        self,
        mailbox_ids: list[str],
        *,
        max_workers: int,
    ) -> MailboxAccessTokenRefreshResult:
        """Refresh mailbox IDs with isolated worker sessions and a bounded thread pool.

        Always use per-mailbox sessions (even when ``max_workers=1``). The request-scoped
        session is unsafe for batch recognition because OAuth/IMAP now commit mid-flight to
        release proxy locks; continuing on the same request session can leave later rows in a
        half-committed / expired state and produce mass failures after the first success.
        """
        worker_count = max(1, max_workers)
        results_by_mailbox_id: dict[str, MailboxAccessTokenRefreshItem] = {}
        # Process-wide budget: concurrent admin batches share one semaphore of permits
        # equal to batch_max_workers, so total in-flight workers never exceed the config.
        batch_worker_semaphore = _get_batch_worker_semaphore(self._settings.batch_max_workers)

        def _refresh_with_global_budget(target_mailbox_id: str) -> MailboxAccessTokenRefreshItem:
            acquired = batch_worker_semaphore.acquire(timeout=30)
            if not acquired:
                return MailboxAccessTokenRefreshItem(
                    mailbox_id=target_mailbox_id,
                    primary_email=None,
                    successful=False,
                    refreshed=False,
                    refresh_token_rotated=False,
                    access_token_expires_at=None,
                    error_summary="batch concurrency budget exhausted",
                )
            try:
                return self._refresh_single_mailbox_in_worker_session(target_mailbox_id)
            finally:
                batch_worker_semaphore.release()

        if worker_count == 1 or len(mailbox_ids) <= 1:
            for mailbox_id in mailbox_ids:
                results_by_mailbox_id[mailbox_id] = _refresh_with_global_budget(mailbox_id)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_by_mailbox_id = {
                    executor.submit(_refresh_with_global_budget, mailbox_id): mailbox_id
                    for mailbox_id in mailbox_ids
                }
                for future in as_completed(future_by_mailbox_id):
                    mailbox_id = future_by_mailbox_id[future]
                    try:
                        results_by_mailbox_id[mailbox_id] = future.result()
                    except Exception as error:  # noqa: BLE001 - keep batch robust against worker crashes.
                        results_by_mailbox_id[mailbox_id] = MailboxAccessTokenRefreshItem(
                            mailbox_id=mailbox_id,
                            primary_email=None,
                            successful=False,
                            refreshed=False,
                            refresh_token_rotated=False,
                            access_token_expires_at=None,
                            error_summary=self._safe_error_summary(error),
                        )

        ordered_results = [results_by_mailbox_id[mailbox_id] for mailbox_id in mailbox_ids]
        successful_count = sum(1 for item in ordered_results if item.successful)
        failed_count = len(ordered_results) - successful_count
        return MailboxAccessTokenRefreshResult(
            successful=successful_count,
            failed=failed_count,
            results=ordered_results,
        )

    def _refresh_single_mailbox_in_worker_session(self, mailbox_id: str) -> MailboxAccessTokenRefreshItem:
        """Open a dedicated session, force-refresh one mailbox, and commit the worker transaction.

        ``ensure_access_token`` already applies invalid_grant through claim/version CAS and
        releases the claim on other failures. Workers must not bypass that path by force-writing
        ``status=INVALID`` after an arbitrary exception.
        """
        with self._session_factory() as session:
            worker_service = self._build_worker_access_token_service(session)
            try:
                access_token_result = worker_service.ensure_access_token(mailbox_id, force_refresh=True)
                session.commit()
                from mailbox_service.audit_service import write_audit_event

                # Item-level durable audit for successful batch refresh (SEC-11).
                write_audit_event(
                    session,
                    actor_type="system",
                    actor_id="batch_refresh",
                    event_type="mailbox.token_refresh_item",
                    target_type="mailbox",
                    target_id=access_token_result.mailbox_id,
                    metadata={
                        "successful": True,
                        "refreshed": access_token_result.refreshed,
                        "refresh_token_rotated": access_token_result.refresh_token_rotated,
                    },
                )
                session.commit()
                return MailboxAccessTokenRefreshItem(
                    mailbox_id=access_token_result.mailbox_id,
                    primary_email=access_token_result.primary_email,
                    successful=True,
                    refreshed=access_token_result.refreshed,
                    refresh_token_rotated=access_token_result.refresh_token_rotated,
                    access_token_expires_at=access_token_result.expires_at,
                )
            except Exception as error:  # noqa: BLE001 - per-mailbox isolation for the batch.
                # invalid_grant CAS may already have dirtied this Session (inline path) or
                # committed in a short unit. Preserve INVALID by committing when possible;
                # otherwise a blanket rollback undoes the status change (regression).
                if isinstance(error, MicrosoftInvalidGrantError):
                    try:
                        session.commit()
                    except Exception:  # noqa: BLE001
                        session.rollback()
                else:
                    session.rollback()
                mailbox = session.get(Mailbox, mailbox_id)
                from mailbox_service.audit_service import write_audit_event

                write_audit_event(
                    session,
                    actor_type="system",
                    actor_id="batch_refresh",
                    event_type="mailbox.token_refresh_item",
                    target_type="mailbox",
                    target_id=mailbox_id,
                    metadata={
                        "successful": False,
                        "error_class": type(error).__name__,
                        "invalid_grant": isinstance(error, MicrosoftInvalidGrantError),
                    },
                )
                session.commit()
                return MailboxAccessTokenRefreshItem(
                    mailbox_id=mailbox_id,
                    primary_email=mailbox.primary_email if mailbox is not None else None,
                    successful=False,
                    refreshed=False,
                    refresh_token_rotated=False,
                    access_token_expires_at=None,
                    error_summary=self._safe_error_summary(error),
                )

    def _build_worker_access_token_service(self, session: Session) -> MailboxAccessTokenService:
        """Construct a request-local AT service stack bound to a worker session.

        Production stacks rebuild OAuth/IMAP/Graph clients against the worker session so
        sticky proxy resolution uses that session's locks/commits. Unit tests inject fake
        OAuth/prober objects that must be reused instead of replaced by live Microsoft clients.
        """
        if isinstance(self._oauth_client, MicrosoftOAuthClient):
            proxy_service = EgressProxyService(
                session_factory=self._session_factory,
                settings=self._settings,
                credential_cipher=self._credential_cipher,
            )
            oauth_client: MicrosoftOAuthClientProtocol = MicrosoftOAuthClient(
                proxy_service, self._settings
            )
            capability_prober = MailboxCapabilityProbeService(
                self._settings,
                MicrosoftIMAPClient(proxy_service, self._settings),
                MicrosoftGraphMailProbeClient(proxy_service, self._settings),
                oauth_client=oauth_client,
            )
        else:
            oauth_client = self._oauth_client
            capability_prober = self._capability_prober
        return MailboxAccessTokenService(
            session,
            self._settings,
            self._credential_cipher,
            oauth_client,
            capability_prober=capability_prober,
            session_factory=self._session_factory,
        )

    def _has_usable_cached_access_token(self, mailbox: Mailbox) -> bool:
        if not mailbox.access_token_ciphertext or mailbox.access_token_expires_at is None:
            return False
        # AT must be bound to the current RT revision (SEC-02).
        if mailbox.access_token_source_version is None:
            return False
        if mailbox.access_token_source_version != mailbox.token_version:
            return False
        refresh_deadline = utc_now() + timedelta(seconds=self._settings.access_token_refresh_skew_seconds)
        access_token_expires_at = mailbox.access_token_expires_at
        from mailbox_service.models import ensure_utc
        access_token_expires_at = ensure_utc(access_token_expires_at)
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
    ) -> str:
        """Run prefer-by-scope IMAP/Graph probes when capability is unknown or AT just refreshed.

        When Graph re-audience succeeds during probing, persist the Graph-audience AT (and any
        rotated RT) so subsequent Graph mail reads use a usable token instead of the outlook default.

        Returns the access token that should be handed to callers after probing (possibly replaced).
        """
        if self._capability_prober is None:
            return access_token
        if mailbox.capability is not None and not force_refresh:
            return access_token
        refresh_token: str | None = None
        if mailbox.refresh_token_ciphertext:
            try:
                refresh_token = self._credential_cipher.decrypt(mailbox.refresh_token_ciphertext)
            except Exception:  # noqa: BLE001 - probe may proceed without re-audience if RT unreadable.
                refresh_token = None
        probe_result = self._capability_prober.probe_mailbox_capability(
            mailbox,
            access_token,
            refresh_token=refresh_token,
        )
        if probe_result.access_token_replacement is not None:
            self._apply_access_token_replacement(mailbox, probe_result)
            apply_capability_probe_result(mailbox, probe_result)
            self._session.flush()
            return probe_result.access_token_replacement.access_token

        apply_capability_probe_result(mailbox, probe_result)
        self._session.flush()
        return access_token

    def _apply_access_token_replacement(
        self,
        mailbox: Mailbox,
        probe_result: CapabilityProbeResult,
    ) -> None:
        """Persist Graph-audience AT/scope (and optional RT rotation) from a successful re-audience."""
        replacement = probe_result.access_token_replacement
        if replacement is None:
            return

        probed_at = utc_now()
        mailbox.access_token_ciphertext = self._credential_cipher.encrypt(replacement.access_token)
        mailbox.access_token_expires_at = probed_at + timedelta(seconds=replacement.expires_in)
        mailbox.access_token_refreshed_at = probed_at
        if replacement.scope:
            mailbox.scope = replacement.scope
        if replacement.rotated_refresh_token:
            current_refresh_token = (
                self._credential_cipher.decrypt(mailbox.refresh_token_ciphertext)
                if mailbox.refresh_token_ciphertext
                else None
            )
            if replacement.rotated_refresh_token != current_refresh_token:
                mailbox.refresh_token_ciphertext = self._credential_cipher.encrypt(
                    replacement.rotated_refresh_token
                )
                # Atomic DB increment after field writes; avoids lost concurrent updates.
                self._session.flush()
                from sqlalchemy import text as sql_text

                self._session.execute(
                    sql_text(
                        "UPDATE mailboxes SET token_version = token_version + 1 "
                        "WHERE id = :mailbox_id"
                    ),
                    {"mailbox_id": mailbox.id},
                )
                self._session.refresh(mailbox)
        mailbox.access_token_source_version = mailbox.token_version
        # Graph re-audience uses the RT; extend sliding RT lifetime whether or not it rotated.
        stamp_refresh_token_lifetime(
            mailbox,
            lifetime_days=self._settings.refresh_token_lifetime_days,
            touched_at=probed_at,
        )
        mailbox.updated_at = probed_at

    @staticmethod
    def _safe_error_summary(error: Exception) -> str:
        if isinstance(error, MicrosoftOAuthError):
            return str(error)
        if isinstance(error, LookupError):
            return str(error)
        return summarize_exception(error)
