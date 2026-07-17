"""Mailbox access-token cache and refresh orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import logging
from typing import Protocol

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session

from mailbox_service.access_token_scopes import extract_oauth_scopes_from_access_token
from mailbox_service.capability_probe_service import (
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

    def ensure_access_token_in_short_transaction(
        self,
        mailbox_id: str,
        *,
        force_refresh: bool = False,
    ) -> MailboxAccessTokenResult:
        """Force-refresh or return AT using a dedicated session that commits immediately.

        Used by long-running verification-code polling so mailbox/proxy row locks are not
        held across sleep intervals in the request-scoped transaction.
        """
        with self._session_factory() as session:
            worker_service = self._build_worker_access_token_service(session)
            try:
                result = worker_service.ensure_access_token(mailbox_id, force_refresh=force_refresh)
                session.commit()
                return result
            except Exception:
                session.rollback()
                raise

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
            mailbox.updated_at = utc_now()
            self._session.flush()
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

    def list_mailbox_ids_due_for_refresh_token_keepalive(self, *, batch_size: int) -> list[str]:
        """Select active mailboxes whose last successful OAuth refresh is older than the keepalive threshold.

        Microsoft personal / work accounts typically receive refresh tokens that remain usable for
        about 90 days unless revoked. This service tracks the last successful token endpoint call in
        ``access_token_refreshed_at`` and refreshes early by ``refresh_token_keepalive_lead_days``.
        Mailboxes holding an active lease are skipped to avoid rotating RT while a client still holds
        an older refresh_token mode lease credential.
        """
        lifetime_days = self._settings.refresh_token_lifetime_days
        lead_days = min(self._settings.refresh_token_keepalive_lead_days, lifetime_days)
        due_before = utc_now() - timedelta(days=max(lifetime_days - lead_days, 0))
        due_before_naive = due_before.replace(tzinfo=None)

        current_time = utc_now()
        sql_current_time = current_time.replace(tzinfo=None)
        active_lease_exists = exists(
            select(Lease.id).where(
                Lease.mailbox_id == Mailbox.id,
                Lease.released_at.is_(None),
                Lease.expires_at > sql_current_time,
            )
        )
        # Prefer access_token_refreshed_at; fall back to created_at for never-refreshed imports.
        last_refresh_expression = func.coalesce(Mailbox.access_token_refreshed_at, Mailbox.created_at)
        return list(
            self._session.scalars(
                select(Mailbox.id)
                .where(
                    Mailbox.status == MailboxStatus.ACTIVE,
                    Mailbox.client_id.is_not(None),
                    Mailbox.refresh_token_ciphertext.is_not(None),
                    ~active_lease_exists,
                    last_refresh_expression <= due_before_naive,
                )
                .order_by(last_refresh_expression.asc(), Mailbox.primary_email.asc())
                .limit(batch_size)
            )
        )

    def run_refresh_token_keepalive_batch(self) -> MailboxAccessTokenRefreshResult:
        """Force-refresh due mailboxes so RT sliding lifetime is extended before expiry."""
        due_mailbox_ids = self.list_mailbox_ids_due_for_refresh_token_keepalive(
            batch_size=self._settings.refresh_token_keepalive_batch_size
        )
        if not due_mailbox_ids:
            return MailboxAccessTokenRefreshResult(successful=0, failed=0, results=[])
        return self.refresh_access_tokens(due_mailbox_ids)

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
        worker_count = max(1, min(available_proxy_count, len(target_mailbox_ids) or 1))
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

        if worker_count == 1 or len(mailbox_ids) <= 1:
            for mailbox_id in mailbox_ids:
                results_by_mailbox_id[mailbox_id] = self._refresh_single_mailbox_in_worker_session(mailbox_id)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_by_mailbox_id = {
                    executor.submit(self._refresh_single_mailbox_in_worker_session, mailbox_id): mailbox_id
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
        """Open a dedicated session, force-refresh one mailbox, and commit the worker transaction."""
        with self._session_factory() as session:
            worker_service = self._build_worker_access_token_service(session)
            try:
                access_token_result = worker_service.ensure_access_token(mailbox_id, force_refresh=True)
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
                session.rollback()
                mailbox = session.get(Mailbox, mailbox_id)
                # Persist invalid_grant status after rollback (ensure_access_token only dirties the row).
                if isinstance(error, MicrosoftInvalidGrantError) and mailbox is not None:
                    mailbox.status = MailboxStatus.INVALID
                    mailbox.updated_at = utc_now()
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
            proxy_service = EgressProxyService(session, self._settings, self._credential_cipher)
            capability_prober = MailboxCapabilityProbeService(
                self._settings,
                MicrosoftIMAPClient(proxy_service, self._settings),
                MicrosoftGraphMailProbeClient(proxy_service, self._settings),
            )
            oauth_client: MicrosoftOAuthClientProtocol = MicrosoftOAuthClient(proxy_service, self._settings)
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
