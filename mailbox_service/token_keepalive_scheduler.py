"""Bounded single-instance scheduler that force-refreshes aging refresh tokens."""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from mailbox_service.capability_probe_service import (
    MailboxCapabilityProbeService,
    MicrosoftGraphMailProbeClient,
)
from mailbox_service.config import Settings
from mailbox_service.database import SessionFactory
from mailbox_service.proxy_service import EgressProxyService, MicrosoftIMAPClient, MicrosoftOAuthClient
from mailbox_service.security import CredentialCipher, summarize_exception
from mailbox_service.token_service import MailboxAccessTokenService

logger = logging.getLogger(__name__)


class RefreshTokenKeepaliveRunner:
    """Refresh mailboxes whose last OAuth refresh is approaching the configured RT lifetime."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def run_once(self) -> None:
        """Process one keepalive batch and commit or roll back as a single unit."""
        if not self._settings.refresh_token_keepalive_enabled:
            return
        if self._settings.credential_encryption_key is None:
            logger.warning("Refresh-token keepalive skipped: credential encryption key is not configured")
            return

        credential_cipher = CredentialCipher(self._settings.credential_encryption_key)
        with SessionFactory() as session:
            proxy_service = EgressProxyService(session, self._settings, credential_cipher)
            capability_prober = MailboxCapabilityProbeService(
                self._settings,
                MicrosoftIMAPClient(proxy_service, self._settings),
                MicrosoftGraphMailProbeClient(proxy_service, self._settings),
            )
            access_token_service = MailboxAccessTokenService(
                session,
                self._settings,
                credential_cipher,
                MicrosoftOAuthClient(proxy_service, self._settings),
                capability_prober=capability_prober,
            )
            try:
                result = access_token_service.run_refresh_token_keepalive_batch()
                session.commit()
            except Exception as error:  # noqa: BLE001 - scheduler must not crash the process.
                session.rollback()
                logger.error(
                    "Refresh-token keepalive batch failed: %s",
                    summarize_exception(error),
                )
                return

        if result.successful or result.failed:
            logger.info(
                "Refresh-token keepalive finished successful=%s failed=%s",
                result.successful,
                result.failed,
            )
            for item in result.results:
                if item.successful:
                    continue
                logger.warning(
                    "Refresh-token keepalive failed mailbox_id=%s primary_email=%s error=%s",
                    item.mailbox_id,
                    item.primary_email,
                    item.error_summary,
                )


def start_refresh_token_keepalive_scheduler(settings: Settings) -> BackgroundScheduler | None:
    """Start the process-local RT keepalive job when enabled."""
    if not settings.refresh_token_keepalive_enabled:
        return None

    scheduler = BackgroundScheduler(timezone="UTC")
    runner = RefreshTokenKeepaliveRunner(settings)
    scheduler.add_job(
        runner.run_once,
        trigger="interval",
        seconds=settings.refresh_token_keepalive_interval_seconds,
        id="refresh-token-keepalive",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    return scheduler
