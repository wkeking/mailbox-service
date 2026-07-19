"""Bounded cluster-coordinated health probes for global egress proxies."""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from mailbox_service.config import Settings
from mailbox_service.database import SessionFactory
from mailbox_service.models import EgressProxy
from mailbox_service.proxy_service import EgressProxyService, EgressProxyTransportError
from mailbox_service.scheduler_lease_repository import (
    ScheduledJobLeaseRepository,
    build_scheduler_owner_id,
)
from mailbox_service.security import CredentialCipher, summarize_exception

logger = logging.getLogger(__name__)


class ProxyHealthProbeRunner:
    """Run bounded proxy handshake checks without logging remote response contents."""

    def __init__(self, settings: Settings, batch_size: int = 20) -> None:
        self._settings = settings
        self._batch_size = batch_size
        self._owner_id = build_scheduler_owner_id()

    def run_once(self) -> None:
        """Probe enabled proxies only when this process holds the job lease."""
        with SessionFactory() as session:
            job_lease_repository = ScheduledJobLeaseRepository(session)
            job_handle = job_lease_repository.try_acquire(
                "egress-proxy-health-probe",
                self._owner_id,
                lease_seconds=self._settings.scheduler_job_lease_seconds,
            )
            if job_handle is None:
                session.rollback()
                logger.info("Egress proxy health probe skipped: another owner holds the job lease")
                return
            session.commit()

        try:
            with SessionFactory() as read_session:
                proxy_ids = list(
                    read_session.scalars(
                        select(EgressProxy.id)
                        .where(EgressProxy.enabled.is_(True))
                        .order_by(EgressProxy.priority.asc(), EgressProxy.id.asc())
                        .limit(self._batch_size)
                    )
                )
            for proxy_id in proxy_ids:
                self._probe_proxy(proxy_id)
        finally:
            try:
                with SessionFactory() as release_session:
                    ScheduledJobLeaseRepository(release_session).release(job_handle)
                    release_session.commit()
            except Exception:  # noqa: BLE001
                logger.warning("Egress proxy health probe job lease release failed")

    def _probe_proxy(self, proxy_id: str) -> None:
        """Isolate one probe failure so it cannot prevent later proxy checks."""
        credential_cipher = (
            CredentialCipher(self._settings.credential_encryption_key)
            if self._settings.credential_encryption_key is not None
            else None
        )
        with SessionFactory() as session:
            proxy_service = EgressProxyService(session, self._settings, credential_cipher)
            try:
                proxy_service.test_proxy_connectivity(proxy_id)
                session.commit()
            except EgressProxyTransportError as error:
                proxy_service.record_proxy_failure(proxy_id, error)
                session.commit()
                logger.warning(
                    "Egress proxy health probe failed for proxy_id=%s: %s",
                    proxy_id,
                    summarize_exception(error),
                )
            except Exception as error:
                session.rollback()
                logger.error(
                    "Egress proxy health probe could not run for proxy_id=%s: %s",
                    proxy_id,
                    summarize_exception(error),
                )


def start_proxy_health_scheduler(settings: Settings) -> BackgroundScheduler:
    """Start the process-local scheduler required by the single-instance topology."""
    scheduler = BackgroundScheduler(timezone="UTC")
    runner = ProxyHealthProbeRunner(settings)
    scheduler.add_job(
        runner.run_once,
        trigger="interval",
        seconds=settings.proxy_health_check_interval_seconds,
        id="egress-proxy-health-probe",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    return scheduler
