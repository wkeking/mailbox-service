"""MySQL 8 concurrency tests for mailbox lease claims (SEC-07).

Acceptance from PLN / REQ:
- 32 threads race on one mailbox: exactly one success, no duplicate claim, no hang
- Late release of an expired lease must not delete a newer claim
"""

from __future__ import annotations

from datetime import timedelta
import threading
import time
import uuid

import pytest
from sqlalchemy import func, select, text, update

from mailbox_service.client_key_service import ClientKeyService, ClientPrincipal
from mailbox_service.config import Settings
from mailbox_service.lease_service import LeaseService, LeaseUnavailableError
from mailbox_service.models import (
    Lease,
    LeaseMode,
    Mailbox,
    MailboxLeaseClaim,
    MailboxStatus,
    ensure_utc,
    utc_now,
)
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


pytestmark = pytest.mark.mysql

THREAD_COUNT = 32
JOIN_TIMEOUT_SECONDS = 15


class NoopOAuthClient:
    """Lease RT mode tests never need Microsoft traffic."""

    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="unused", expires_in=3600)


def _build_lease_service(session, settings: Settings, cipher: CredentialCipher) -> LeaseService:
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=session.get_bind(), autoflush=False, expire_on_commit=False)
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        NoopOAuthClient(),
        session_factory=session_factory,
    )
    return LeaseService(session, cipher, access_token_service)


def _seed_client_principal(session, *, name: str) -> ClientPrincipal:
    creation = ClientKeyService(session).create_client_key(
        name=name,
        scopes=[
            "leases:acquire",
            "leases:release",
            "tokens:refresh:read",
            "tokens:refresh:write",
            "tokens:access:read",
        ],
    )
    session.flush()
    return ClientKeyService(session).authenticate(creation.api_key)


def _seed_mailbox(session, cipher: CredentialCipher, *, primary_email: str) -> Mailbox:
    mailbox = Mailbox(
        primary_email=primary_email,
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
        token_version=1,
    )
    session.add(mailbox)
    session.flush()
    return mailbox


def test_thirty_two_threads_claim_one_mailbox_exactly_once(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """32 concurrent acquires against one free mailbox: 1 winner, 31 unavailable."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    setup_session = mysql_session_factory()
    unique_suffix = uuid.uuid4().hex[:12]
    try:
        principal = _seed_client_principal(setup_session, name=f"lease-race-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup_session,
            cipher,
            primary_email=f"lease-race-{unique_suffix}@example.com",
        )
        setup_session.commit()
        mailbox_id = mailbox.id
        principal_snapshot = principal
    finally:
        setup_session.close()

    barrier = threading.Barrier(THREAD_COUNT)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()
    winners: list[str] = []

    def worker(worker_index: int) -> None:
        worker_session = mysql_session_factory()
        try:
            # Keep lock waits short so a deadlock/regression fails the test quickly.
            worker_session.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
            lease_service = _build_lease_service(worker_session, mysql_settings, cipher)
            barrier.wait(timeout=10)
            try:
                result = lease_service.acquire_lease(
                    principal_snapshot,
                    mode=LeaseMode.REFRESH_TOKEN,
                    ttl_seconds=600,
                    preferred_email=f"lease-race-{unique_suffix}@example.com",
                    client_tag=f"worker-{worker_index}",
                )
                worker_session.commit()
                with outcomes_lock:
                    outcomes.append("success")
                    winners.append(result.lease_id)
            except LeaseUnavailableError:
                worker_session.rollback()
                with outcomes_lock:
                    outcomes.append("unavailable")
            except Exception as error:  # noqa: BLE001 - surface unexpected races
                worker_session.rollback()
                with outcomes_lock:
                    outcomes.append(f"error:{type(error).__name__}:{error}")
        finally:
            worker_session.close()

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(THREAD_COUNT)]
    started_at = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=JOIN_TIMEOUT_SECONDS)
        assert not thread.is_alive(), "lease concurrency worker did not finish in time"
    elapsed_seconds = time.monotonic() - started_at
    assert elapsed_seconds < JOIN_TIMEOUT_SECONDS

    assert outcomes.count("success") == 1, outcomes
    assert outcomes.count("unavailable") == THREAD_COUNT - 1, outcomes
    assert not any(item.startswith("error:") for item in outcomes), outcomes
    assert len(winners) == 1

    verify_session = mysql_session_factory()
    try:
        claim_count = verify_session.scalar(select(func.count()).select_from(MailboxLeaseClaim))
        # Count claims for this mailbox only.
        mailbox_claim_count = verify_session.scalar(
            select(func.count())
            .select_from(MailboxLeaseClaim)
            .where(MailboxLeaseClaim.mailbox_id == mailbox_id)
        )
        assert mailbox_claim_count == 1

        claim = verify_session.scalar(
            select(MailboxLeaseClaim)
            .where(MailboxLeaseClaim.mailbox_id == mailbox_id)
            .limit(1)
        )
        assert claim is not None
        assert claim.lease_id == winners[0]
        assert claim.mode == LeaseMode.REFRESH_TOKEN

        active_lease_count = verify_session.scalar(
            select(func.count())
            .select_from(Lease)
            .where(
                Lease.mailbox_id == mailbox_id,
                Lease.released_at.is_(None),
                Lease.expires_at > utc_now().replace(tzinfo=None),
            )
        )
        assert active_lease_count == 1
        assert claim_count is not None  # schema present
    finally:
        verify_session.close()


def test_late_release_does_not_delete_successor_claim(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Expired Lease A late-release must keep Lease B claim intact."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    session = mysql_session_factory()
    unique_suffix = uuid.uuid4().hex[:12]
    try:
        principal = _seed_client_principal(session, name=f"late-release-{unique_suffix}")
        mailbox = _seed_mailbox(
            session,
            cipher,
            primary_email=f"late-release-{unique_suffix}@example.com",
        )
        session.commit()

        lease_service = _build_lease_service(session, mysql_settings, cipher)
        first = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=mailbox.primary_email,
        )
        session.commit()
        first_lease_id = first.lease_id
        mailbox_id = first.mailbox_id

        # Expire Lease A (and its claim) so the mailbox becomes free.
        past = utc_now() - timedelta(seconds=30)
        past_naive = past.replace(tzinfo=None)
        session.execute(
            update(Lease)
            .where(Lease.id == first_lease_id)
            .values(expires_at=past_naive)
        )
        session.execute(
            update(MailboxLeaseClaim)
            .where(
                MailboxLeaseClaim.mailbox_id == mailbox_id,
                MailboxLeaseClaim.lease_id == first_lease_id,
            )
            .values(expires_at=past_naive)
        )
        session.commit()

        second = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=mailbox.primary_email,
        )
        session.commit()
        second_lease_id = second.lease_id
        assert second_lease_id != first_lease_id

        claim_before_late_release = session.scalar(
            select(MailboxLeaseClaim)
            .where(MailboxLeaseClaim.mailbox_id == mailbox_id)
            .limit(1)
        )
        assert claim_before_late_release is not None
        assert claim_before_late_release.lease_id == second_lease_id

        # Late release of the expired first lease must not remove B's claim.
        late_release = lease_service.release_lease(principal, first_lease_id)
        session.commit()
        assert late_release.lease_id == first_lease_id

        claim_after = session.scalar(
            select(MailboxLeaseClaim)
            .where(MailboxLeaseClaim.mailbox_id == mailbox_id)
            .limit(1)
        )
        assert claim_after is not None
        assert claim_after.lease_id == second_lease_id

        second_lease = session.get(Lease, second_lease_id)
        assert second_lease is not None
        assert second_lease.released_at is None
        assert ensure_utc(second_lease.expires_at) > utc_now()
    finally:
        session.close()


def test_release_clears_matching_claim_only(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Normal release of the current owner clears the claim row."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    session = mysql_session_factory()
    unique_suffix = uuid.uuid4().hex[:12]
    try:
        principal = _seed_client_principal(session, name=f"release-claim-{unique_suffix}")
        mailbox = _seed_mailbox(
            session,
            cipher,
            primary_email=f"release-claim-{unique_suffix}@example.com",
        )
        session.commit()
        lease_service = _build_lease_service(session, mysql_settings, cipher)
        acquired = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=mailbox.primary_email,
        )
        session.commit()
        assert (
            session.scalar(
                select(MailboxLeaseClaim)
                .where(MailboxLeaseClaim.mailbox_id == acquired.mailbox_id)
                .limit(1)
            )
            is not None
        )

        lease_service.release_lease(principal, acquired.lease_id)
        session.commit()
        assert (
            session.scalar(
                select(MailboxLeaseClaim)
                .where(MailboxLeaseClaim.mailbox_id == acquired.mailbox_id)
                .limit(1)
            )
            is None
        )
    finally:
        session.close()
