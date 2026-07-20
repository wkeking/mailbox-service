"""MySQL 8: ACCESS_TOKEN acquire must not hold business row locks across OAuth I/O."""

from __future__ import annotations

import threading
import time
import uuid

import pytest
from sqlalchemy import select, text

from mailbox_service.client_key_service import ClientKeyService, ClientPrincipal
from mailbox_service.config import Settings
from mailbox_service.lease_service import LeaseService
from mailbox_service.models import Lease, LeaseMode, Mailbox, MailboxLeaseClaim, MailboxStatus
from mailbox_service.proxy_service import MicrosoftOAuthError, MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


pytestmark = pytest.mark.mysql

JOIN_TIMEOUT_SECONDS = 20


class BlockingOAuthClient:
    """Blocks inside refresh so sibling transactions can probe row locks."""

    def __init__(self) -> None:
        self.call_count = 0
        self._lock = threading.Lock()
        self.refresh_started = threading.Event()
        self.allow_refresh_to_finish = threading.Event()

    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        with self._lock:
            self.call_count += 1
        self.refresh_started.set()
        if not self.allow_refresh_to_finish.wait(timeout=JOIN_TIMEOUT_SECONDS):
            raise TimeoutError("OAuth refresh was not released by the test")
        return MicrosoftTokenResponse(access_token="mysql-at-acquired", expires_in=3600)


class FailingOAuthClient:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        raise MicrosoftOAuthError("forced oauth failure for compensation test")


def _build_services(
    session,
    settings: Settings,
    cipher: CredentialCipher,
    oauth_client,
    session_factory,
) -> LeaseService:
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        session_factory=session_factory,
    )
    return LeaseService(
        session,
        cipher,
        access_token_service,
        session_factory=session_factory,
    )


def _seed_client_principal(session, *, name: str) -> ClientPrincipal:
    creation = ClientKeyService(session).create_client_key(
        name=name,
        scopes=[
            "leases:acquire",
            "leases:release",
            "tokens:access:read",
            "tokens:refresh:read",
            "tokens:refresh:write",
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


def test_access_token_network_holds_no_mailbox_row_lock(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Sibling transaction can FOR UPDATE the mailbox while OAuth is blocked."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    oauth_client = BlockingOAuthClient()
    unique_suffix = uuid.uuid4().hex[:12]

    setup_session = mysql_session_factory()
    try:
        principal = _seed_client_principal(setup_session, name=f"at-lock-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup_session,
            cipher,
            primary_email=f"at-lock-{unique_suffix}@example.com",
        )
        setup_session.commit()
        mailbox_id = mailbox.id
        principal_snapshot = principal
    finally:
        setup_session.close()

    outcomes: list[str] = []
    sibling_lock_acquired = threading.Event()

    def acquire_worker() -> None:
        worker_session = mysql_session_factory()
        try:
            worker_session.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
            lease_service = _build_services(
                worker_session,
                mysql_settings,
                cipher,
                oauth_client,
                mysql_session_factory,
            )
            result = lease_service.acquire_lease(
                principal_snapshot,
                mode=LeaseMode.ACCESS_TOKEN,
                ttl_seconds=600,
                preferred_email=f"at-lock-{unique_suffix}@example.com",
            )
            worker_session.commit()
            outcomes.append(f"success:{result.lease_id}")
        except Exception as error:  # noqa: BLE001
            worker_session.rollback()
            outcomes.append(f"error:{type(error).__name__}:{error}")
        finally:
            worker_session.close()

    def sibling_lock_worker() -> None:
        assert oauth_client.refresh_started.wait(timeout=JOIN_TIMEOUT_SECONDS)
        sibling_session = mysql_session_factory()
        try:
            sibling_session.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
            started_at = time.monotonic()
            locked = sibling_session.scalar(
                select(Mailbox).where(Mailbox.id == mailbox_id).with_for_update()
            )
            elapsed = time.monotonic() - started_at
            assert locked is not None
            # If the acquire request still held the mailbox lock, this would block ~2s then fail.
            assert elapsed < 1.0, f"sibling waited {elapsed:.3f}s for mailbox lock"
            sibling_lock_acquired.set()
            sibling_session.rollback()
        finally:
            sibling_session.close()

    acquire_thread = threading.Thread(target=acquire_worker)
    sibling_thread = threading.Thread(target=sibling_lock_worker)
    acquire_thread.start()
    sibling_thread.start()

    assert sibling_lock_acquired.wait(timeout=JOIN_TIMEOUT_SECONDS)
    oauth_client.allow_refresh_to_finish.set()
    acquire_thread.join(timeout=JOIN_TIMEOUT_SECONDS)
    sibling_thread.join(timeout=JOIN_TIMEOUT_SECONDS)
    assert not acquire_thread.is_alive()
    assert not sibling_thread.is_alive()
    assert outcomes and outcomes[0].startswith("success:")
    assert oauth_client.call_count == 1


def test_access_token_oauth_failure_releases_claim_without_ghost_lease(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Failed OAuth after reserve must compensate-release claim and lease."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    oauth_client = FailingOAuthClient()
    unique_suffix = uuid.uuid4().hex[:12]

    setup_session = mysql_session_factory()
    try:
        principal = _seed_client_principal(setup_session, name=f"at-fail-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup_session,
            cipher,
            primary_email=f"at-fail-{unique_suffix}@example.com",
        )
        setup_session.commit()
        mailbox_id = mailbox.id
        principal_snapshot = principal
    finally:
        setup_session.close()

    worker_session = mysql_session_factory()
    try:
        lease_service = _build_services(
            worker_session,
            mysql_settings,
            cipher,
            oauth_client,
            mysql_session_factory,
        )
        try:
            lease_service.acquire_lease(
                principal_snapshot,
                mode=LeaseMode.ACCESS_TOKEN,
                ttl_seconds=600,
                preferred_email=f"at-fail-{unique_suffix}@example.com",
            )
            raised = False
        except MicrosoftOAuthError:
            raised = True
            worker_session.rollback()
        assert raised
    finally:
        worker_session.close()

    verify_session = mysql_session_factory()
    try:
        claim = verify_session.get(MailboxLeaseClaim, mailbox_id)
        assert claim is None
        active_leases = list(
            verify_session.scalars(
                select(Lease).where(
                    Lease.mailbox_id == mailbox_id,
                    Lease.released_at.is_(None),
                )
            )
        )
        assert active_leases == []
        released = list(
            verify_session.scalars(
                select(Lease).where(
                    Lease.mailbox_id == mailbox_id,
                    Lease.released_at.is_not(None),
                )
            )
        )
        assert len(released) == 1
    finally:
        verify_session.close()
