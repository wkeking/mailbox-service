"""MySQL 8 interleaving matrix: late release, reacquire, RT CAS, force-delete style cleanup."""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, text

from mailbox_service.client_key_service import ClientKeyService, ClientPrincipal
from mailbox_service.config import Settings
from mailbox_service.lease_service import LeaseService, TokenVersionConflictError
from mailbox_service.models import (
    Lease,
    LeaseMode,
    Mailbox,
    MailboxCapability,
    MailboxLeaseClaim,
    MailboxStatus,
    utc_now,
)
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


pytestmark = pytest.mark.mysql


class NoopOAuthClient:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="unused", expires_in=3600)


def _build_lease_service(session, settings: Settings, cipher: CredentialCipher, session_factory) -> LeaseService:
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        NoopOAuthClient(),
        session_factory=session_factory,
    )
    return LeaseService(
        session,
        cipher,
        access_token_service,
        session_factory=session_factory,
    )


def _seed_principal(session, *, name: str, scopes: list[str] | None = None) -> ClientPrincipal:
    creation = ClientKeyService(session).create_client_key(
        name=name,
        scopes=scopes
        or [
            "leases:acquire",
            "leases:release",
            "tokens:refresh:read",
            "tokens:refresh:write",
            "tokens:access:read",
            "mailboxes:acquire",
            "mailboxes:reacquire",
        ],
    )
    session.flush()
    return ClientKeyService(session).authenticate(creation.api_key)


def _seed_mailbox(session, cipher: CredentialCipher, *, primary_email: str) -> Mailbox:
    mailbox = Mailbox(
        primary_email=primary_email,
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token-v1"),
        token_version=1,
        capability=MailboxCapability.GRAPH,
    )
    session.add(mailbox)
    session.flush()
    return mailbox


def test_late_release_does_not_delete_successor_claim(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Release of lease-1 must not remove claim that now points at lease-2."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    unique_suffix = uuid.uuid4().hex[:12]
    setup = mysql_session_factory()
    try:
        principal = _seed_principal(setup, name=f"late-rel-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup,
            cipher,
            primary_email=f"late-rel-{unique_suffix}@example.com",
        )
        setup.commit()
        mailbox_id = mailbox.id
        principal_snapshot = principal
    finally:
        setup.close()

    session_a = mysql_session_factory()
    try:
        lease_service_a = _build_lease_service(session_a, mysql_settings, cipher, mysql_session_factory)
        first = lease_service_a.acquire_lease(
            principal_snapshot,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=f"late-rel-{unique_suffix}@example.com",
        )
        session_a.commit()
        first_lease_id = first.lease_id
        assert first.mailbox_id == mailbox_id
    finally:
        session_a.close()

    # Expire first lease + claim without releasing, then install successor claim via acquire.
    expire_session = mysql_session_factory()
    try:
        past = utc_now() - timedelta(minutes=5)
        past_naive = past.replace(tzinfo=None) if past.tzinfo else past
        lease_row = expire_session.get(Lease, first_lease_id)
        assert lease_row is not None
        lease_row.expires_at = past_naive
        claim_row = expire_session.get(MailboxLeaseClaim, mailbox_id)
        assert claim_row is not None
        claim_row.expires_at = past_naive
        expire_session.commit()
    finally:
        expire_session.close()

    session_b = mysql_session_factory()
    try:
        lease_service_b = _build_lease_service(session_b, mysql_settings, cipher, mysql_session_factory)
        second = lease_service_b.acquire_lease(
            principal_snapshot,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=f"late-rel-{unique_suffix}@example.com",
        )
        session_b.commit()
        second_lease_id = second.lease_id
        assert second.mailbox_id == mailbox_id
    finally:
        session_b.close()

    assert first_lease_id != second_lease_id

    # Late release of first lease must be idempotent and must not drop successor claim.
    release_session = mysql_session_factory()
    try:
        release_service = _build_lease_service(
            release_session, mysql_settings, cipher, mysql_session_factory
        )
        release_service.release_lease(principal_snapshot, first_lease_id)
        release_session.commit()
    finally:
        release_session.close()

    verify = mysql_session_factory()
    try:
        claim = verify.get(MailboxLeaseClaim, mailbox_id)
        assert claim is not None
        assert claim.lease_id == second_lease_id
        first_lease = verify.get(Lease, first_lease_id)
        assert first_lease is not None
        assert first_lease.released_at is not None
        second_lease = verify.get(Lease, second_lease_id)
        assert second_lease is not None
        assert second_lease.released_at is None
    finally:
        verify.close()


def test_stale_rt_cas_cannot_overwrite_newer_version(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    unique_suffix = uuid.uuid4().hex[:12]
    setup = mysql_session_factory()
    try:
        principal = _seed_principal(setup, name=f"rt-cas-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup,
            cipher,
            primary_email=f"rt-cas-{unique_suffix}@example.com",
        )
        setup.commit()
        principal_snapshot = principal
    finally:
        setup.close()

    session = mysql_session_factory()
    try:
        lease_service = _build_lease_service(session, mysql_settings, cipher, mysql_session_factory)
        preferred_email = f"rt-cas-{unique_suffix}@example.com"
        lease_result = lease_service.acquire_lease(
            principal_snapshot,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=preferred_email,
        )
        session.commit()
        lease_id = lease_result.lease_id
        assert lease_result.token_version == 1
        assert lease_result.primary_email == preferred_email

        updated = lease_service.update_refresh_token(
            principal_snapshot,
            lease_id,
            expected_token_version=1,
            refresh_token="refresh-token-v2",
        )
        session.commit()
        assert updated.updated is True
        assert updated.token_version == 2

        try:
            lease_service.update_refresh_token(
                principal_snapshot,
                lease_id,
                expected_token_version=1,
                refresh_token="stale-should-fail",
            )
            session.commit()
            raised = False
        except TokenVersionConflictError:
            session.rollback()
            raised = True
        assert raised

        stored = session.scalar(select(Mailbox).where(Mailbox.primary_email == preferred_email))
        assert stored is not None
        assert stored.token_version == 2
        assert cipher.decrypt(stored.refresh_token_ciphertext or "") == "refresh-token-v2"
    finally:
        session.close()


def test_concurrent_release_and_reacquire_mailbox_first(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Release and reacquire interleaved under Mailbox-first lock order without hang."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    unique_suffix = uuid.uuid4().hex[:12]
    setup = mysql_session_factory()
    try:
        principal = _seed_principal(setup, name=f"rel-rea-{unique_suffix}")
        mailbox = _seed_mailbox(
            setup,
            cipher,
            primary_email=f"rel-rea-{unique_suffix}@example.com",
        )
        # Seed a prior mail_read history so reacquire is authorized.
        history = Lease(
            mailbox_id=mailbox.id,
            client_key_id=principal.client_key_id,
            mode=LeaseMode.MAIL_READ,
            allocated_email=mailbox.primary_email,
            expires_at=utc_now() - timedelta(hours=1),
            released_at=utc_now() - timedelta(hours=1),
            created_at=utc_now() - timedelta(hours=2),
        )
        setup.add(history)
        setup.commit()
        mailbox_id = mailbox.id
        principal_snapshot = principal
        primary_email = mailbox.primary_email
    finally:
        setup.close()

    session = mysql_session_factory()
    try:
        lease_service = _build_lease_service(session, mysql_settings, cipher, mysql_session_factory)
        active = lease_service.acquire_lease(
            principal_snapshot,
            mode=LeaseMode.REFRESH_TOKEN,
            ttl_seconds=600,
            preferred_email=primary_email,
        )
        session.commit()
        lease_id = active.lease_id
        assert active.mailbox_id == mailbox_id
    finally:
        session.close()

    errors: list[str] = []
    barrier = threading.Barrier(2)

    def release_worker() -> None:
        worker = mysql_session_factory()
        try:
            worker.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
            service = _build_lease_service(worker, mysql_settings, cipher, mysql_session_factory)
            barrier.wait(timeout=10)
            service.release_lease(principal_snapshot, lease_id)
            worker.commit()
        except Exception as error:  # noqa: BLE001
            worker.rollback()
            errors.append(f"release:{type(error).__name__}:{error}")
        finally:
            worker.close()

    def reacquire_worker() -> None:
        worker = mysql_session_factory()
        try:
            worker.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
            service = _build_lease_service(worker, mysql_settings, cipher, mysql_session_factory)
            barrier.wait(timeout=10)
            # May race with release: either busy or success after release.
            try:
                service.reacquire_lease_by_email(
                    principal_snapshot,
                    email=primary_email,
                    ttl_seconds=600,
                )
                worker.commit()
            except Exception as error:  # noqa: BLE001
                worker.rollback()
                # Busy while RT lease still holds claim is acceptable interleaving.
                errors.append(f"reacquire:{type(error).__name__}:{error}")
        finally:
            worker.close()

    threads = [
        threading.Thread(target=release_worker),
        threading.Thread(target=reacquire_worker),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()

    # Release must succeed; reacquire may fail as busy if it ran first — no deadlock errors.
    assert not any("1205" in item or "1213" in item or "Deadlock" in item for item in errors)
    assert not any(item.startswith("release:") for item in errors)

    verify = mysql_session_factory()
    try:
        released = verify.get(Lease, lease_id)
        assert released is not None
        assert released.released_at is not None
        claim = verify.get(MailboxLeaseClaim, mailbox_id)
        if claim is not None:
            assert claim.lease_id != lease_id
    finally:
        verify.close()
