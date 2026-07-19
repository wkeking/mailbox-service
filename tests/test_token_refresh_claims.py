"""Token refresh claim / single-flight / CAS finalize tests."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta
import threading
import time

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import Mailbox, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class BlockingOAuthClient:
    """OAuth double that blocks until allowed, for single-flight interleaving."""

    def __init__(self, response: MicrosoftTokenResponse) -> None:
        self.response = response
        self.refresh_started = threading.Event()
        self.allow_refresh_to_finish = threading.Event()
        self.call_count = 0
        self._lock = threading.Lock()

    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        with self._lock:
            self.call_count += 1
        self.refresh_started.set()
        self.allow_refresh_to_finish.wait(timeout=5)
        return self.response


def _build_context(oauth_client):
    database_engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session = session_factory()
    encryption_key = urlsafe_b64encode(b"c" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        app_env="test",
        token_refresh_claim_ttl_seconds=30,
    )
    cipher = CredentialCipher(encryption_key)
    service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        session_factory=session_factory,
    )
    return session, cipher, service, session_factory


def test_stale_refresh_cannot_overwrite_external_cas() -> None:
    """A late finalize for an old claim must not overwrite a newer RT revision."""
    oauth_client = BlockingOAuthClient(
        MicrosoftTokenResponse(
            access_token="stale-access-token",
            expires_in=3600,
            rotated_refresh_token="stale-rotated-rt",
        )
    )
    session, cipher, service, session_factory = _build_context(oauth_client)
    mailbox = Mailbox(
        primary_email="race@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("original-rt"),
        token_version=4,
    )
    session.add(mailbox)
    session.commit()
    mailbox_id = mailbox.id

    errors: list[BaseException] = []

    def run_refresh() -> None:
        worker_session = session_factory()
        try:
            worker_service = MailboxAccessTokenService(
                worker_session,
                service._settings,
                cipher,
                oauth_client,
                session_factory=session_factory,
            )
            worker_service.ensure_access_token(mailbox_id, force_refresh=True)
            worker_session.commit()
        except BaseException as error:  # noqa: BLE001
            errors.append(error)
            worker_session.rollback()
        finally:
            worker_session.close()

    worker = threading.Thread(target=run_refresh)
    worker.start()
    assert oauth_client.refresh_started.wait(timeout=2)

    # Concurrent admin-style CAS: bump to v5 with a newer RT while refresh is in-flight.
    from mailbox_service.token_repository import compare_and_swap_refresh_token

    admin_session = session_factory()
    try:
        now = utc_now()
        compare_and_swap_refresh_token(
            admin_session,
            mailbox_id=mailbox_id,
            expected_token_version=4,
            encrypted_refresh_token=cipher.encrypt("admin-newer-rt"),
            refresh_token_updated_at=now,
            refresh_token_expires_at=now + timedelta(days=90),
        )
        admin_session.commit()
    finally:
        admin_session.close()

    oauth_client.allow_refresh_to_finish.set()
    worker.join(timeout=5)
    assert not worker.is_alive()

    session.expire_all()
    final_mailbox = session.get(Mailbox, mailbox_id)
    assert final_mailbox is not None
    assert final_mailbox.token_version == 5
    assert cipher.decrypt(final_mailbox.refresh_token_ciphertext or "") == "admin-newer-rt"
    # Stale OAuth response must not land as winner AT/RT.
    if final_mailbox.access_token_ciphertext:
        assert cipher.decrypt(final_mailbox.access_token_ciphertext) != "stale-access-token"


def test_two_concurrent_refreshers_only_one_oauth_call() -> None:
    """After claim is committed, a second refresher must not open another OAuth call."""
    oauth_client = BlockingOAuthClient(
        MicrosoftTokenResponse(access_token="winner-at", expires_in=3600)
    )
    session, cipher, service, session_factory = _build_context(oauth_client)
    mailbox = Mailbox(
        primary_email="singleflight@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=1,
    )
    session.add(mailbox)
    session.commit()
    mailbox_id = mailbox.id

    results: list[object] = []
    errors: list[BaseException] = []

    def run_refresh() -> None:
        worker_session = session_factory()
        try:
            worker_service = MailboxAccessTokenService(
                worker_session,
                service._settings,
                cipher,
                oauth_client,
                session_factory=session_factory,
            )
            result = worker_service.ensure_access_token(mailbox_id, force_refresh=True)
            worker_session.commit()
            results.append(result)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)
            worker_session.rollback()
        finally:
            worker_session.close()

    first = threading.Thread(target=run_refresh)
    first.start()
    # Wait until Phase A claim is committed and Phase B has entered OAuth.
    assert oauth_client.refresh_started.wait(timeout=2)
    assert oauth_client.call_count == 1

    second = threading.Thread(target=run_refresh)
    second.start()
    second.join(timeout=5)
    assert not second.is_alive()
    # Second path must observe the live claim and not call Microsoft again.
    assert oauth_client.call_count == 1
    assert len(errors) == 1
    assert "正在刷新" in str(errors[0]) or "refresh" in str(errors[0]).lower()

    oauth_client.allow_refresh_to_finish.set()
    first.join(timeout=5)
    assert not first.is_alive()
    assert len(results) == 1
