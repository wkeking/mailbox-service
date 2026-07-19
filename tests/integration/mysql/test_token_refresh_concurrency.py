"""MySQL concurrency tests for token refresh claim/CAS (SEC-02)."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import select

from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


pytestmark = pytest.mark.mysql


class CountingOAuthClient:
    def __init__(self, response: MicrosoftTokenResponse) -> None:
        self.response = response
        self.call_count = 0
        self._lock = threading.Lock()
        self.started = threading.Event()
        self.release = threading.Event()

    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        with self._lock:
            self.call_count += 1
        self.started.set()
        self.release.wait(timeout=5)
        return self.response


def test_two_threads_refresh_same_mailbox_single_oauth(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """After claim is committed, a second refresher must not open another OAuth call."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    oauth_client = CountingOAuthClient(
        MicrosoftTokenResponse(access_token="mysql-at", expires_in=3600)
    )
    session = mysql_session_factory()
    mailbox = Mailbox(
        primary_email=f"mysql-race-{utc_now().timestamp()}@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=1,
    )
    session.add(mailbox)
    session.commit()
    mailbox_id = mailbox.id
    session.close()

    results: list[str] = []
    errors: list[str] = []

    def run_refresh() -> None:
        worker_session = mysql_session_factory()
        try:
            service = MailboxAccessTokenService(
                worker_session,
                mysql_settings,
                cipher,
                oauth_client,
                session_factory=mysql_session_factory,
            )
            service.ensure_access_token(mailbox_id, force_refresh=True)
            worker_session.commit()
            results.append("ok")
        except Exception as error:  # noqa: BLE001
            errors.append(f"{type(error).__name__}:{error}")
            worker_session.rollback()
        finally:
            worker_session.close()

    first = threading.Thread(target=run_refresh)
    first.start()
    assert oauth_client.started.wait(timeout=5)
    assert oauth_client.call_count == 1

    second = threading.Thread(target=run_refresh)
    second.start()
    second.join(timeout=10)
    assert not second.is_alive()
    assert oauth_client.call_count == 1
    assert len(errors) == 1
    assert "正在刷新" in errors[0] or "RefreshAlreadyClaimed" in errors[0] or "refresh" in errors[0].lower()

    oauth_client.release.set()
    first.join(timeout=10)
    assert not first.is_alive()
    assert results == ["ok"]

    verify_session = mysql_session_factory()
    try:
        stored = verify_session.scalar(select(Mailbox).where(Mailbox.id == mailbox_id))
        assert stored is not None
        assert stored.access_token_source_version == stored.token_version
        assert stored.token_refresh_claim_id is None
    finally:
        verify_session.close()
