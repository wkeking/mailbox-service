"""Import replace_token must respect active lease claims by default (SEC-08)."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseService
from mailbox_service.main import import_mailboxes
from mailbox_service.models import LeaseMode, Mailbox
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.schemas import MailboxImportRequest
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class FakeOAuth:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="at", expires_in=3600)


def _build():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    key = urlsafe_b64encode(b"i" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=key,
        app_env="test",
    )
    cipher = CredentialCipher(key)
    access = MailboxAccessTokenService(session, settings, cipher, FakeOAuth(), session_factory=session_factory)
    return session, settings, cipher, ClientKeyService(session), LeaseService(session, cipher, access)


def test_import_replace_token_fails_on_active_claim_without_force() -> None:
    session, settings, cipher, client_keys, leases = _build()
    mailbox = Mailbox(
        primary_email="held@outlook.com",
        client_id="old-client",
        mail_password_ciphertext=cipher.encrypt("old-pass"),
        refresh_token_ciphertext=cipher.encrypt("old-rt"),
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="holder",
        scopes=["leases:acquire", "leases:release", "tokens:refresh:read"],
    )
    principal = client_keys.authenticate(created.api_key)
    leases.acquire_lease(principal, mode=LeaseMode.REFRESH_TOKEN, ttl_seconds=600)
    session.flush()

    result = import_mailboxes(
        MailboxImportRequest(
            content="held@outlook.com----new-pass----new-client----new-rt\n",
            on_conflict="replace_token",
            force_release_active_leases=False,
        ),
        session,
        settings,
        "admin-1",
    )
    assert result.updated == 0
    assert result.failed == 1
    assert "活跃租约" in result.errors[0].message
    session.refresh(mailbox)
    assert cipher.decrypt(mailbox.refresh_token_ciphertext or "") == "old-rt"


def test_import_replace_token_force_releases_claim() -> None:
    session, settings, cipher, client_keys, leases = _build()
    mailbox = Mailbox(
        primary_email="force@outlook.com",
        client_id="old-client",
        mail_password_ciphertext=cipher.encrypt("old-pass"),
        refresh_token_ciphertext=cipher.encrypt("old-rt"),
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="holder2",
        scopes=["leases:acquire", "leases:release", "tokens:refresh:read"],
    )
    principal = client_keys.authenticate(created.api_key)
    leases.acquire_lease(principal, mode=LeaseMode.REFRESH_TOKEN, ttl_seconds=600)
    session.flush()

    result = import_mailboxes(
        MailboxImportRequest(
            content="force@outlook.com----new-pass----new-client----new-rt\n",
            on_conflict="replace_token",
            force_release_active_leases=True,
        ),
        session,
        settings,
        "admin-1",
    )
    assert result.updated == 1
    assert result.failed == 0
    session.refresh(mailbox)
    assert cipher.decrypt(mailbox.refresh_token_ciphertext or "") == "new-rt"
