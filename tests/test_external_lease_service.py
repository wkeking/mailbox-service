"""Regression tests for external mailbox lease and token operations."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseNotFoundError, LeaseService, TokenVersionConflictError
from mailbox_service.models import LeaseMode, Mailbox, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class FakeMicrosoftOAuthClient:
    """OAuth test double used when a lease needs a refreshed Access Token."""

    def __init__(self) -> None:
        self.refresh_attempts: list[tuple[str, str]] = []

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
        self.refresh_attempts.append((mailbox.primary_email, refresh_token))
        return MicrosoftTokenResponse(access_token="new-access-token", expires_in=3600)


def create_lease_test_context() -> tuple[
    Session,
    CredentialCipher,
    FakeMicrosoftOAuthClient,
    ClientKeyService,
    LeaseService,
]:
    """Build an isolated lease service with deterministic credential encryption."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session = session_factory()
    encryption_key = urlsafe_b64encode(b"l" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        access_token_refresh_skew_seconds=120,
    )
    credential_cipher = CredentialCipher(encryption_key)
    oauth_client = FakeMicrosoftOAuthClient()
    access_token_service = MailboxAccessTokenService(session, settings, credential_cipher, oauth_client, session_factory=session_factory)
    client_key_service = ClientKeyService(session)
    lease_service = LeaseService(session, credential_cipher, access_token_service)
    return session, credential_cipher, oauth_client, client_key_service, lease_service


def test_refresh_token_lease_supports_owned_cas_update_and_idempotent_release() -> None:
    """A lease owner can rotate RT once; a stale version cannot overwrite the newer value."""
    session, credential_cipher, _, client_key_service, lease_service = create_lease_test_context()
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("old-refresh-token"),
        token_version=4,
    )
    session.add(mailbox)
    session.flush()
    creation_result = client_key_service.create_client_key(
        name="refresh-worker",
        scopes=["leases:acquire", "leases:release", "tokens:refresh:read", "tokens:refresh:write"],
    )
    principal = client_key_service.authenticate(creation_result.api_key)

    lease_result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.REFRESH_TOKEN,
        ttl_seconds=600,
    )

    assert lease_result.refresh_token == "old-refresh-token"
    assert lease_result.token_version == 4

    update_result = lease_service.update_refresh_token(
        principal,
        lease_result.lease_id,
        expected_token_version=4,
        refresh_token="new-refresh-token",
    )
    assert update_result.updated is True
    assert update_result.token_version == 5
    assert credential_cipher.decrypt(mailbox.refresh_token_ciphertext or "") == "new-refresh-token"

    try:
        lease_service.update_refresh_token(
            principal,
            lease_result.lease_id,
            expected_token_version=4,
            refresh_token="stale-refresh-token",
        )
    except TokenVersionConflictError:
        pass
    else:
        raise AssertionError("过期 token_version 必须触发 CAS 冲突")
    assert credential_cipher.decrypt(mailbox.refresh_token_ciphertext or "") == "new-refresh-token"

    first_release = lease_service.release_lease(principal, lease_result.lease_id)
    second_release = lease_service.release_lease(principal, lease_result.lease_id)
    assert first_release.released_at == second_release.released_at


def test_access_token_lease_returns_cached_token_and_rejects_other_client() -> None:
    """AT leases reuse valid cache and cannot be accessed by another Client Key."""
    session, credential_cipher, oauth_client, client_key_service, lease_service = create_lease_test_context()
    mailbox = Mailbox(
        primary_email="cached@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_source_version=1,
        access_token_expires_at=utc_now() + timedelta(minutes=20),
        access_token_refreshed_at=utc_now(),
    )
    session.add(mailbox)
    session.flush()
    owner_creation = client_key_service.create_client_key(
        name="access-owner",
        scopes=["leases:acquire", "leases:release", "tokens:access:read"],
    )
    other_creation = client_key_service.create_client_key(
        name="access-other",
        scopes=["tokens:access:read"],
    )
    owner = client_key_service.authenticate(owner_creation.api_key)
    other_client = client_key_service.authenticate(other_creation.api_key)

    lease_result = lease_service.acquire_lease(owner, mode=LeaseMode.ACCESS_TOKEN, ttl_seconds=600)
    token_result = lease_service.get_access_token(owner, lease_result.lease_id)

    assert token_result.access_token == "cached-access-token"
    assert token_result.refreshed is False
    assert oauth_client.refresh_attempts == []

    try:
        lease_service.get_access_token(other_client, lease_result.lease_id)
    except LeaseNotFoundError:
        pass
    else:
        raise AssertionError("其他 Client Key 不应读取不属于自己的租约")
