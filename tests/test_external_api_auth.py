"""HTTP-level tests for external and Admin authentication separation."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings, get_settings
from mailbox_service.database import Base, get_session
from mailbox_service.lease_service import LeaseService
from mailbox_service.main import app, get_access_token_service, get_lease_service
from mailbox_service.models import Mailbox, utc_now
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class UnexpectedOAuthClient:
    """Fail immediately if a test unexpectedly bypasses the cached Access Token."""

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ):
        raise AssertionError("有效 AT 缓存不应触发 OAuth 请求")


def test_external_api_uses_client_key_and_rejects_admin_token() -> None:
    """External and Admin authentication headers must never substitute for each other."""
    database_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session: Session = session_factory()
    encryption_key = urlsafe_b64encode(b"h" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        admin_api_token="admin-secret",
        credential_encryption_key=encryption_key,
    )
    credential_cipher = CredentialCipher(encryption_key)
    mailbox = Mailbox(
        primary_email="external@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_source_version=1,
        access_token_expires_at=utc_now() + timedelta(minutes=20),
        access_token_refreshed_at=utc_now(),
    )
    session.add(mailbox)
    session.flush()
    client_key_creation = ClientKeyService(session).create_client_key(
        name="http-worker",
        scopes=["leases:acquire", "leases:release", "tokens:access:read"],
    )
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        credential_cipher,
        UnexpectedOAuthClient(),
        session_factory=session_factory,
    )
    lease_service = LeaseService(session, credential_cipher, access_token_service)

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_lease_service] = lambda: lease_service
    app.dependency_overrides[get_access_token_service] = lambda: access_token_service

    @contextmanager
    def _noop_lifespan(_application):
        yield

    # Patch lifespan so developer .env MySQL is not touched by TestClient startup.
    with patch.object(app.router, "lifespan_context", _noop_lifespan):
        http_client = TestClient(app)
        try:
            missing_client_key_response = http_client.post(
                "/api/v1/leases/acquire",
                headers={"X-Admin-Token": "admin-secret"},
                json={"mode": "access_token", "lease_ttl_seconds": 600},
            )
            assert missing_client_key_response.status_code == 401

            acquire_response = http_client.post(
                "/api/v1/leases/acquire",
                headers={"X-API-Key": client_key_creation.api_key},
                json={"mode": "access_token", "lease_ttl_seconds": 600},
            )
            assert acquire_response.status_code == 201
            assert acquire_response.headers["cache-control"] == "no-store"
            assert acquire_response.json()["credential"]["access_token"] == "cached-access-token"

            sensitive_invalid_refresh_token = "sensitive-refresh-token-marker\n"
            invalid_refresh_token_response = http_client.post(
                "/api/v1/leases/not-a-real-lease/refresh-token",
                headers={"X-API-Key": client_key_creation.api_key},
                json={
                    "expected_token_version": 1,
                    "refresh_token": sensitive_invalid_refresh_token,
                },
            )
            assert invalid_refresh_token_response.status_code == 422
            assert sensitive_invalid_refresh_token.strip() not in invalid_refresh_token_response.text
            assert invalid_refresh_token_response.headers["cache-control"] == "no-store"

            admin_response = http_client.get(
                "/api/v1/admin/client-keys",
                headers={"X-API-Key": client_key_creation.api_key},
            )
            assert admin_response.status_code == 401

            admin_access_token_response = http_client.post(
                "/api/v1/admin/mailboxes/missing-mailbox/access-token",
                headers={"X-Admin-Token": "admin-secret"},
            )
            assert admin_access_token_response.status_code == 404
            assert admin_access_token_response.headers["cache-control"] == "no-store"
        finally:
            http_client.close()
            app.dependency_overrides.clear()
            session.close()
