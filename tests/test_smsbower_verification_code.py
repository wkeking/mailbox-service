"""SMSBower verification getCode path (no Microsoft TokenService)."""

from __future__ import annotations

import asyncio
from base64 import urlsafe_b64encode
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import (
    Mailbox,
    MailboxProviderResource,
    MailboxStatus,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
)
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.verification_code_service import (
    VerificationCodeLookupOptions,
    VerificationCodeService,
)


class NoopOAuth:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="x", expires_in=3600)


class FakeHttp:
    def __init__(self, payload) -> None:
        self.payload = payload

    def request(self, prepared, *, api_key: str):
        assert prepared.action == "getCode"
        return self.payload


def test_smsbower_get_code_returns_direct_code(monkeypatch) -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    key = urlsafe_b64encode(b"v" * 32).decode()
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        credential_encryption_key=key,
        smsbower_enabled=True,
        smsbower_api_key="k",
    )
    cipher = CredentialCipher(key)
    mailbox = Mailbox(
        primary_email="code@gmail.com",
        provider_type="smsbower_gmail",
        status=MailboxStatus.ACTIVE,
        token_version=1,
    )
    session.add(mailbox)
    session.flush()
    session.add(
        MailboxProviderResource(
            mailbox_id=mailbox.id,
            provider_type="smsbower_gmail",
            provider_instance_id="default",
            external_resource_id="mid-9",
            lifecycle_state=ProviderResourceLifecycle.CLAIMED.value,
            readiness=ProviderResourceReadiness.READY.value,
            state_version=1,
            resource_generation=1,
            encrypted_secret=cipher.encrypt('{"mail_id":"mid-9"}'),
        )
    )
    session.commit()

    token_service = MailboxAccessTokenService(
        session, settings, cipher, NoopOAuth(), session_factory=factory
    )
    service = VerificationCodeService(token_service, settings=settings, sleep_function=lambda s: None)

    from mailbox_service.providers.smsbower_transport import SmsBowerMailTransport

    transport = SmsBowerMailTransport(FakeHttp("STATUS_OK:123456"), api_key="k")

    def fake_get_code(prepared):
        return transport.get_code(prepared)

    # Patch Httpx client construction path by monkeypatching transport factory inside method
    # via replacing build path: inject by patching SmsBowerMailTransport.__init__ is heavy;
    # instead patch httpx client request used inside.
    from mailbox_service.providers import smsbower_transport as st

    class Instant:
        def __init__(self, *a, **k):
            pass

        def request(self, prepared, *, api_key: str):
            return "STATUS_OK:123456"

    monkeypatch.setattr(st, "HttpxSmsBowerClient", Instant)

    result = asyncio.run(
        service.wait_for_verification_code(
            mailbox,
            VerificationCodeLookupOptions(
                timeout_seconds=1,
                since_seconds=60,
                poll_interval_seconds=1,
            ),
        )
    )
    assert result.found is True
    assert result.code == "123456"
