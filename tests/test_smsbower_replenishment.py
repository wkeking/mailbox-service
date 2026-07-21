"""SMSBower replenishment durable operation tests (mock transport only)."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import Mailbox, MailboxProviderOperation, MailboxProviderResource
from mailbox_service.providers.smsbower_contracts import build_get_activation_request
from mailbox_service.providers.smsbower_gmail import SmsBowerGmailProvider
from mailbox_service.providers.smsbower_transport import SmsBowerMailTransport
from mailbox_service.security import CredentialCipher


class FakeHttp:
    def __init__(self, payload) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def request(self, prepared, *, api_key: str):
        self.calls.append(prepared.action)
        assert api_key == "test-key"
        if callable(self.payload):
            return self.payload(prepared)
        return self.payload


def _context(http_client):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    key = urlsafe_b64encode(b"s" * 32).decode()
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        credential_encryption_key=key,
        smsbower_enabled=True,
        smsbower_api_key="test-key",
        smsbower_instance_id="default",
    )
    cipher = CredentialCipher(key)
    transport = SmsBowerMailTransport(http_client, api_key="test-key")
    provider = SmsBowerGmailProvider(
        settings,
        credential_cipher=cipher,
        session_factory=factory,
        transport=transport,
    )
    return factory, provider


def test_replenish_success_writes_resource_not_mailbox() -> None:
    http_client = FakeHttp("ACCESS:90001:sms.user@gmail.com")
    factory, provider = _context(http_client)
    outcome = provider.replenish_one(actor_id="admin")
    assert outcome.status == "succeeded"
    assert outcome.primary_email == "sms.user@gmail.com"
    assert outcome.external_resource_id == "90001"
    assert outcome.mailbox_id is None
    assert outcome.provider_resource_id is not None
    session = factory()
    try:
        assert session.scalars(select(Mailbox)).first() is None
        resource = session.get(MailboxProviderResource, outcome.provider_resource_id)
        assert resource is not None
        assert resource.provider_type == "smsbower_gmail"
        assert resource.primary_email == "sms.user@gmail.com"
        assert resource.lifecycle_state == "available"
        assert resource.external_resource_id == "90001"
        ops = list(session.scalars(select(MailboxProviderOperation)))
        assert len(ops) == 1
        assert ops[0].status == "succeeded"
        assert ops[0].provider_resource_id == resource.id
    finally:
        session.close()


def test_replenish_timeout_marks_unknown_not_second_purchase() -> None:
    from mailbox_service.providers.smsbower_transport import SmsBowerTransportError

    def boom(prepared):
        raise SmsBowerTransportError("timeout", is_timeout=True, is_unknown=True)

    http_client = FakeHttp(boom)
    factory, provider = _context(http_client)
    outcome = provider.replenish_one()
    assert outcome.status == "unknown"
    assert outcome.mailbox_id is None
    assert outcome.provider_resource_id is None
    session = factory()
    try:
        assert session.scalars(select(Mailbox)).first() is None
        assert session.scalars(select(MailboxProviderResource)).first() is None
        op = session.scalars(select(MailboxProviderOperation)).first()
        assert op is not None
        assert op.status == "unknown"
    finally:
        session.close()


def test_activation_request_builder_uses_service_code() -> None:
    request = build_get_activation_request(
        base_url="https://smsbower.page/api/mail",
        service="openai",
        domain="gmail.com",
        max_price=1.5,
    )
    assert request.params["service"] == "dr"
    assert request.params["maxPrice"] == 1.5
