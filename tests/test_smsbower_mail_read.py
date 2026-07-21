"""SMSBower mail_read acquire and claim lifecycle (SQLite)."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseService, LeaseUnavailableError
from mailbox_service.models import (
    LeaseMode,
    Mailbox,
    MailboxProviderResource,
    MailboxStatus,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
)
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class NoopOAuth:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="x", expires_in=3600)


def _build():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    key = urlsafe_b64encode(b"m" * 32).decode()
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", app_env="test", credential_encryption_key=key)
    cipher = CredentialCipher(key)
    token = MailboxAccessTokenService(session, settings, cipher, NoopOAuth(), session_factory=factory)
    lease = LeaseService(session, cipher, token, session_factory=factory)
    return session, cipher, lease


def _seed_resource(session, cipher, email: str = "sms.a@gmail.com", external_id: str = "act-1") -> MailboxProviderResource:
    resource = MailboxProviderResource(
        provider_type="smsbower_gmail",
        provider_instance_id="default",
        external_resource_id=external_id,
        primary_email=email,
        lifecycle_state=ProviderResourceLifecycle.AVAILABLE.value,
        readiness=ProviderResourceReadiness.READY.value,
        state_version=0,
        resource_generation=0,
        encrypted_secret=cipher.encrypt(f'{{"mail_id":"{external_id}"}}'),
    )
    session.add(resource)
    session.flush()
    return resource


def test_smsbower_acquire_requires_scope_and_claims_resource() -> None:
    session, cipher, lease_service = _build()
    resource = _seed_resource(session, cipher)
    key_service = ClientKeyService(session)
    creation = key_service.create_client_key(name="no-scope", scopes=["mailboxes:acquire"])
    principal = key_service.authenticate(creation.api_key)
    try:
        lease_service.acquire_lease(
            principal,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=300,
            provider="smsbower_gmail",
            explicit_provider_request=True,
        )
        raised = False
    except Exception as error:
        raised = True
        assert "providers:smsbower_gmail:acquire" in str(error)
    assert raised

    creation2 = key_service.create_client_key(
        name="with-scope",
        scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire", "leases:release"],
    )
    principal2 = key_service.authenticate(creation2.api_key)
    result = lease_service.acquire_lease(
        principal2,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider="smsbower_gmail",
        explicit_provider_request=True,
    )
    assert result.provider_type == "smsbower_gmail"
    assert result.mailbox_id is None
    assert result.provider_resource_id == resource.id
    assert result.allocated_email == "sms.a@gmail.com"
    # must not pollute mailboxes
    assert session.scalars(select(Mailbox)).first() is None
    stored = session.get(MailboxProviderResource, resource.id)
    assert stored is not None
    assert stored.lifecycle_state == "claimed"
    assert stored.resource_generation == 1

    try:
        lease_service.acquire_lease(
            principal2,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=300,
            provider="smsbower_gmail",
            explicit_provider_request=True,
        )
        blocked = False
    except LeaseUnavailableError:
        blocked = True
    assert blocked

    lease_service.release_lease(principal2, result.lease_id)
    session.flush()
    stored = session.get(MailboxProviderResource, resource.id)
    assert stored is not None
    assert stored.lifecycle_state == "releasing"


def test_omitted_provider_with_scope_can_select_smsbower() -> None:
    """Omit/all pools authorized types; smsbower is eligible when scoped and inventory exists."""
    session, cipher, lease_service = _build()
    _seed_resource(session, cipher, email="sms.only@gmail.com", external_id="act-only")
    key_service = ClientKeyService(session)
    creation = key_service.create_client_key(
        name="with-scope",
        scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
    )
    principal = key_service.authenticate(creation.api_key)
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
    )
    assert result.provider_type == "smsbower_gmail"
    assert result.mailbox_id is None
    assert result.provider_resource_id is not None
    assert session.scalars(select(Mailbox)).first() is None
