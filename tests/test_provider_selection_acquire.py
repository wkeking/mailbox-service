"""mail_read provider multi-select, all, and exclude_providers selection."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import (
    LeaseService,
    ProviderUnsupportedError,
)
from mailbox_service.models import (
    LeaseMode,
    Mailbox,
    MailboxCapability,
    MailboxProviderResource,
    MailboxStatus,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
    UsageSite,
)
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.schemas import MailboxAcquireRequest
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
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        credential_encryption_key=key,
    )
    cipher = CredentialCipher(key)
    token = MailboxAccessTokenService(
        session, settings, cipher, NoopOAuth(), session_factory=factory
    )
    lease = LeaseService(session, cipher, token, session_factory=factory)
    return session, cipher, lease


def _seed_microsoft(session, cipher, email: str = "ms@example.com") -> Mailbox:
    session.add(UsageSite(code="openai", display_name="OpenAI", enabled=True))
    mailbox = Mailbox(
        primary_email=email,
        provider_type="microsoft",
        status=MailboxStatus.ACTIVE,
        capability=MailboxCapability.IMAP,
        client_id="client",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=1,
    )
    session.add(mailbox)
    session.flush()
    return mailbox


def _seed_smsbower(session, cipher, email: str = "sms@gmail.com") -> MailboxProviderResource:
    resource = MailboxProviderResource(
        provider_type="smsbower_gmail",
        provider_instance_id="default",
        external_resource_id="act-1",
        primary_email=email,
        lifecycle_state=ProviderResourceLifecycle.AVAILABLE.value,
        readiness=ProviderResourceReadiness.READY.value,
        state_version=0,
        resource_generation=0,
        encrypted_secret=cipher.encrypt('{"mail_id":"act-1"}'),
    )
    session.add(resource)
    session.flush()
    return resource


def test_schema_normalizes_provider_all_and_lists() -> None:
    assert MailboxAcquireRequest(provider="all").provider is None
    assert MailboxAcquireRequest(provider=["microsoft", "SMSBOWER_GMAIL"]).provider == [
        "microsoft",
        "smsbower_gmail",
    ]
    assert MailboxAcquireRequest(provider="microsoft,ignored".split(",")).provider == [
        "microsoft",
        "ignored",
    ]
    request = MailboxAcquireRequest(
        provider=["all"],
        exclude_providers=["smsbower_gmail", "SMSBOWER_GMAIL", "inbucket"],
    )
    assert request.provider is None
    assert request.exclude_providers == ["smsbower_gmail", "inbucket"]


def test_omit_provider_without_extra_scope_stays_microsoft() -> None:
    session, cipher, lease_service = _build()
    _seed_microsoft(session, cipher)
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(name="ms-only", scopes=["mailboxes:acquire"])
        .api_key
    )
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        usage_site="openai",
    )
    assert result.provider_type == "microsoft"
    assert result.primary_email == "ms@example.com"


def test_all_with_scopes_can_select_smsbower() -> None:
    session, cipher, lease_service = _build()
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(
            name="both",
            scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
        )
        .api_key
    )
    # No microsoft inventory + omit provider: should land on authorized smsbower.
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider=None,
    )
    assert result.provider_type == "smsbower_gmail"


def test_exclude_providers_wins_over_all() -> None:
    session, cipher, lease_service = _build()
    _seed_microsoft(session, cipher)
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(
            name="both",
            scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
        )
        .api_key
    )
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider=["microsoft", "smsbower_gmail"],
        exclude_providers=["microsoft"],
        usage_site="openai",
        explicit_provider_request=True,
    )
    assert result.provider_type == "smsbower_gmail"


def test_exclude_all_candidates_raises() -> None:
    session, cipher, lease_service = _build()
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(name="ms", scopes=["mailboxes:acquire"])
        .api_key
    )
    try:
        lease_service.acquire_lease(
            principal,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=300,
            provider="microsoft",
            exclude_providers="microsoft",
            explicit_provider_request=True,
        )
        raised = False
    except ProviderUnsupportedError:
        raised = True
    assert raised


def test_multi_provider_list_randomizes_available() -> None:
    session, cipher, lease_service = _build()
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(
            name="both",
            scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
        )
        .api_key
    )
    # microsoft listed but empty inventory; should fall through to smsbower.
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider=["microsoft", "smsbower_gmail"],
        usage_site="openai",
        explicit_provider_request=True,
    )
    assert result.provider_type == "smsbower_gmail"


def test_explicit_unauthorized_provider_still_requires_scope() -> None:
    session, cipher, lease_service = _build()
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(name="no-sms", scopes=["mailboxes:acquire"])
        .api_key
    )
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


def test_use_plus_alias_does_not_force_microsoft_when_excluded() -> None:
    """use_plus_alias applies only after microsoft is selected; ignore for other types."""
    session, cipher, lease_service = _build()
    _seed_smsbower(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(
            name="sms-only-scope",
            scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
        )
        .api_key
    )

    # If plus alias forced microsoft, this would fail with LEASE_MODE_MISMATCH.
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider="all",
        exclude_providers=["microsoft"],
        use_plus_alias=True,
        explicit_provider_request=False,
    )
    assert result.provider_type == "smsbower_gmail"
    assert result.allocated_email == "sms@gmail.com"
    assert result.address_kind == "primary"


def test_use_plus_alias_still_applies_when_microsoft_selected() -> None:
    session, cipher, lease_service = _build()
    _seed_microsoft(session, cipher)
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(name="ms", scopes=["mailboxes:acquire"])
        .api_key
    )
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=300,
        provider="microsoft",
        use_plus_alias=True,
        preferred_alias_suffix="abc12345",
        explicit_provider_request=True,
    )
    assert result.provider_type == "microsoft"
    assert result.address_kind == "plus_alias"
    assert result.allocated_email == "ms+abc12345@example.com"


def test_resolve_candidates_exclude_priority() -> None:
    session, cipher, lease_service = _build()
    principal = ClientKeyService(session).authenticate(
        ClientKeyService(session)
        .create_client_key(
            name="both",
            scopes=["mailboxes:acquire", "providers:smsbower_gmail:acquire"],
        )
        .api_key
    )
    # Explicit list with unauthorized scoped type → hard fail (scope required).
    try:
        lease_service._resolve_mail_read_provider_candidates(
            principal,
            provider=["microsoft", "inbucket"],
            exclude_providers=None,
            explicit_provider_request=True,
        )
        unauthorized_hard_fail = False
    except Exception:
        unauthorized_hard_fail = True
    assert unauthorized_hard_fail

    candidates = lease_service._resolve_mail_read_provider_candidates(
        principal,
        provider=["microsoft", "smsbower_gmail"],
        exclude_providers=["smsbower_gmail"],
        explicit_provider_request=True,
    )
    assert candidates == ["microsoft"]

    all_authorized = lease_service._resolve_mail_read_provider_candidates(
        principal,
        provider=None,
        exclude_providers=["microsoft"],
        explicit_provider_request=False,
    )
    assert "microsoft" not in all_authorized
    assert "smsbower_gmail" in all_authorized
