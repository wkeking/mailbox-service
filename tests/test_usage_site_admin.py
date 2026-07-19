"""Admin CRUD for registration sites and occupancy revoke flows."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import (
    LeaseService,
    UsageSiteConflictError,
    UsageSiteInUseError,
    UsageSiteNotFoundError,
)
from mailbox_service.models import EmailSiteUsage, LeaseMode, Mailbox, MailboxCapability, UsageSite, utc_now
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class FakeMicrosoftOAuthClient:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        raise AssertionError("not used")


def create_context():
    database_engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session = session_factory()
    encryption_key = urlsafe_b64encode(b"m" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        access_token_refresh_skew_seconds=120,
    )
    credential_cipher = CredentialCipher(encryption_key)
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        credential_cipher,
        FakeMicrosoftOAuthClient(),
        session_factory=session_factory,
    )
    client_key_service = ClientKeyService(session)
    lease_service = LeaseService(session, credential_cipher, access_token_service)
    return session, credential_cipher, client_key_service, lease_service


def test_admin_create_update_usage_site() -> None:
    session, _cipher, _client_key_service, lease_service = create_context()

    created = lease_service.create_usage_site(
        code="Discord",
        display_name=" Discord ",
        enabled=True,
    )
    assert created.code == "discord"
    assert created.display_name == "Discord"
    assert created.enabled is True

    try:
        lease_service.create_usage_site(code="discord", display_name="Again")
    except UsageSiteConflictError:
        pass
    else:
        raise AssertionError("duplicate code should conflict")

    updated = lease_service.update_usage_site("discord", display_name="Discord App", enabled=False)
    assert updated.display_name == "Discord App"
    assert updated.enabled is False

    sites = lease_service.list_usage_sites_for_admin(include_disabled=True)
    assert any(site.code == "discord" and site.enabled is False for site in sites)
    enabled_only = lease_service.list_usage_sites_for_admin(include_disabled=False)
    assert all(site.code != "discord" for site in enabled_only)

    try:
        lease_service.update_usage_site("missing-site", enabled=True)
    except UsageSiteNotFoundError:
        pass
    else:
        raise AssertionError("missing site should 404")


def test_admin_delete_usage_site_requires_no_active_occupancy() -> None:
    session, credential_cipher, client_key_service, lease_service = create_context()
    lease_service.create_usage_site(code="temp-site", display_name="Temp", enabled=True)
    session.add(
        Mailbox(
            primary_email="temp@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
            capability=MailboxCapability.IMAP,
            access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
            access_token_source_version=1,
            access_token_expires_at=utc_now() + timedelta(minutes=30),
        )
    )
    session.flush()
    creation = client_key_service.create_client_key(
        name="delete-site-bot",
        scopes=["mailboxes:acquire", "leases:release"],
    )
    principal = client_key_service.authenticate(creation.api_key)
    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        preferred_email="temp@outlook.com",
        usage_site="temp-site",
    )
    lease_service.release_lease(principal, result.lease_id)

    try:
        lease_service.delete_usage_site("temp-site")
    except UsageSiteInUseError:
        pass
    else:
        raise AssertionError("active occupancy should block delete")

    usage = session.scalar(
        select(EmailSiteUsage).where(
            EmailSiteUsage.allocated_email == "temp@outlook.com",
            EmailSiteUsage.usage_site_code == "temp-site",
        )
    )
    assert usage is not None
    lease_service.revoke_email_site_usage(usage.id)
    lease_service.delete_usage_site("temp-site")
    assert session.get(UsageSite, "temp-site") is None
    assert (
        session.scalar(
            select(EmailSiteUsage).where(EmailSiteUsage.usage_site_code == "temp-site")
        )
        is None
    )


def test_admin_list_and_revoke_email_site_usage() -> None:
    session, credential_cipher, client_key_service, lease_service = create_context()
    session.add(UsageSite(code="openai", display_name="OpenAI", enabled=True))
    session.add(
        Mailbox(
            primary_email="owner@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
            capability=MailboxCapability.IMAP,
            access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
            access_token_source_version=1,
            access_token_expires_at=utc_now() + timedelta(minutes=30),
        )
    )
    session.flush()
    creation = client_key_service.create_client_key(
        name="usage-admin-bot",
        scopes=["mailboxes:acquire", "leases:release"],
    )
    principal = client_key_service.authenticate(creation.api_key)
    lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        usage_site="openai",
    )

    items, total = lease_service.list_email_site_usages(
        allocated_email="owner@outlook.com",
        include_revoked=False,
    )
    assert total == 1
    assert items[0].usage_site_code == "openai"
    assert items[0].revoked_at is None

    revoked = lease_service.revoke_email_site_usage(items[0].id)
    assert revoked.revoked_at is not None
    active_items, active_total = lease_service.list_email_site_usages(
        allocated_email="owner@outlook.com",
        include_revoked=False,
    )
    assert active_total == 0
    assert active_items == []

    all_items, all_total = lease_service.list_email_site_usages(
        allocated_email="owner@outlook.com",
        include_revoked=True,
    )
    assert all_total == 1
    assert all_items[0].revoked_at is not None

    usage_row = session.scalar(select(EmailSiteUsage).where(EmailSiteUsage.id == items[0].id))
    assert usage_row is not None
    assert usage_row.revoked_at is not None
