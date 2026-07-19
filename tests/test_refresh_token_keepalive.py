"""Regression tests for scheduled refresh-token keepalive selection."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import Lease, LeaseMode, Mailbox, MailboxStatus, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class RecordingOAuthClient:
    def __init__(self) -> None:
        self.refreshed_emails: list[str] = []

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
        self.refreshed_emails.append(mailbox.primary_email)
        return MicrosoftTokenResponse(
            access_token=f"at-{mailbox.primary_email}",
            expires_in=3600,
            rotated_refresh_token=f"rotated-{refresh_token}",
            scope="offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
        )


def create_keepalive_service(
    *,
    lifetime_days: int = 90,
    lead_days: int = 7,
    batch_size: int = 20,
) -> tuple[MailboxAccessTokenService, CredentialCipher, RecordingOAuthClient, object]:
    database_engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session = session_factory()
    encryption_key = urlsafe_b64encode(b"k" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        refresh_token_lifetime_days=lifetime_days,
        refresh_token_keepalive_lead_days=lead_days,
        refresh_token_keepalive_batch_size=batch_size,
    )
    credential_cipher = CredentialCipher(encryption_key)
    oauth_client = RecordingOAuthClient()
    service = MailboxAccessTokenService(session, settings, credential_cipher, oauth_client, session_factory=session_factory)
    return service, credential_cipher, oauth_client, session


def test_keepalive_selects_stale_active_mailboxes_and_skips_leased_or_fresh() -> None:
    service, credential_cipher, oauth_client, session = create_keepalive_service(
        lifetime_days=90,
        lead_days=7,
        batch_size=10,
    )
    now = utc_now()
    # Expires in 5 days → within 7-day lead window → due.
    stale_mailbox = Mailbox(
        primary_email="stale@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("old-rt"),
        refresh_token_updated_at=now - timedelta(days=85),
        refresh_token_expires_at=now + timedelta(days=5),
        access_token_refreshed_at=now - timedelta(days=85),
        created_at=now - timedelta(days=120),
    )
    # Legacy row without RT expiry columns; last refresh 100 days ago → due via fallback.
    never_refreshed = Mailbox(
        primary_email="imported@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("imported-rt"),
        access_token_refreshed_at=None,
        created_at=now - timedelta(days=100),
    )
    # Expires in 80 days → outside lead window → skip.
    fresh_mailbox = Mailbox(
        primary_email="fresh@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("fresh-rt"),
        refresh_token_updated_at=now - timedelta(days=10),
        refresh_token_expires_at=now + timedelta(days=80),
        access_token_refreshed_at=now - timedelta(days=10),
        created_at=now - timedelta(days=10),
    )
    # Due by expiry but has an active lease → skip.
    leased_mailbox = Mailbox(
        primary_email="leased@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("leased-rt"),
        refresh_token_updated_at=now - timedelta(days=88),
        refresh_token_expires_at=now + timedelta(days=2),
        access_token_refreshed_at=now - timedelta(days=88),
        created_at=now - timedelta(days=100),
    )
    invalid_mailbox = Mailbox(
        primary_email="invalid@outlook.com",
        status=MailboxStatus.INVALID,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("invalid-rt"),
        refresh_token_updated_at=now - timedelta(days=100),
        refresh_token_expires_at=now - timedelta(days=10),
        access_token_refreshed_at=now - timedelta(days=100),
        created_at=now - timedelta(days=120),
    )
    session.add_all([stale_mailbox, never_refreshed, fresh_mailbox, leased_mailbox, invalid_mailbox])
    session.flush()
    session.add(
        Lease(
            mailbox_id=leased_mailbox.id,
            client_key_id=None,
            mode=LeaseMode.ACCESS_TOKEN,
            expires_at=now + timedelta(minutes=30),
            created_at=now,
        )
    )
    session.flush()

    due_ids = service.list_mailbox_ids_due_for_refresh_token_keepalive(batch_size=10)
    due_emails = {
        session.get(Mailbox, mailbox_id).primary_email
        for mailbox_id in due_ids
    }
    assert due_emails == {"stale@outlook.com", "imported@outlook.com"}

    result = service.run_refresh_token_keepalive_batch()
    assert result.successful == 2
    assert result.failed == 0
    assert set(oauth_client.refreshed_emails) == {"stale@outlook.com", "imported@outlook.com"}
    assert "rotated-" in credential_cipher.decrypt(stale_mailbox.refresh_token_ciphertext or "")
    assert stale_mailbox.token_version == 2
    assert stale_mailbox.refresh_token_updated_at is not None
    assert stale_mailbox.refresh_token_expires_at is not None
    # Successful refresh rewrites sliding window to ~now + 90 days.
    # SQLite may return naive datetimes; normalize before comparing with aware utc_now().
    from mailbox_service.models import ensure_utc

    assert ensure_utc(stale_mailbox.refresh_token_expires_at) > now + timedelta(days=89)


def test_keepalive_batch_size_limits_due_selection() -> None:
    service, credential_cipher, _, session = create_keepalive_service(
        lifetime_days=90,
        lead_days=7,
        batch_size=1,
    )
    now = utc_now()
    older = Mailbox(
        primary_email="a-older@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("rt-a"),
        refresh_token_updated_at=now - timedelta(days=100),
        refresh_token_expires_at=now - timedelta(days=10),
        access_token_refreshed_at=now - timedelta(days=100),
        created_at=now - timedelta(days=120),
    )
    newer = Mailbox(
        primary_email="b-newer@outlook.com",
        status=MailboxStatus.ACTIVE,
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("rt-b"),
        refresh_token_updated_at=now - timedelta(days=90),
        refresh_token_expires_at=now + timedelta(days=1),
        access_token_refreshed_at=now - timedelta(days=90),
        created_at=now - timedelta(days=100),
    )
    session.add_all([older, newer])
    session.flush()

    due_ids = service.list_mailbox_ids_due_for_refresh_token_keepalive(batch_size=1)
    assert len(due_ids) == 1
    assert session.get(Mailbox, due_ids[0]).primary_email == "a-older@outlook.com"
