"""Regression tests for unprobed batch recognition and invalid mailbox cleanup."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta
from unittest.mock import MagicMock

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.capability_probe_service import CapabilityProbeResult, ProbeOutcomeKind, ChannelProbeOutcome
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.main import delete_invalid_mailboxes, refresh_unprobed_mailbox_access_tokens
from mailbox_service.models import AuditLog, Lease, LeaseMode, Mailbox, MailboxCapability, MailboxStatus, utc_now
from mailbox_service.proxy_service import MicrosoftInvalidGrantError, MicrosoftTokenResponse
from mailbox_service.schemas import MailboxUnprobedRefreshRequest
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


def create_service_context(
    *,
    with_capability_prober: bool = True,
) -> tuple[Session, Settings, CredentialCipher, MailboxAccessTokenService, MagicMock]:
    """Build an isolated SQLite session with a mocked OAuth client."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"u" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
    )
    cipher = CredentialCipher(encryption_key)
    oauth_client = MagicMock()
    capability_prober = None
    if with_capability_prober:
        capability_prober = MagicMock()
        capability_prober.probe_mailbox_capability.return_value = CapabilityProbeResult(
            capability=MailboxCapability.IMAP,
            preferred_channel="imap",
            probe_error=None,
            outcomes=(
                ChannelProbeOutcome(channel="imap", kind=ProbeOutcomeKind.SUCCESS),
            ),
        )
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        capability_prober=capability_prober,
    )
    return session, settings, cipher, access_token_service, oauth_client


def seed_mailbox(
    session: Session,
    cipher: CredentialCipher,
    *,
    primary_email: str,
    status: MailboxStatus = MailboxStatus.ACTIVE,
    capability: MailboxCapability | None = None,
) -> Mailbox:
    mailbox = Mailbox(
        primary_email=primary_email,
        status=status,
        client_id="client-id",
        mail_password_ciphertext=cipher.encrypt("mail-secret"),
        refresh_token_ciphertext=cipher.encrypt(f"refresh-{primary_email}"),
        capability=capability,
    )
    session.add(mailbox)
    session.flush()
    return mailbox


def test_refresh_unprobed_only_processes_null_and_unknown_in_batches() -> None:
    """Unprobed refresh should target capability NULL/UNKNOWN and respect batch_size."""
    session, _settings, cipher, access_token_service, oauth_client = create_service_context()
    unprobed_a = seed_mailbox(session, cipher, primary_email="a@outlook.com", capability=None)
    unprobed_b = seed_mailbox(session, cipher, primary_email="b@outlook.com", capability=MailboxCapability.UNKNOWN)
    seed_mailbox(session, cipher, primary_email="c@outlook.com", capability=MailboxCapability.IMAP)
    seed_mailbox(
        session,
        cipher,
        primary_email="d@outlook.com",
        status=MailboxStatus.INVALID,
        capability=None,
    )

    oauth_client.refresh_access_token.return_value = MicrosoftTokenResponse(
        access_token="access-token-value",
        expires_in=3600,
        rotated_refresh_token=None,
        scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    )

    result = refresh_unprobed_mailbox_access_tokens(
        MailboxUnprobedRefreshRequest(batch_size=1),
        access_token_service,
        session,
        "test-admin",
    )
    audit_count = session.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.event_type == "mailbox.unprobed_refreshed")
    )

    assert result.candidate_total == 2
    assert result.processed == 1
    assert result.successful == 1
    assert result.failed == 0
    assert result.remaining_candidates == 1
    assert result.results[0].mailbox_id == unprobed_a.id
    assert unprobed_a.access_token_ciphertext is not None
    assert unprobed_a.capability == MailboxCapability.IMAP
    assert unprobed_b.access_token_ciphertext is None
    assert audit_count == 1


def test_refresh_unprobed_marks_invalid_grant_as_failed_and_invalid_status() -> None:
    """invalid_grant during recognition should mark the mailbox invalid and count as failed."""
    session, _settings, cipher, access_token_service, oauth_client = create_service_context()
    mailbox = seed_mailbox(session, cipher, primary_email="bad@outlook.com", capability=None)
    oauth_client.refresh_access_token.side_effect = MicrosoftInvalidGrantError("Microsoft 拒绝 refresh token")

    result = refresh_unprobed_mailbox_access_tokens(
        MailboxUnprobedRefreshRequest(batch_size=50),
        access_token_service,
        session,
        "test-admin",
    )

    assert result.processed == 1
    assert result.successful == 0
    assert result.failed == 1
    assert mailbox.status == MailboxStatus.INVALID
    assert result.remaining_candidates == 0


def test_delete_invalid_mailboxes_removes_only_invalid_rows_and_leases() -> None:
    """Invalid cleanup must not touch active mailboxes."""
    session, _settings, cipher, _service, _oauth = create_service_context()
    invalid_mailbox = seed_mailbox(
        session,
        cipher,
        primary_email="invalid@outlook.com",
        status=MailboxStatus.INVALID,
    )
    active_mailbox = seed_mailbox(session, cipher, primary_email="active@outlook.com")
    session.add(
        Lease(
            mailbox_id=invalid_mailbox.id,
            client_key_id="client-key",
            mode=LeaseMode.ACCESS_TOKEN,
            expires_at=utc_now() + timedelta(hours=1),
        )
    )
    session.add(
        Lease(
            mailbox_id=active_mailbox.id,
            client_key_id="client-key",
            mode=LeaseMode.ACCESS_TOKEN,
            expires_at=utc_now() + timedelta(hours=1),
        )
    )
    session.flush()

    result = delete_invalid_mailboxes(session, "test-admin")
    remaining_mailbox_ids = set(session.scalars(select(Mailbox.id)).all())
    remaining_lease_mailbox_ids = set(session.scalars(select(Lease.mailbox_id)).all())
    audit_count = session.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.event_type == "mailbox.invalid_deleted")
    )

    assert result.deleted == 1
    assert result.deleted_mailbox_ids == [invalid_mailbox.id]
    assert result.deleted_primary_emails == ["invalid@outlook.com"]
    assert remaining_mailbox_ids == {active_mailbox.id}
    assert remaining_lease_mailbox_ids == {active_mailbox.id}
    assert audit_count == 1
