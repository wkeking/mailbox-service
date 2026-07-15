"""Focused regression tests for mailbox credential import behavior."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.main import import_mailboxes
from mailbox_service.models import AuditLog, Mailbox, MailboxCapability, utc_now
from mailbox_service.schemas import MailboxImportRequest
from mailbox_service.security import CredentialCipher


def create_import_test_context() -> tuple[Session, Settings, CredentialCipher]:
    """Build an isolated SQLite session and matching cipher for import tests."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"m" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
    )
    return session, settings, CredentialCipher(encryption_key)


def test_mailbox_import_creates_encrypted_credentials() -> None:
    """Imported mailbox passwords and refresh tokens are encrypted at rest."""
    session, settings, cipher = create_import_test_context()
    payload = MailboxImportRequest(
        content="owner@outlook.com----mail-secret----client-id----refresh-token",
        on_conflict="replace_token",
    )

    result = import_mailboxes(payload, session, settings, "test-admin")
    stored_mailbox = session.scalar(select(Mailbox).where(Mailbox.primary_email == "owner@outlook.com"))
    audit_log_count = session.scalar(select(func.count(AuditLog.id)))

    assert result.created == 1
    assert result.updated == 0
    assert result.skipped == 0
    assert result.failed == 0
    assert stored_mailbox is not None
    assert stored_mailbox.client_id == "client-id"
    assert stored_mailbox.scope is None
    assert stored_mailbox.mail_password_ciphertext is not None
    assert stored_mailbox.refresh_token_ciphertext is not None
    assert stored_mailbox.mail_password_ciphertext != "mail-secret"
    assert stored_mailbox.refresh_token_ciphertext != "refresh-token"
    assert cipher.decrypt(stored_mailbox.mail_password_ciphertext) == "mail-secret"
    assert cipher.decrypt(stored_mailbox.refresh_token_ciphertext) == "refresh-token"
    assert audit_log_count == 1


def test_mailbox_import_replaces_existing_token_version() -> None:
    """The replace strategy refreshes secrets and increments the mailbox token version."""
    session, settings, cipher = create_import_test_context()
    existing_mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="old-client-id",
        mail_password_ciphertext=cipher.encrypt("old-mail-secret"),
        refresh_token_ciphertext=cipher.encrypt("old-refresh-token"),
        access_token_ciphertext=cipher.encrypt("old-access-token"),
        access_token_expires_at=utc_now() + timedelta(hours=1),
        access_token_refreshed_at=utc_now(),
        scope="Mail.Read offline_access",
        capability=MailboxCapability.GRAPH,
        capability_probe_error=None,
        token_version=4,
    )
    session.add(existing_mailbox)
    session.flush()
    payload = MailboxImportRequest(
        content="owner@outlook.com----new-mail-secret----new-client-id----new-refresh-token",
        on_conflict="replace_token",
    )

    result = import_mailboxes(payload, session, settings, "test-admin")

    assert result.created == 0
    assert result.updated == 1
    assert result.skipped == 0
    assert result.failed == 0
    assert existing_mailbox.client_id == "new-client-id"
    assert existing_mailbox.token_version == 5
    assert existing_mailbox.access_token_ciphertext is None
    assert existing_mailbox.access_token_expires_at is None
    assert existing_mailbox.access_token_refreshed_at is None
    assert existing_mailbox.scope is None
    assert existing_mailbox.capability is None
    assert existing_mailbox.capability_probed_at is None
    assert existing_mailbox.capability_probe_error is None
    assert existing_mailbox.mail_password_ciphertext is not None
    assert existing_mailbox.refresh_token_ciphertext is not None
    assert cipher.decrypt(existing_mailbox.mail_password_ciphertext) == "new-mail-secret"
    assert cipher.decrypt(existing_mailbox.refresh_token_ciphertext) == "new-refresh-token"


def test_mailbox_import_reports_line_errors_without_writing_invalid_rows() -> None:
    """Invalid line format, invalid email, and batch duplicates are reported per line."""
    session, settings, _ = create_import_test_context()
    payload = MailboxImportRequest(
        content=(
            "bad-line\n"
            "not-an-email----mail-secret----client-id----refresh-token\n"
            "owner@outlook.com----mail-secret----client-id----refresh-token\n"
            "owner@outlook.com----other-mail-secret----client-id----other-refresh-token"
        ),
        on_conflict="replace_token",
    )

    result = import_mailboxes(payload, session, settings, "test-admin")
    stored_mailbox_count = session.scalar(select(func.count(Mailbox.id)))

    assert result.created == 1
    assert result.updated == 0
    assert result.skipped == 0
    assert result.failed == 3
    assert [line_error.line_number for line_error in result.errors] == [1, 2, 4]
    assert stored_mailbox_count == 1
