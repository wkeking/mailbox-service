"""Regression tests for selected mailbox export and delete admin APIs."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.main import delete_mailboxes, export_mailboxes, import_mailboxes
from mailbox_service.models import AuditLog, Lease, LeaseMode, Mailbox, utc_now
from mailbox_service.schemas import MailboxBatchIdsRequest, MailboxImportRequest
from mailbox_service.security import CredentialCipher


def create_export_delete_test_context() -> tuple[Session, Settings, CredentialCipher]:
    """Build an isolated SQLite session and matching cipher for export/delete tests."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"m" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
    )
    return session, settings, CredentialCipher(encryption_key)


def seed_import_mailboxes(session: Session, settings: Settings) -> list[str]:
    """Import two complete mailbox rows and return their IDs in primary-email order."""
    payload = MailboxImportRequest(
        content=(
            "owner-a@outlook.com----mail-secret-a----client-id-a----refresh-token-a\n"
            "owner-b@outlook.com----mail-secret-b----client-id-b----refresh-token-b\n"
        ),
        on_conflict="replace_token",
    )
    result = import_mailboxes(payload, session, settings, "test-admin")
    assert result.created == 2
    mailboxes = session.scalars(select(Mailbox).order_by(Mailbox.primary_email.asc())).all()
    return [mailbox.id for mailbox in mailboxes]


def test_export_mailboxes_returns_import_compatible_txt() -> None:
    """Selected export should decrypt credentials into the four-segment import format."""
    session, settings, _cipher = create_export_delete_test_context()
    mailbox_ids = seed_import_mailboxes(session, settings)

    response = export_mailboxes(
        MailboxBatchIdsRequest(mailbox_ids=mailbox_ids),
        session,
        settings,
        "test-admin",
    )
    export_lines = [line for line in response.body.decode("utf-8").splitlines() if line.strip()]
    audit_log_count = session.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.event_type == "mailbox.exported")
    )

    assert response.media_type.startswith("text/plain")
    assert response.headers["content-disposition"] == 'attachment; filename="mailboxes-export.txt"'
    assert export_lines == [
        "owner-a@outlook.com----mail-secret-a----client-id-a----refresh-token-a",
        "owner-b@outlook.com----mail-secret-b----client-id-b----refresh-token-b",
    ]
    assert audit_log_count == 1


def test_export_mailboxes_rejects_missing_ids() -> None:
    """Export should fail when any requested mailbox ID does not exist."""
    session, settings, _cipher = create_export_delete_test_context()
    mailbox_ids = seed_import_mailboxes(session, settings)

    try:
        export_mailboxes(
            MailboxBatchIdsRequest(mailbox_ids=[mailbox_ids[0], "missing-mailbox-id"]),
            session,
            settings,
            "test-admin",
        )
        raise AssertionError("expected missing mailbox IDs to raise HTTPException")
    except HTTPException as error:
        assert error.status_code == 404
        assert error.detail["code"] == "MAILBOX_NOT_FOUND"
        assert "missing-mailbox-id" in error.detail["missing_mailbox_ids"]


def test_export_mailboxes_rejects_incomplete_credentials() -> None:
    """Export should fail when a mailbox cannot be serialized into the import format."""
    session, settings, cipher = create_export_delete_test_context()
    incomplete_mailbox = Mailbox(
        primary_email="incomplete@outlook.com",
        client_id=None,
        mail_password_ciphertext=cipher.encrypt("only-password"),
        refresh_token_ciphertext=None,
    )
    session.add(incomplete_mailbox)
    session.flush()

    try:
        export_mailboxes(
            MailboxBatchIdsRequest(mailbox_ids=[incomplete_mailbox.id]),
            session,
            settings,
            "test-admin",
        )
        raise AssertionError("expected incomplete credentials to raise HTTPException")
    except HTTPException as error:
        assert error.status_code == 409
        assert error.detail["code"] == "MAILBOX_CREDENTIALS_INCOMPLETE"
        assert "incomplete@outlook.com" in error.detail["incomplete_primary_emails"]


def test_delete_mailboxes_removes_rows_and_related_leases() -> None:
    """Selected delete should remove mailboxes and cascade lease rows for those mailboxes."""
    session, settings, _cipher = create_export_delete_test_context()
    mailbox_ids = seed_import_mailboxes(session, settings)
    retained_mailbox_id = mailbox_ids[1]
    session.add(
        Lease(
            mailbox_id=mailbox_ids[0],
            client_key_id="client-key-1",
            mode=LeaseMode.ACCESS_TOKEN,
            expires_at=utc_now() + timedelta(hours=1),
        )
    )
    session.add(
        Lease(
            mailbox_id=retained_mailbox_id,
            client_key_id="client-key-2",
            mode=LeaseMode.ACCESS_TOKEN,
            expires_at=utc_now() + timedelta(hours=1),
        )
    )
    session.flush()

    result = delete_mailboxes(
        MailboxBatchIdsRequest(mailbox_ids=[mailbox_ids[0], "already-gone-id"]),
        session,
        "test-admin",
    )
    remaining_mailbox_ids = set(session.scalars(select(Mailbox.id)).all())
    remaining_lease_mailbox_ids = set(session.scalars(select(Lease.mailbox_id)).all())
    audit_log_count = session.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.event_type == "mailbox.deleted")
    )

    assert result.deleted == 1
    assert result.deleted_mailbox_ids == [mailbox_ids[0]]
    assert result.missing_mailbox_ids == ["already-gone-id"]
    assert remaining_mailbox_ids == {retained_mailbox_id}
    assert remaining_lease_mailbox_ids == {retained_mailbox_id}
    assert audit_log_count == 1
