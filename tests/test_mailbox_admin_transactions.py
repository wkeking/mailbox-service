"""Admin delete claim-guard and chunk audit tests."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseService
from mailbox_service.mailbox_admin_service import (
    ActiveLeaseClaimConflictError,
    MailboxAdminService,
)
from mailbox_service.models import AuditLog, LeaseMode, Mailbox, MailboxStatus, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class FakeOAuth:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="at", expires_in=3600)


def _build():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    key = urlsafe_b64encode(b"a" * 32).decode("ascii")
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", credential_encryption_key=key, app_env="test")
    cipher = CredentialCipher(key)
    access = MailboxAccessTokenService(session, settings, cipher, FakeOAuth(), session_factory=session_factory)
    return session, cipher, ClientKeyService(session), LeaseService(session, cipher, access)


def test_delete_rejects_active_claim_without_force() -> None:
    session, cipher, client_keys, leases = _build()
    mailbox = Mailbox(
        primary_email="del@outlook.com",
        client_id="c",
        refresh_token_ciphertext=cipher.encrypt("rt"),
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="worker",
        scopes=["leases:acquire", "leases:release", "tokens:refresh:read"],
    )
    principal = client_keys.authenticate(created.api_key)
    leases.acquire_lease(principal, mode=LeaseMode.REFRESH_TOKEN, ttl_seconds=600)
    session.flush()

    admin = MailboxAdminService(session)
    with pytest.raises(ActiveLeaseClaimConflictError):
        admin.delete_mailboxes_by_ids([mailbox.id], admin_id="admin-1", force_release_active_leases=False)


def test_delete_force_releases_claim_and_writes_audit() -> None:
    session, cipher, client_keys, leases = _build()
    mailbox = Mailbox(
        primary_email="force@outlook.com",
        client_id="c",
        refresh_token_ciphertext=cipher.encrypt("rt"),
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="worker2",
        scopes=["leases:acquire", "leases:release", "tokens:refresh:read"],
    )
    principal = client_keys.authenticate(created.api_key)
    leases.acquire_lease(principal, mode=LeaseMode.REFRESH_TOKEN, ttl_seconds=600)
    session.flush()

    admin = MailboxAdminService(session)
    result = admin.delete_mailboxes_by_ids(
        [mailbox.id], admin_id="admin-1", force_release_active_leases=True
    )
    session.commit()
    assert result.deleted == 1
    audits = list(session.scalars(select(AuditLog).order_by(AuditLog.created_at.asc())))
    event_types = {audit.event_type for audit in audits}
    assert "lease.force_released_for_delete" in event_types
    assert "mailbox.deleted" in event_types


def test_delete_invalid_chunk_writes_chunk_audit() -> None:
    session, cipher, _, _ = _build()
    for index in range(3):
        session.add(
            Mailbox(
                primary_email=f"invalid{index}@outlook.com",
                status=MailboxStatus.INVALID,
                client_id="c",
                refresh_token_ciphertext=cipher.encrypt("rt"),
            )
        )
    session.flush()
    admin = MailboxAdminService(session)
    result = admin.delete_invalid_mailboxes_in_chunks(admin_id="admin-1", batch_size=2)
    session.commit()
    assert result.deleted == 3
    chunk_audits = list(
        session.scalars(select(AuditLog).where(AuditLog.event_type == "mailbox.invalid_deleted_chunk"))
    )
    assert len(chunk_audits) >= 2
    # Regression: MySQL rejects operation_id longer than VARCHAR(36).
    # Never use composite keys like "{uuid}:{chunk_index}" here.
    for chunk_audit in chunk_audits:
        assert chunk_audit.operation_id is not None
        assert len(chunk_audit.operation_id) <= 36
        assert ":" not in chunk_audit.operation_id
        assert chunk_audit.metadata_json.get("chunk_index") is not None
    parent_operation_ids = {chunk_audit.operation_id for chunk_audit in chunk_audits}
    assert len(parent_operation_ids) == 1
    summary_audits = list(
        session.scalars(select(AuditLog).where(AuditLog.event_type == "mailbox.invalid_deleted"))
    )
    assert len(summary_audits) == 1
    assert summary_audits[0].operation_id == next(iter(parent_operation_ids))
