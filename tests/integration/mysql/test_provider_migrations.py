"""MySQL 8 verification for provider binding migrations (014-016)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from mailbox_service.config import Settings
from mailbox_service.migration_runner import run_pending_migrations
from mailbox_service.models import Mailbox, MailboxStatus
from mailbox_service.security import CredentialCipher


pytestmark = pytest.mark.mysql


def test_provider_migrations_columns_defaults_and_idempotent_rerun(
    mysql_engine,
    mysql_settings: Settings,
    mysql_session_factory,
) -> None:
    versions = [
        row[0]
        for row in mysql_engine.connect()
        .execute(text("SELECT version FROM schema_migrations ORDER BY version"))
        .fetchall()
    ]
    assert "014" in versions
    assert "015" in versions
    assert "016" in versions

    with mysql_engine.connect() as connection:
        mailbox_columns = {
            row[0]: row
            for row in connection.execute(text("SHOW COLUMNS FROM mailboxes")).fetchall()
        }
        assert "provider_type" in mailbox_columns
        assert mailbox_columns["provider_type"][4] == "microsoft" or mailbox_columns[
            "provider_type"
        ][4] in ("microsoft", b"microsoft")
        assert "provider_config_json" in mailbox_columns

        lease_columns = {
            row[0]
            for row in connection.execute(text("SHOW COLUMNS FROM leases")).fetchall()
        }
        assert "provider_type" in lease_columns
        assert "provider_instance_id" in lease_columns
        assert "provider_config_revision" in lease_columns

        tables = {
            row[0]
            for row in connection.execute(text("SHOW TABLES")).fetchall()
        }
        assert "mailbox_provider_resources" in tables
        assert "mailbox_provider_operations" in tables

    # Second apply is a no-op (idempotent).
    applied_again = run_pending_migrations(mysql_engine, mysql_settings)
    assert applied_again == []

    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    session = mysql_session_factory()
    try:
        unique = uuid.uuid4().hex[:12]
        mailbox = Mailbox(
            primary_email=f"provider-default-{unique}@example.com",
            status=MailboxStatus.ACTIVE,
            client_id="client-id",
            refresh_token_ciphertext=cipher.encrypt("rt"),
            token_version=1,
        )
        session.add(mailbox)
        session.commit()
        session.refresh(mailbox)
        assert mailbox.provider_type == "microsoft"
        assert mailbox.provider_config_json is None
    finally:
        session.close()


def test_provider_resource_unique_external_id(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    from mailbox_service.models import (
        MailboxProviderResource,
        ProviderResourceLifecycle,
        ProviderResourceReadiness,
    )
    from sqlalchemy.exc import IntegrityError

    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    session = mysql_session_factory()
    try:
        unique = uuid.uuid4().hex[:12]
        first = Mailbox(
            primary_email=f"res-a-{unique}@example.com",
            status=MailboxStatus.ACTIVE,
            provider_type="smsbower_gmail",
            client_id=None,
            refresh_token_ciphertext=None,
            token_version=1,
        )
        second = Mailbox(
            primary_email=f"res-b-{unique}@example.com",
            status=MailboxStatus.ACTIVE,
            provider_type="smsbower_gmail",
            client_id=None,
            refresh_token_ciphertext=None,
            token_version=1,
        )
        session.add_all([first, second])
        session.flush()
        session.add(
            MailboxProviderResource(
                mailbox_id=first.id,
                provider_type="smsbower_gmail",
                provider_instance_id="default",
                external_resource_id=f"activation-{unique}",
                lifecycle_state=ProviderResourceLifecycle.AVAILABLE.value,
                readiness=ProviderResourceReadiness.READY.value,
                state_version=0,
                resource_generation=0,
            )
        )
        session.commit()
        session.add(
            MailboxProviderResource(
                mailbox_id=second.id,
                provider_type="smsbower_gmail",
                provider_instance_id="default",
                external_resource_id=f"activation-{unique}",
                lifecycle_state=ProviderResourceLifecycle.AVAILABLE.value,
                readiness=ProviderResourceReadiness.READY.value,
                state_version=0,
                resource_generation=0,
            )
        )
        try:
            session.commit()
            raised = False
        except IntegrityError:
            session.rollback()
            raised = True
        assert raised
    finally:
        session.close()
