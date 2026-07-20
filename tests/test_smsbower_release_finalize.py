"""SMSBower release CAS finalize outcomes."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.database import Base
from mailbox_service.models import (
    Mailbox,
    MailboxProviderOperation,
    MailboxProviderResource,
    MailboxStatus,
    ProviderOperationStatus,
    ProviderOperationType,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
)
from mailbox_service.provider_operation_service import ProviderOperationService
from mailbox_service.security import CredentialCipher


def _session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _seed(session):
    mailbox = Mailbox(
        primary_email="rel@gmail.com",
        provider_type="smsbower_gmail",
        status=MailboxStatus.ACTIVE,
        token_version=1,
    )
    session.add(mailbox)
    session.flush()
    session.add(
        MailboxProviderResource(
            mailbox_id=mailbox.id,
            provider_type="smsbower_gmail",
            provider_instance_id="default",
            external_resource_id="rid-1",
            lifecycle_state=ProviderResourceLifecycle.RELEASING.value,
            readiness=ProviderResourceReadiness.NOT_READY.value,
            state_version=2,
            resource_generation=3,
            encrypted_secret="cipher",
        )
    )
    session.add(
        MailboxProviderOperation(
            id="op-1",
            operation_type=ProviderOperationType.RELEASE.value,
            provider_type="smsbower_gmail",
            provider_instance_id="default",
            mailbox_id=mailbox.id,
            lease_id="lease-1",
            external_resource_id="rid-1",
            resource_generation=3,
            expected_state_version=2,
            status=ProviderOperationStatus.PENDING.value,
            idempotency_key="release:lease-1:3",
            attempt_count=1,
        )
    )
    session.flush()
    return mailbox


def test_finalize_succeeded_returns_available_and_bumps_generation() -> None:
    session = _session()
    mailbox = _seed(session)
    ops = ProviderOperationService(session)
    applied = ops.finalize_release_cas(
        operation_id="op-1",
        mailbox_id=mailbox.id,
        expected_generation=3,
        expected_state_version=2,
        outcome="succeeded",
        clear_secret=True,
    )
    assert applied is True
    resource = session.get(MailboxProviderResource, mailbox.id)
    assert resource.lifecycle_state == "available"
    assert resource.resource_generation == 4
    assert resource.encrypted_secret is None
    op = session.get(MailboxProviderOperation, "op-1")
    assert op.status == "succeeded"


def test_finalize_unknown_leaves_release_unknown() -> None:
    session = _session()
    mailbox = _seed(session)
    ops = ProviderOperationService(session)
    applied = ops.finalize_release_cas(
        operation_id="op-1",
        mailbox_id=mailbox.id,
        expected_generation=3,
        expected_state_version=2,
        outcome="unknown",
    )
    assert applied is True
    resource = session.get(MailboxProviderResource, mailbox.id)
    assert resource.lifecycle_state == "release_unknown"
    assert resource.resource_generation == 3  # generation not advanced on unknown
    op = session.get(MailboxProviderOperation, "op-1")
    assert op.status == "unknown"


def test_finalize_stale_generation_is_noop() -> None:
    session = _session()
    mailbox = _seed(session)
    ops = ProviderOperationService(session)
    applied = ops.finalize_release_cas(
        operation_id="op-1",
        mailbox_id=mailbox.id,
        expected_generation=99,
        expected_state_version=2,
        outcome="succeeded",
    )
    assert applied is False
    resource = session.get(MailboxProviderResource, mailbox.id)
    assert resource.lifecycle_state == "releasing"
