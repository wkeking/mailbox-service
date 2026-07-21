"""SMSBower release CAS finalize outcomes."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.database import Base
from mailbox_service.models import (
    MailboxProviderOperation,
    MailboxProviderResource,
    ProviderOperationStatus,
    ProviderOperationType,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
)
from mailbox_service.provider_operation_service import ProviderOperationService


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
    resource = MailboxProviderResource(
        id="res-1",
        provider_type="smsbower_gmail",
        provider_instance_id="default",
        external_resource_id="rid-1",
        primary_email="rel@gmail.com",
        lifecycle_state=ProviderResourceLifecycle.RELEASING.value,
        readiness=ProviderResourceReadiness.NOT_READY.value,
        state_version=2,
        resource_generation=3,
        encrypted_secret="cipher",
    )
    session.add(resource)
    session.add(
        MailboxProviderOperation(
            id="op-1",
            operation_type=ProviderOperationType.RELEASE.value,
            provider_type="smsbower_gmail",
            provider_instance_id="default",
            provider_resource_id=resource.id,
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
    return resource


def test_finalize_succeeded_returns_available_and_bumps_generation() -> None:
    session = _session()
    resource = _seed(session)
    ops = ProviderOperationService(session)
    applied = ops.finalize_release_cas(
        operation_id="op-1",
        provider_resource_id=resource.id,
        expected_generation=3,
        expected_state_version=2,
        outcome="succeeded",
        clear_secret=True,
    )
    assert applied is True
    stored = session.get(MailboxProviderResource, resource.id)
    assert stored.lifecycle_state == "available"
    assert stored.resource_generation == 4
    assert stored.encrypted_secret is None
    op = session.get(MailboxProviderOperation, "op-1")
    assert op.status == "succeeded"


def test_finalize_unknown_leaves_release_unknown() -> None:
    session = _session()
    resource = _seed(session)
    ops = ProviderOperationService(session)
    applied = ops.finalize_release_cas(
        operation_id="op-1",
        provider_resource_id=resource.id,
        expected_generation=3,
        expected_state_version=2,
        outcome="unknown",
    )
    assert applied is True
    stored = session.get(MailboxProviderResource, resource.id)
    assert stored.lifecycle_state == "release_unknown"
