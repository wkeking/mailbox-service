"""Scheduler job lease and fencing token tests."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mailbox_service.database import Base
from mailbox_service.models import ScheduledJobLease, utc_now
from mailbox_service.scheduler_lease_repository import ScheduledJobLeaseRepository


def test_second_owner_cannot_acquire_live_lease() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    repository = ScheduledJobLeaseRepository(session)

    first = repository.try_acquire("keepalive", "owner-a", lease_seconds=60)
    second = repository.try_acquire("keepalive", "owner-b", lease_seconds=60)
    assert first is not None
    assert first.fencing_token == 1
    assert second is None
    session.commit()


def test_expired_lease_is_taken_over_with_incremented_fencing() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(
        ScheduledJobLease(
            job_name="keepalive",
            owner_id="owner-a",
            lease_until=utc_now() - timedelta(seconds=1),
            fencing_token=3,
            updated_at=utc_now() - timedelta(seconds=10),
        )
    )
    session.commit()

    repository = ScheduledJobLeaseRepository(session)
    handle = repository.try_acquire("keepalive", "owner-b", lease_seconds=60)
    assert handle is not None
    assert handle.owner_id == "owner-b"
    assert handle.fencing_token == 4
