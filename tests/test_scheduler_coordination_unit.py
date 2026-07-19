"""Unit tests for scheduler job lease dual-owner behavior."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.database import Base
from mailbox_service.models import ScheduledJobLease, utc_now
from mailbox_service.scheduler_lease_repository import ScheduledJobLeaseRepository


def test_only_one_owner_acquires_live_job_lease() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    repository = ScheduledJobLeaseRepository(session)
    first = repository.try_acquire("keepalive", "owner-a", 60)
    second = repository.try_acquire("keepalive", "owner-b", 60)
    assert first is not None
    assert second is None
    session.commit()


def test_expired_owner_is_taken_over_with_fencing_increment() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(
        ScheduledJobLease(
            job_name="keepalive",
            owner_id="owner-a",
            lease_until=utc_now() - timedelta(seconds=1),
            fencing_token=7,
            updated_at=utc_now() - timedelta(seconds=5),
        )
    )
    session.commit()
    repository = ScheduledJobLeaseRepository(session)
    handle = repository.try_acquire("keepalive", "owner-b", 60)
    assert handle is not None
    assert handle.fencing_token == 8
    assert handle.owner_id == "owner-b"
