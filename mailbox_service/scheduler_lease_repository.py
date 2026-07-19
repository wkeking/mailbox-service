"""Database-backed scheduler job leases with fencing tokens."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import socket
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from mailbox_service.models import ScheduledJobLease, ensure_utc, is_expired, utc_now


@dataclass(frozen=True, slots=True)
class JobLeaseHandle:
    """Handle returned to a successful job owner."""

    job_name: str
    owner_id: str
    fencing_token: int


def build_scheduler_owner_id() -> str:
    """Return a stable-enough owner identity without secrets."""
    hostname = socket.gethostname()[:48]
    return f"{hostname}:{uuid.uuid4().hex[:12]}"


class ScheduledJobLeaseRepository:
    """Acquire, renew, and release cluster-wide job ownership leases."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def try_acquire(
        self,
        job_name: str,
        owner_id: str,
        lease_seconds: int,
    ) -> JobLeaseHandle | None:
        """Try to become the job owner. Returns None when another owner holds a live lease."""
        current_time = utc_now()
        lease = self._session.scalar(
            select(ScheduledJobLease).where(ScheduledJobLease.job_name == job_name).with_for_update()
        )
        if lease is None:
            lease = ScheduledJobLease(
                job_name=job_name,
                owner_id=owner_id,
                lease_until=current_time + timedelta(seconds=lease_seconds),
                fencing_token=1,
                updated_at=current_time,
            )
            self._session.add(lease)
            self._session.flush()
            return JobLeaseHandle(job_name=job_name, owner_id=owner_id, fencing_token=1)

        if not is_expired(lease.lease_until, current_time=current_time) and lease.owner_id != owner_id:
            return None

        if lease.owner_id != owner_id:
            lease.fencing_token = int(lease.fencing_token) + 1
        lease.owner_id = owner_id
        lease.lease_until = current_time + timedelta(seconds=lease_seconds)
        lease.updated_at = current_time
        self._session.flush()
        return JobLeaseHandle(
            job_name=job_name,
            owner_id=owner_id,
            fencing_token=int(lease.fencing_token),
        )

    def renew(self, handle: JobLeaseHandle, lease_seconds: int) -> bool:
        """Extend ownership only when fencing token still matches."""
        lease = self._session.scalar(
            select(ScheduledJobLease)
            .where(ScheduledJobLease.job_name == handle.job_name)
            .with_for_update()
        )
        if lease is None:
            return False
        if lease.owner_id != handle.owner_id or int(lease.fencing_token) != handle.fencing_token:
            return False
        current_time = utc_now()
        lease.lease_until = current_time + timedelta(seconds=lease_seconds)
        lease.updated_at = current_time
        self._session.flush()
        return True

    def release(self, handle: JobLeaseHandle) -> None:
        """Release ownership when still the fencing-token owner."""
        lease = self._session.scalar(
            select(ScheduledJobLease)
            .where(ScheduledJobLease.job_name == handle.job_name)
            .with_for_update()
        )
        if lease is None:
            return
        if lease.owner_id != handle.owner_id or int(lease.fencing_token) != handle.fencing_token:
            return
        lease.lease_until = ensure_utc(utc_now())
        lease.updated_at = utc_now()
        self._session.flush()
