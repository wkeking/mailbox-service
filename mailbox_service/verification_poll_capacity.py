"""In-process capacity limits for verification-code long polls (SEC-09)."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from mailbox_service.config import Settings


class VerificationPollCapacityExceededError(Exception):
    """Raised when a poll cannot acquire capacity immediately."""

    def __init__(self, *, scope: str, retry_after_seconds: int = 1) -> None:
        self.scope = scope
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"verification poll capacity exceeded scope={scope}")


@dataclass
class _CapacityBuckets:
    global_semaphore: threading.BoundedSemaphore
    per_client_limit: int
    per_lease_limit: int
    per_client_counts: dict[str, int]
    per_lease_counts: dict[str, int]
    lock: threading.Lock


_CAPACITY: _CapacityBuckets | None = None
_CAPACITY_LOCK = threading.Lock()


def _get_capacity(settings: Settings) -> _CapacityBuckets:
    global _CAPACITY
    with _CAPACITY_LOCK:
        if _CAPACITY is None:
            _CAPACITY = _CapacityBuckets(
                global_semaphore=threading.BoundedSemaphore(settings.mail_poll_max_concurrency),
                per_client_limit=settings.mail_poll_max_concurrency_per_client,
                per_lease_limit=settings.mail_poll_max_concurrency_per_lease,
                per_client_counts={},
                per_lease_counts={},
                lock=threading.Lock(),
            )
        return _CAPACITY


@contextmanager
def acquire_verification_poll_slot(
    settings: Settings,
    *,
    client_key_id: str,
    lease_id: str,
) -> Iterator[None]:
    """Acquire global + per-client + per-lease capacity or raise immediately (no queue)."""
    capacity = _get_capacity(settings)
    if not capacity.global_semaphore.acquire(blocking=False):
        raise VerificationPollCapacityExceededError(scope="global")

    try:
        with capacity.lock:
            client_active = capacity.per_client_counts.get(client_key_id, 0)
            if client_active >= capacity.per_client_limit:
                raise VerificationPollCapacityExceededError(scope="client")
            lease_active = capacity.per_lease_counts.get(lease_id, 0)
            if lease_active >= capacity.per_lease_limit:
                raise VerificationPollCapacityExceededError(scope="lease")
            capacity.per_client_counts[client_key_id] = client_active + 1
            capacity.per_lease_counts[lease_id] = lease_active + 1
        yield
    finally:
        with capacity.lock:
            client_active = capacity.per_client_counts.get(client_key_id, 0)
            if client_active <= 1:
                capacity.per_client_counts.pop(client_key_id, None)
            else:
                capacity.per_client_counts[client_key_id] = client_active - 1
            lease_active = capacity.per_lease_counts.get(lease_id, 0)
            if lease_active <= 1:
                capacity.per_lease_counts.pop(lease_id, None)
            else:
                capacity.per_lease_counts[lease_id] = lease_active - 1
        capacity.global_semaphore.release()


def reset_verification_poll_capacity_for_tests() -> None:
    """Clear process-wide capacity state between unit tests."""
    global _CAPACITY
    with _CAPACITY_LOCK:
        _CAPACITY = None
