"""Monotonic deadline helpers for long-running request-bound operations."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


class OperationDeadlineExceededError(TimeoutError):
    """Raised when an operation exceeds its monotonic deadline."""


@dataclass(frozen=True, slots=True)
class OperationDeadline:
    """Wall-clock-independent deadline based on ``time.monotonic()``."""

    deadline_monotonic: float
    started_monotonic: float

    @classmethod
    def from_timeout_seconds(
        cls,
        timeout_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> OperationDeadline:
        """Create a deadline that expires ``timeout_seconds`` from now."""
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be >= 0")
        started_monotonic = float(clock())
        return cls(
            deadline_monotonic=started_monotonic + float(timeout_seconds),
            started_monotonic=started_monotonic,
        )

    def remaining_seconds(self, *, clock: Callable[[], float] = time.monotonic) -> float:
        """Return non-negative remaining time until the deadline."""
        return max(0.0, self.deadline_monotonic - float(clock()))

    def is_expired(self, *, clock: Callable[[], float] = time.monotonic) -> bool:
        """Return whether the deadline has already passed."""
        return float(clock()) >= self.deadline_monotonic

    def elapsed_seconds(self, *, clock: Callable[[], float] = time.monotonic) -> float:
        """Return elapsed time since the deadline was created."""
        return max(0.0, float(clock()) - self.started_monotonic)

    def bounded_timeout_seconds(
        self,
        configured_timeout_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        minimum_seconds: float = 0.05,
    ) -> float:
        """Clamp a network timeout to the remaining deadline budget."""
        if configured_timeout_seconds <= 0:
            raise ValueError("configured_timeout_seconds must be > 0")
        remaining_seconds = self.remaining_seconds(clock=clock)
        if remaining_seconds <= 0:
            raise OperationDeadlineExceededError("operation deadline exceeded")
        bounded_timeout = min(float(configured_timeout_seconds), remaining_seconds)
        if bounded_timeout < minimum_seconds:
            raise OperationDeadlineExceededError("operation deadline exceeded")
        return bounded_timeout

    def raise_if_expired(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        """Raise when the deadline has passed."""
        if self.is_expired(clock=clock):
            raise OperationDeadlineExceededError("operation deadline exceeded")
