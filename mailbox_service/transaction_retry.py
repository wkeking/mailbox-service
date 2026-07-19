"""Retry helpers for short MySQL transactions that hit 1205/1213."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from typing import TypeVar

from sqlalchemy.exc import OperationalError

logger = logging.getLogger("uvicorn.error")

ResultType = TypeVar("ResultType")

# Exponential backoff base delays in seconds; jitter is applied on top.
DEFAULT_BACKOFF_SECONDS = (0.025, 0.075, 0.225)
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_JITTER_SECONDS = 0.025

# MySQL error codes that are safe to retry when the whole short transaction is replayed.
RETRYABLE_MYSQL_ERROR_CODES = frozenset({1205, 1213})


class TransactionRetryExhaustedError(RuntimeError):
    """Raised after limited retries still fail with lock wait/deadlock errors."""

    def __init__(
        self,
        *,
        operation: str,
        mysql_error_code: int | None,
        attempts: int,
        cause: Exception,
    ) -> None:
        self.operation = operation
        self.mysql_error_code = mysql_error_code
        self.attempts = attempts
        self.cause = cause
        super().__init__(
            f"transaction retry exhausted operation={operation} "
            f"mysql_error_code={mysql_error_code} attempts={attempts}"
        )


def extract_mysql_error_code(error: BaseException) -> int | None:
    """Best-effort extraction of a MySQL errno from SQLAlchemy/DB-API errors."""
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        args = getattr(current, "args", ())
        if args:
            first_argument = args[0]
            if isinstance(first_argument, int):
                return first_argument
            if isinstance(first_argument, (tuple, list)) and first_argument:
                nested_code = first_argument[0]
                if isinstance(nested_code, int):
                    return nested_code
        original = getattr(current, "orig", None)
        if isinstance(original, BaseException):
            current = original
            continue
        current = current.__cause__ if isinstance(current.__cause__, BaseException) else None
    return None


def is_retryable_mysql_lock_error(error: BaseException) -> bool:
    """Return whether the error is a MySQL lock wait timeout or deadlock."""
    if not isinstance(error, (OperationalError, OSError, RuntimeError)):
        # SQLAlchemy wraps DBAPIError as OperationalError for these codes.
        mysql_error_code = extract_mysql_error_code(error)
        return mysql_error_code in RETRYABLE_MYSQL_ERROR_CODES
    mysql_error_code = extract_mysql_error_code(error)
    return mysql_error_code in RETRYABLE_MYSQL_ERROR_CODES


def run_with_mysql_lock_retry(
    operation: Callable[[], ResultType],
    *,
    operation_name: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF_SECONDS,
    jitter_seconds: float = DEFAULT_JITTER_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> ResultType:
    """Replay a complete short transaction on MySQL 1205/1213 only.

    The callable must open its own Session, re-read state, and commit or roll back
    completely. Network I/O must not live inside the callable.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    attempt_index = 0
    while True:
        attempt_index += 1
        try:
            return operation()
        except Exception as error:
            mysql_error_code = extract_mysql_error_code(error)
            if mysql_error_code not in RETRYABLE_MYSQL_ERROR_CODES or attempt_index >= max_attempts:
                if mysql_error_code in RETRYABLE_MYSQL_ERROR_CODES:
                    logger.warning(
                        "mysql_lock_retry_exhausted operation=%s mysql_error_code=%s attempts=%s",
                        operation_name,
                        mysql_error_code,
                        attempt_index,
                    )
                    raise TransactionRetryExhaustedError(
                        operation=operation_name,
                        mysql_error_code=mysql_error_code,
                        attempts=attempt_index,
                        cause=error,
                    ) from error
                raise

            backoff_index = min(attempt_index - 1, len(backoff_seconds) - 1)
            delay_seconds = backoff_seconds[backoff_index] + random.uniform(0.0, max(jitter_seconds, 0.0))
            logger.info(
                "mysql_lock_retry operation=%s mysql_error_code=%s attempt=%s delay_seconds=%.3f",
                operation_name,
                mysql_error_code,
                attempt_index,
                delay_seconds,
            )
            sleep(delay_seconds)
