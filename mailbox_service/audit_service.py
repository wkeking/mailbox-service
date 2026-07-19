"""Append-only audit helpers with optional operation idempotency keys."""

from __future__ import annotations

from typing import Any
import uuid

from sqlalchemy.orm import Session

from mailbox_service.models import AuditLog, utc_now


def write_audit_event(
    session: Session,
    *,
    actor_type: str,
    actor_id: str | None,
    event_type: str,
    target_type: str,
    target_id: str | None,
    metadata: dict[str, Any] | None = None,
    operation_id: str | None = None,
) -> AuditLog:
    """Insert one durable audit row. Does not commit."""
    audit_log = AuditLog(
        id=str(uuid.uuid4()),
        actor_type=actor_type,
        actor_id=actor_id,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        operation_id=operation_id,
        metadata_json=metadata or {},
        created_at=utc_now(),
    )
    session.add(audit_log)
    session.flush()
    return audit_log


def new_operation_id() -> str:
    """Generate a batch/item operation correlation id."""
    return str(uuid.uuid4())
