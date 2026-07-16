"""Persisted models for mailbox credentials and egress proxy routing."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mailbox_service.database import Base


def utc_now() -> datetime:
    """Return a timezone-aware timestamp for persistence and comparisons."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Normalize a stored or computed timestamp to timezone-aware UTC.

    MySQL DATETIME columns often come back as naive datetimes. Application code
    uses aware UTC via :func:`utc_now`, so comparisons must normalize first.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_expired(expires_at: datetime, *, current_time: datetime | None = None) -> bool:
    """Return whether ``expires_at`` is at or before the current time in UTC."""
    comparable_now = ensure_utc(current_time or utc_now())
    return ensure_utc(expires_at) <= comparable_now


def enum_values(enum_type: type[enum.Enum]) -> list[str]:
    """Persist enum values so ORM storage matches the explicit MySQL migration."""
    return [member.value for member in enum_type]


class MailboxStatus(str, enum.Enum):
    """Health state independent from whether a mailbox currently has a lease."""

    ACTIVE = "active"
    DISABLED = "disabled"
    INVALID = "invalid"
    COOLDOWN = "cooldown"


class EgressProxyProtocol(str, enum.Enum):
    """Proxy protocols supported by the outbound OAuth and IMAP transports."""

    HTTP_CONNECT = "http_connect"
    SOCKS5 = "socks5"


class EgressProxyStatus(str, enum.Enum):
    """Operational health status of an egress proxy."""

    HEALTHY = "healthy"
    COOLDOWN = "cooldown"
    UNKNOWN = "unknown"


class LeaseMode(str, enum.Enum):
    """Credential mode granted by a mailbox lease."""

    REFRESH_TOKEN = "refresh_token"
    ACCESS_TOKEN = "access_token"
    MAIL_READ = "mail_read"


class MailboxCapability(str, enum.Enum):
    """Runtime-verified mail access channel for a mailbox access token."""

    IMAP = "imap"
    GRAPH = "graph"
    UNUSABLE = "unusable"
    UNKNOWN = "unknown"


class LeaseStatus(str, enum.Enum):
    """Derived lifecycle status for persisted lease records."""

    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"


class Mailbox(Base):
    """A mailbox credential record with an optional sticky egress proxy binding."""

    __tablename__ = "mailboxes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    primary_email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    status: Mapped[MailboxStatus] = mapped_column(
        Enum(MailboxStatus, values_callable=enum_values), nullable=False, default=MailboxStatus.ACTIVE
    )
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mail_password_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    access_token_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    capability: Mapped[MailboxCapability | None] = mapped_column(
        Enum(MailboxCapability, values_callable=enum_values), nullable=True
    )
    capability_probed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    capability_probe_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    egress_proxy_id: Mapped[str | None] = mapped_column(
        ForeignKey("egress_proxies.id", ondelete="SET NULL"), nullable=True, index=True
    )
    proxy_bound_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    proxy_last_switch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    egress_proxy: Mapped[EgressProxy | None] = relationship(back_populates="bound_mailboxes")


class EgressProxy(Base):
    """A reusable global outbound proxy with encrypted optional credentials."""

    __tablename__ = "egress_proxies"
    __table_args__ = (
        UniqueConstraint("name", name="uq_egress_proxies_name"),
        UniqueConstraint(
            "protocol",
            "host",
            "port",
            "credential_fingerprint",
            name="uq_egress_proxies_endpoint_credentials",
        ),
        Index("ix_egress_proxies_selection", "enabled", "status", "priority", "cooldown_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    protocol: Mapped[EgressProxyProtocol] = mapped_column(
        Enum(EgressProxyProtocol, values_callable=enum_values), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    username_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    status: Mapped[EgressProxyStatus] = mapped_column(
        Enum(EgressProxyStatus, values_callable=enum_values),
        nullable=False,
        default=EgressProxyStatus.UNKNOWN,
    )
    consecutive_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    bound_mailboxes: Mapped[list[Mailbox]] = relationship(back_populates="egress_proxy")


class ProxyPolicy(Base):
    """The singleton, database-backed policy used by proxy resolution."""

    __tablename__ = "proxy_policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_protocols: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    connect_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    read_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    health_check_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    failure_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    switch_minimum_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    allow_direct_development: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class ClientKey(Base):
    """External client identity whose API Key secret is stored only as a digest."""

    __tablename__ = "client_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    secret_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Lease(Base):
    """A mailbox lease used by client systems to reserve one credential record."""

    __tablename__ = "leases"
    __table_args__ = (
        Index("ix_leases_mailbox_active", "mailbox_id", "released_at", "expires_at"),
        Index("ix_leases_client_created", "client_key_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    mailbox_id: Mapped[str] = mapped_column(
        ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_tag: Mapped[str | None] = mapped_column(String(100), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Business recipient for this lease: primary address or a plus alias of primary_email.
    # IMAP/Graph auth always uses the mailbox primary identity; verification-code matching
    # defaults to this allocated address when present.
    allocated_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    mode: Mapped[LeaseMode] = mapped_column(
        Enum(LeaseMode, values_callable=enum_values), nullable=False, default=LeaseMode.ACCESS_TOKEN
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    mailbox: Mapped[Mailbox] = relationship()


class AuditLog(Base):
    """Append-only audit event that intentionally excludes secret material."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_target", "target_type", "target_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
