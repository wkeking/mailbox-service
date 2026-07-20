"""Persisted models for mailbox credentials and egress proxy routing."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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


class ProviderResourceLifecycle(str, enum.Enum):
    """Lifecycle of a non-Microsoft inventory provider resource."""

    AVAILABLE = "available"
    CLAIMED = "claimed"
    RELEASING = "releasing"
    COOLDOWN = "cooldown"
    RELEASE_UNKNOWN = "release_unknown"
    RETIRED = "retired"


class ProviderResourceReadiness(str, enum.Enum):
    """Whether a provider resource can accept mail_read (independent of MailboxCapability)."""

    READY = "ready"
    NOT_READY = "not_ready"
    UNKNOWN = "unknown"


class ProviderOperationType(str, enum.Enum):
    """Durable external side-effect categories."""

    REPLENISH = "replenish"
    RELEASE = "release"
    RECONCILE = "reconcile"


class ProviderOperationStatus(str, enum.Enum):
    """Durable operation status machine."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class Mailbox(Base):
    """A mailbox credential record with an optional sticky egress proxy binding."""

    __tablename__ = "mailboxes"
    __table_args__ = (
        Index("ix_mailboxes_provider_status", "provider_type", "status", "capability"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # microsoft | smsbower_gmail | future inventory providers. Not MailboxCapability.
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False, default="microsoft")
    primary_email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    status: Mapped[MailboxStatus] = mapped_column(
        Enum(MailboxStatus, values_callable=enum_values), nullable=False, default=MailboxStatus.ACTIVE
    )
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mail_password_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Sliding-window metadata for the stored refresh token (service-estimated; Microsoft does not
    # return an absolute RT expiry). Keepalive selects rows by refresh_token_expires_at.
    refresh_token_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    refresh_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    access_token_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    access_token_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # RT revision that produced the cached AT; NULL forces refresh after migration.
    access_token_source_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    capability: Mapped[MailboxCapability | None] = mapped_column(
        Enum(MailboxCapability, values_callable=enum_values), nullable=True
    )
    capability_probed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    capability_probe_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Non-sensitive provider metadata only; secrets live in encrypted fields / resource table.
    provider_config_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Single-flight refresh claim; expired claims may be taken over by another worker.
    token_refresh_claim_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    token_refresh_claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
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


class MailboxLeaseClaim(Base):
    """Current exclusive occupancy for one mailbox (history remains in leases)."""

    __tablename__ = "mailbox_lease_claims"
    __table_args__ = (
        UniqueConstraint("lease_id", name="uq_mailbox_lease_claims_lease_id"),
        UniqueConstraint("allocated_email", name="uq_mailbox_lease_claims_allocated_email"),
        Index("ix_mailbox_lease_claims_expires_at", "expires_at"),
        Index("ix_mailbox_lease_claims_client", "client_key_id", "expires_at"),
    )

    mailbox_id: Mapped[str] = mapped_column(
        ForeignKey("mailboxes.id", ondelete="CASCADE"), primary_key=True
    )
    lease_id: Mapped[str] = mapped_column(String(36), nullable=False)
    client_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mode: Mapped[LeaseMode] = mapped_column(
        Enum(LeaseMode, values_callable=enum_values), nullable=False
    )
    allocated_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Lease(Base):
    """A mailbox lease used by client systems to reserve one credential record."""

    __tablename__ = "leases"
    __table_args__ = (
        Index("ix_leases_mailbox_active", "mailbox_id", "released_at", "expires_at"),
        Index("ix_leases_client_created", "client_key_id", "created_at"),
        Index("ix_leases_provider_type", "provider_type", "released_at", "expires_at"),
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
    # Immutable Provider binding written at acquire; verification/release must not re-infer.
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False, default="microsoft")
    provider_instance_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_config_revision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    mailbox: Mapped[Mailbox] = relationship()


class MailboxProviderResource(Base):
    """External inventory resource attached to one mailbox (SMSBower activation, etc.)."""

    __tablename__ = "mailbox_provider_resources"
    __table_args__ = (
        UniqueConstraint(
            "provider_instance_id",
            "external_resource_id",
            name="uq_provider_instance_external",
        ),
        Index("ix_provider_resources_lifecycle", "provider_type", "lifecycle_state", "readiness"),
    )

    mailbox_id: Mapped[str] = mapped_column(
        ForeignKey("mailboxes.id", ondelete="CASCADE"), primary_key=True
    )
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    external_resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    readiness: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resource_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class MailboxProviderOperation(Base):
    """Durable external operation with idempotency and fencing metadata."""

    __tablename__ = "mailbox_provider_operations"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_provider_ops_idempotency"),
        Index("ix_provider_ops_status", "status", "updated_at"),
        Index("ix_provider_ops_mailbox", "mailbox_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    operation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    mailbox_id: Mapped[str | None] = mapped_column(
        ForeignKey("mailboxes.id", ondelete="SET NULL"), nullable=True
    )
    lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    external_resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource_generation: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expected_state_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_summary_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class ProviderInstanceSettings(Base):
    """Admin-editable Provider instance settings (DB overrides env defaults).

    Secrets are stored only in encrypted columns (e.g. api_key_ciphertext).
    Non-secret knobs may live in typed columns or config_json.
    """

    __tablename__ = "provider_instance_settings"

    provider_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    instance_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    api_base: Mapped[str | None] = mapped_column(String(512), nullable=True)
    api_key_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Encrypted JSON bag for secondary secrets (admin_password, ddg_token, cf_inbox_jwt, ...).
    secrets_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    max_price: Mapped[float | None] = mapped_column(Float, nullable=True)
    request_timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=30.0)
    config_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class UsageSite(Base):
    """Whitelist entry for registration sites declared on mail_read acquire."""

    __tablename__ = "usage_sites"
    __table_args__ = (Index("ix_usage_sites_enabled", "enabled"),)

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class EmailSiteUsage(Base):
    """Global occupancy: one business email may register once per usage site."""

    __tablename__ = "email_site_usages"
    __table_args__ = (
        UniqueConstraint("allocated_email", "usage_site_code", name="uq_email_site_usages_email_site"),
        Index("ix_email_site_usages_site_revoked", "usage_site_code", "revoked_at"),
        Index("ix_email_site_usages_created", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    allocated_email: Mapped[str] = mapped_column(String(320), nullable=False)
    usage_site_code: Mapped[str] = mapped_column(
        ForeignKey("usage_sites.code"),
        nullable=False,
        index=True,
    )
    mailbox_id: Mapped[str | None] = mapped_column(
        ForeignKey("mailboxes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("leases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    client_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class ScheduledJobLease(Base):
    """Database-backed ownership lease for multi-instance background jobs."""

    __tablename__ = "scheduled_job_leases"

    job_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ProxyHealthEvent(Base):
    """Idempotent proxy health observation event used for audit and CAS."""

    __tablename__ = "proxy_health_events"
    __table_args__ = (
        UniqueConstraint("operation_id", name="uq_proxy_health_events_operation_id"),
        Index("ix_proxy_health_events_proxy_observed", "proxy_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    operation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    proxy_id: Mapped[str] = mapped_column(
        ForeignKey("egress_proxies.id", ondelete="CASCADE"), nullable=False
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class AuditLog(Base):
    """Append-only audit event that intentionally excludes secret material."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_target", "target_type", "target_id", "created_at"),
        UniqueConstraint(
            "operation_id",
            "target_id",
            "event_type",
            name="uq_audit_logs_operation_resource_event",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    operation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
