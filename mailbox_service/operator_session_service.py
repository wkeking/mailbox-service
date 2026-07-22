"""Admin-only operator debug sessions for on-demand mailbox provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from mailbox_service.config import Settings
from mailbox_service.models import (
    Lease,
    LeaseMode,
    MailboxProviderResource,
    ProviderResourceLifecycle,
    ProviderResourceReadiness,
    is_expired,
    utc_now,
)
from mailbox_service.provider_health_service import OPERATOR_DEBUG_PURPOSE
from mailbox_service.providers.catalog import ON_DEMAND_PROVIDER_TYPES
from mailbox_service.providers.ondemand_adapters import OnDemandProviderError
from mailbox_service.providers.ondemand_facade import OnDemandProviderService
from mailbox_service.providers.ports import (
    OnDemandProvisionRequest,
    VerificationAllocationSnapshot,
    VerificationQuery,
)
from mailbox_service.security import CredentialCipher
from mailbox_service.verification_code_service import extract_verification_code


DEFAULT_OPERATOR_SESSION_TTL_SECONDS = 1800
MAX_ACTIVE_OPERATOR_SESSIONS = 20
MESSAGE_TEXT_LIMIT = 32_768


class OperatorSessionError(Exception):
    """Base error for operator session operations."""


class OperatorSessionNotFoundError(OperatorSessionError):
    """Session lease is missing or not an operator debug session."""


class OperatorSessionLimitError(OperatorSessionError):
    """Too many concurrent operator debug sessions."""


class OperatorProviderError(OperatorSessionError):
    """Provider configuration or provision failure."""


@dataclass(frozen=True)
class OperatorSessionView:
    lease_id: str
    provider_type: str
    provider_instance_id: str
    provider_resource_id: str
    address: str
    purpose: str
    expires_at: datetime
    created_at: datetime
    released_at: datetime | None
    last_verification_code: str | None
    last_code_checked_at: datetime | None


@dataclass(frozen=True)
class OperatorMessageView:
    id: str | None
    from_address: str | None
    subject: str | None
    intro: str
    text: str
    created_at: datetime | None
    code: str | None


class OperatorSessionService:
    """Create, list, read, and release Admin operator debug sessions."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        credential_cipher: CredentialCipher,
        *,
        on_demand_service: OnDemandProviderService,
    ) -> None:
        self._session = session
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._on_demand_service = on_demand_service

    def list_sessions(self, *, include_released: bool = False) -> list[OperatorSessionView]:
        statement = (
            select(Lease)
            .where(Lease.purpose == OPERATOR_DEBUG_PURPOSE)
            .order_by(Lease.created_at.desc())
            .limit(100)
        )
        leases = list(self._session.scalars(statement))
        views: list[OperatorSessionView] = []
        for lease in leases:
            if not include_released and (
                lease.released_at is not None or is_expired(lease.expires_at)
            ):
                continue
            views.append(self._to_view(lease))
        return views

    def create_session(
        self,
        *,
        provider_type: str,
        provider_instance_id: str | None = None,
        domain: str | None = None,
        local_part: str | None = None,
        label: str | None = None,
        ttl_seconds: int = DEFAULT_OPERATOR_SESSION_TTL_SECONDS,
        admin_id: str,
    ) -> OperatorSessionView:
        normalized_type = (provider_type or "").strip().lower()
        if normalized_type not in ON_DEMAND_PROVIDER_TYPES:
            raise OperatorProviderError("联调会话目前仅支持 on-demand Provider")

        active_count = self._count_active_sessions()
        if active_count >= MAX_ACTIVE_OPERATOR_SESSIONS:
            raise OperatorSessionLimitError(
                f"活跃联调会话已达上限（{MAX_ACTIVE_OPERATOR_SESSIONS}），请先释放旧会话"
            )

        instance_id = (provider_instance_id or "default").strip() or "default"
        # domain is accepted for UI parity; adapters currently choose from configured lists.
        _ = domain
        try:
            provision_result = self._on_demand_service.provision(
                OnDemandProvisionRequest(
                    provider_type=normalized_type,
                    provider_instance_id=instance_id,
                    preferred_local_part=(local_part or "").strip() or None,
                )
            )
        except OnDemandProviderError as error:
            raise OperatorProviderError(str(error)) from error
        except Exception as error:
            raise OperatorProviderError(str(error)) from error

        address = str(provision_result.address or "").strip().lower()
        if not address or "@" not in address:
            raise OperatorProviderError("on-demand provider returned invalid address")

        current_time = utc_now()
        resource_id = str(uuid.uuid4())
        encrypted_secret = self._credential_cipher.encrypt(
            json.dumps(provision_result.secret_payload or {}, ensure_ascii=False)
        )
        metadata = dict(provision_result.metadata or {})
        if label:
            metadata["operator_label"] = label
        metadata["operator_admin_id"] = admin_id

        resource = MailboxProviderResource(
            id=resource_id,
            provider_type=normalized_type,
            provider_instance_id=instance_id,
            external_resource_id=str(provision_result.external_resource_id or address),
            primary_email=address,
            lifecycle_state=ProviderResourceLifecycle.CLAIMED.value,
            readiness=ProviderResourceReadiness.READY.value,
            state_version=1,
            resource_generation=1,
            encrypted_secret=encrypted_secret,
            metadata_json=metadata,
        )
        lease = Lease(
            mailbox_id=None,
            provider_resource_id=resource_id,
            client_key_id=None,
            client_tag="operator",
            purpose=OPERATOR_DEBUG_PURPOSE,
            allocated_email=address,
            mode=LeaseMode.MAIL_READ,
            provider_type=normalized_type,
            provider_instance_id=instance_id,
            provider_config_revision=None,
            expires_at=current_time + timedelta(seconds=max(ttl_seconds, 60)),
            created_at=current_time,
        )
        self._session.add(resource)
        self._session.flush()
        self._session.add(lease)
        self._session.flush()
        return self._to_view(lease)

    def get_session(self, lease_id: str) -> OperatorSessionView:
        lease = self._load_operator_lease(lease_id, require_active=False)
        return self._to_view(lease)

    def fetch_messages(self, lease_id: str) -> tuple[OperatorSessionView, list[OperatorMessageView], list[str]]:
        lease = self._load_operator_lease(lease_id, require_active=True)
        resource = self._session.get(MailboxProviderResource, lease.provider_resource_id)
        if resource is None:
            raise OperatorSessionNotFoundError("联调资源不存在")

        access_context: dict[str, str] = {
            "external_resource_id": str(resource.external_resource_id or ""),
        }
        if resource.encrypted_secret:
            try:
                secret = json.loads(self._credential_cipher.decrypt(resource.encrypted_secret))
                if isinstance(secret, dict):
                    for key, value in secret.items():
                        if value is not None:
                            access_context[str(key)] = str(value)
            except Exception:
                pass

        allocation = VerificationAllocationSnapshot(
            lease_id=lease.id,
            mailbox_id="",
            provider_type=lease.provider_type,
            provider_instance_id=lease.provider_instance_id,
            primary_email=resource.primary_email,
            allocated_email=lease.allocated_email or resource.primary_email,
            access_context=access_context,
        )
        query = VerificationQuery(max_messages=30)
        try:
            evidence = self._on_demand_service.fetch_evidence(allocation, query)
        except OnDemandProviderError as error:
            raise OperatorProviderError(str(error)) from error

        message_views: list[OperatorMessageView] = []
        codes: list[str] = []
        checked_at = utc_now()
        last_code: str | None = None
        for index, message in enumerate(evidence.messages):
            body = (message.body_text or "")[:MESSAGE_TEXT_LIMIT]
            subject = message.subject or ""
            code = evidence.direct_code if index == 0 and evidence.direct_code else None
            if not code:
                code = extract_verification_code(subject=subject, body_text=body)
            if code:
                codes.append(code)
                if last_code is None:
                    last_code = code
            message_views.append(
                OperatorMessageView(
                    id=None,
                    from_address=message.from_address,
                    subject=message.subject,
                    intro=(body[:180] if body else ""),
                    text=body,
                    created_at=message.received_at,
                    code=code,
                )
            )

        if last_code:
            resource.last_verification_code = last_code[:32]
        resource.last_code_checked_at = checked_at
        resource.updated_at = checked_at
        self._session.flush()
        return self._to_view(lease), message_views, codes

    def release_session(self, lease_id: str) -> OperatorSessionView:
        lease = self._load_operator_lease(lease_id, require_active=False)
        if lease.released_at is None:
            lease.released_at = utc_now()
            if lease.provider_resource_id:
                resource = self._session.get(MailboxProviderResource, lease.provider_resource_id)
                if resource is not None:
                    resource.lifecycle_state = ProviderResourceLifecycle.RETIRED.value
                    resource.readiness = ProviderResourceReadiness.NOT_READY.value
                    resource.state_version = int(resource.state_version or 0) + 1
                    resource.encrypted_secret = None
                    resource.updated_at = utc_now()
            # Drop claim row if present (operator sessions may not have claims).
            from mailbox_service.models import MailboxLeaseClaim

            claim = self._session.get(MailboxLeaseClaim, lease.id)
            if claim is not None:
                self._session.delete(claim)
            self._session.flush()
        return self._to_view(lease)

    def _count_active_sessions(self) -> int:
        leases = list(
            self._session.scalars(
                select(Lease).where(
                    Lease.purpose == OPERATOR_DEBUG_PURPOSE,
                    Lease.released_at.is_(None),
                )
            )
        )
        return sum(1 for lease in leases if not is_expired(lease.expires_at))

    def _load_operator_lease(self, lease_id: str, *, require_active: bool) -> Lease:
        lease = self._session.get(Lease, lease_id)
        if lease is None or lease.purpose != OPERATOR_DEBUG_PURPOSE:
            raise OperatorSessionNotFoundError("联调会话不存在")
        if require_active:
            if lease.released_at is not None or is_expired(lease.expires_at):
                raise OperatorSessionNotFoundError("联调会话已释放或已过期")
        return lease

    def _to_view(self, lease: Lease) -> OperatorSessionView:
        resource = (
            self._session.get(MailboxProviderResource, lease.provider_resource_id)
            if lease.provider_resource_id
            else None
        )
        address = (
            (lease.allocated_email or (resource.primary_email if resource else "") or "").strip().lower()
        )
        return OperatorSessionView(
            lease_id=lease.id,
            provider_type=lease.provider_type,
            provider_instance_id=lease.provider_instance_id or "default",
            provider_resource_id=lease.provider_resource_id or "",
            address=address,
            purpose=lease.purpose or OPERATOR_DEBUG_PURPOSE,
            expires_at=lease.expires_at,
            created_at=lease.created_at,
            released_at=lease.released_at,
            last_verification_code=resource.last_verification_code if resource else None,
            last_code_checked_at=resource.last_code_checked_at if resource else None,
        )
