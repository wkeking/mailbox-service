"""SMSBower Gmail inventory: replenish, evidence, remote finalize (no Microsoft Token path)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.models import ProviderOperationStatus
from mailbox_service.provider_operation_service import ProviderOperationService
from mailbox_service.providers.ports import (
    ExternalOperationResult,
    InboxMessageEvidence,
    ReleaseOperationSnapshot,
    VerificationAllocationSnapshot,
    VerificationEvidence,
    VerificationQuery,
)
from mailbox_service.providers.smsbower_contracts import (
    SMSBOWER_DEFAULT_DOMAIN,
    SMSBOWER_DEFAULT_INSTANCE_ID,
    SMSBOWER_PROVIDER_TYPE,
    SMSBOWER_STATUS_CLOSE_FAILED,
    SMSBOWER_STATUS_CLOSE_SUCCESS,
    SmsBowerContractError,
    build_get_activation_request,
    build_get_code_request,
    build_set_status_request,
    normalize_smsbower_base_url,
)
from mailbox_service.providers.smsbower_transport import (
    HttpxSmsBowerClient,
    SmsBowerMailTransport,
    SmsBowerTransportError,
)
from mailbox_service.security import CredentialCipher


class SmsBowerUnsupportedFilterError(Exception):
    """Raised when verification filters cannot be applied to direct-code evidence."""


class SmsBowerNotConfiguredError(Exception):
    """Raised when SMSBower is disabled or missing API key (authorized callers only)."""


@dataclass(frozen=True)
class SmsBowerReplenishOutcome:
    operation_id: str
    status: str
    mailbox_id: str | None
    primary_email: str | None
    external_resource_id: str | None
    error_class: str | None


class SmsBowerGmailProvider:
    """Inventory replenisher + evidence source + remote finalizer for one instance."""

    def __init__(
        self,
        settings: Settings,
        *,
        credential_cipher: CredentialCipher,
        session_factory: sessionmaker[Session],
        transport: SmsBowerMailTransport | None = None,
    ) -> None:
        self._settings = settings
        self._credential_cipher = credential_cipher
        self._session_factory = session_factory
        self._injected_transport = transport

    def _resolve_runtime(self):
        from mailbox_service.provider_settings_service import ProviderSettingsService

        session = self._session_factory()
        try:
            return ProviderSettingsService(
                session, self._settings, self._credential_cipher
            ).resolve_smsbower_runtime()
        finally:
            session.close()

    def _build_transport(self, runtime) -> SmsBowerMailTransport:
        if self._injected_transport is not None:
            return self._injected_transport
        return SmsBowerMailTransport(
            HttpxSmsBowerClient(timeout_seconds=runtime.request_timeout_seconds),
            api_key=(runtime.api_key or "").strip(),
        )

    @property
    def provider_type(self) -> str:
        return SMSBOWER_PROVIDER_TYPE

    @property
    def instance_id(self) -> str:
        try:
            return self._resolve_runtime().instance_id
        except Exception:
            return (self._settings.smsbower_instance_id or SMSBOWER_DEFAULT_INSTANCE_ID).strip()

    def ensure_configured(self) -> None:
        runtime = self._resolve_runtime()
        if not runtime.enabled:
            raise SmsBowerNotConfiguredError("SMSBower is not enabled")
        if not (runtime.api_key or "").strip():
            raise SmsBowerNotConfiguredError("SMSBower API key is not configured")

    def replenish_one(self, *, actor_id: str = "admin") -> SmsBowerReplenishOutcome:
        """Admin-triggered single activation purchase with durable operation."""
        runtime = self._resolve_runtime()
        if not runtime.enabled:
            raise SmsBowerNotConfiguredError("SMSBower is not enabled")
        if not (runtime.api_key or "").strip():
            raise SmsBowerNotConfiguredError("SMSBower API key is not configured")
        transport = self._build_transport(runtime)
        operation_id = str(uuid.uuid4())
        idempotency_key = f"replenish:{runtime.instance_id}:{operation_id}"
        session = self._session_factory()
        try:
            ops = ProviderOperationService(session, session_factory=self._session_factory)
            snapshot = ops.create_pending_operation(
                operation_type="replenish",
                provider_type=SMSBOWER_PROVIDER_TYPE,
                provider_instance_id=runtime.instance_id,
                idempotency_key=idempotency_key,
            )
            ops.mark_running(snapshot.operation_id)
            session.commit()
            operation_id = snapshot.operation_id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        prepared = build_get_activation_request(
            base_url=normalize_smsbower_base_url(runtime.api_base),
            service=runtime.service,
            domain=runtime.domain or SMSBOWER_DEFAULT_DOMAIN,
            max_price=runtime.max_price,
        )
        try:
            activation = transport.get_activation(prepared)
        except SmsBowerTransportError as error:
            return self._finalize_replenish_failure(
                operation_id,
                error_class="timeout" if error.is_timeout else "transport",
                unknown=error.is_unknown,
            )
        except SmsBowerContractError:
            return self._finalize_replenish_failure(
                operation_id,
                error_class="contract",
                unknown=False,
            )

        external_resource_id = str(activation["id"])
        primary_email = str(activation["email"]).strip().lower()
        cost = activation.get("cost")
        secret_payload = json.dumps(
            {"mail_id": external_resource_id, "email": primary_email},
            ensure_ascii=False,
        )
        encrypted_secret = self._credential_cipher.encrypt(secret_payload)

        session = self._session_factory()
        try:
            ops = ProviderOperationService(session, session_factory=self._session_factory)
            mailbox_id = ops.finalize_smsbower_replenish_success(
                operation_id=operation_id,
                provider_instance_id=runtime.instance_id,
                external_resource_id=external_resource_id,
                primary_email=primary_email,
                encrypted_secret=encrypted_secret,
                cost=float(cost) if cost is not None else None,
                actor_id=actor_id,
            )
            session.commit()
            return SmsBowerReplenishOutcome(
                operation_id=operation_id,
                status=ProviderOperationStatus.SUCCEEDED.value,
                mailbox_id=mailbox_id,
                primary_email=primary_email,
                external_resource_id=external_resource_id,
                error_class=None,
            )
        except Exception:
            session.rollback()
            return self._finalize_replenish_failure(
                operation_id,
                error_class="finalize",
                unknown=True,
            )
        finally:
            session.close()

    def _finalize_replenish_failure(
        self,
        operation_id: str,
        *,
        error_class: str,
        unknown: bool,
    ) -> SmsBowerReplenishOutcome:
        status = (
            ProviderOperationStatus.UNKNOWN.value
            if unknown
            else ProviderOperationStatus.FAILED.value
        )
        session = self._session_factory()
        try:
            ops = ProviderOperationService(session, session_factory=self._session_factory)
            ops.finalize_operation(
                operation_id,
                status=status,
                error_class=error_class,
                result_summary={"error_class": error_class},
            )
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()
        return SmsBowerReplenishOutcome(
            operation_id=operation_id,
            status=status,
            mailbox_id=None,
            primary_email=None,
            external_resource_id=None,
            error_class=error_class,
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        """Direct getCode evidence; unsupported filters fail closed."""
        if any(
            (
                query.from_address,
                query.subject_contains,
                query.body_contains,
                query.recipient,
                query.newer_than,
            )
        ):
            raise SmsBowerUnsupportedFilterError(
                "SMSBower direct-code path does not support message filters"
            )
        mail_id = allocation.access_context.get("mail_id") or allocation.access_context.get(
            "external_resource_id"
        )
        if not mail_id:
            raise RuntimeError("SMSBower evidence requires mail_id in access_context")
        runtime = self._resolve_runtime()
        transport = self._build_transport(runtime)
        prepared = build_get_code_request(
            base_url=normalize_smsbower_base_url(runtime.api_base),
            mail_id=mail_id,
        )
        code, is_pending = transport.get_code(prepared)
        if is_pending or not code:
            return VerificationEvidence(messages=(), direct_code=None, read_method="getCode")
        return VerificationEvidence(
            messages=(
                InboxMessageEvidence(
                    from_address=None,
                    subject=None,
                    body_text=None,
                    received_at=None,
                    recipient_addresses=frozenset(),
                    channel=None,
                    direct_code=code,
                ),
            ),
            direct_code=code,
            read_method="getCode",
        )

    def finalize(self, request: ReleaseOperationSnapshot) -> ExternalOperationResult:
        runtime = self._resolve_runtime()
        transport = self._build_transport(runtime)
        prepared = build_set_status_request(
            base_url=normalize_smsbower_base_url(runtime.api_base),
            mail_id=request.external_resource_id,
            status=request.remote_status,
        )
        try:
            summary = transport.set_status(prepared)
            return ExternalOperationResult(
                operation_id=request.operation_id,
                outcome="succeeded",
                raw_summary=summary[:200] if summary else None,
            )
        except SmsBowerTransportError as error:
            if error.is_unknown or error.is_timeout:
                return ExternalOperationResult(
                    operation_id=request.operation_id,
                    outcome="unknown",
                    error_class="timeout" if error.is_timeout else "transport_unknown",
                )
            return ExternalOperationResult(
                operation_id=request.operation_id,
                outcome="failed",
                error_class="transport",
            )

    def remote_status_for_outcome(self, *, success: bool) -> int:
        return SMSBOWER_STATUS_CLOSE_SUCCESS if success else SMSBOWER_STATUS_CLOSE_FAILED
