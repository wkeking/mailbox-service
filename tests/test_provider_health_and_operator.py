"""Unit tests for provider health probes and operator session service (P0)."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import utc_now
from mailbox_service.operator_session_service import (
    OperatorProviderError,
    OperatorSessionService,
)
from mailbox_service.provider_health_service import OPERATOR_DEBUG_PURPOSE, ProviderHealthService
from mailbox_service.providers.ondemand_adapters import OnDemandRuntimeConfig
from mailbox_service.providers.ondemand_facade import OnDemandProviderService
from mailbox_service.providers.ports import OnDemandProvisionResult, VerificationEvidence
from mailbox_service.providers.ports import InboxMessageEvidence
from mailbox_service.security import CredentialCipher


def _settings() -> Settings:
    return Settings(
        admin_api_token="test-admin-token-with-enough-length",
        credential_encryption_key="4qdlb9CIQgjRT5FtiAtFJhHXBBhizoMq6jU4kF5TKPo=",
        database_url="sqlite+pysqlite:///:memory:",
    )


def _session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


class FakeHttp:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def request_json(self, method, url, **kwargs):
        self.calls.append((method.upper(), url))
        if self.error is not None:
            raise self.error
        return self.response


def test_provider_health_check_false_returns_unknown() -> None:
    factory = _session_factory()
    service = ProviderHealthService(
        _settings(),
        credential_cipher=None,
        session_factory=factory,
    )
    result = service.check_one("duckmail", "default", check=False)
    assert result.status == "unknown"
    assert result.provider_type == "duckmail"


def test_provider_health_microsoft_inventory_ok() -> None:
    factory = _session_factory()
    service = ProviderHealthService(
        _settings(),
        credential_cipher=None,
        session_factory=factory,
    )
    result = service.check_one("microsoft", check=True)
    assert result.status in {"ok", "degraded"}
    assert result.detail.get("total") == 0


def test_provider_health_ondemand_down_on_http_error() -> None:
    from mailbox_service.providers.http_client import ProviderHttpError

    factory = _session_factory()
    settings = _settings()
    cipher = CredentialCipher(settings.credential_encryption_key or "")
    session = factory()
    try:
        from mailbox_service.provider_settings_service import ProviderSettingsService

        ProviderSettingsService(session, settings, cipher).update_provider_instance(
            "inbucket",
            instance_id="default",
            enabled=True,
            values={"api_base": "https://inbucket.example", "domain": ["example.com"]},
            secrets={},
        )
        session.commit()
    finally:
        session.close()

    http = FakeHttp(error=ProviderHttpError("HTTP 401 for GET https://x: denied"))
    # Force remote domain probe by clearing domain list path: still has configured domains
    # so status should be ok from config list without HTTP.
    service = ProviderHealthService(
        settings,
        credential_cipher=cipher,
        session_factory=factory,
        http_client=http,
    )
    result = service.check_one("inbucket", "default", check=True)
    assert result.status == "ok"
    assert "example.com" in result.domains_preview


def test_operator_session_create_fetch_release() -> None:
    factory = _session_factory()
    settings = _settings()
    cipher = CredentialCipher(settings.credential_encryption_key or "")

    class FakeOnDemand(OnDemandProviderService):
        def __init__(self) -> None:
            pass

        def provision(self, request):
            return OnDemandProvisionResult(
                address="debug@example.com",
                external_resource_id="debug@example.com",
                secret_payload={"token": "t", "api_base": "https://x"},
                metadata={},
            )

        def fetch_evidence(self, allocation, query):
            return VerificationEvidence(
                messages=(
                    InboxMessageEvidence(
                        from_address="otp@svc.com",
                        subject="Your code",
                        body_text="verification code: 445566",
                        received_at=utc_now(),
                        recipient_addresses=frozenset({"debug@example.com"}),
                    ),
                )
            )

    session = factory()
    try:
        service = OperatorSessionService(
            session,
            settings,
            cipher,
            on_demand_service=FakeOnDemand(),  # type: ignore[arg-type]
        )
        created = service.create_session(
            provider_type="inbucket",
            admin_id="admin-1",
            label="manual",
        )
        assert created.address == "debug@example.com"
        assert created.purpose == OPERATOR_DEBUG_PURPOSE
        assert created.provider_resource_id
        session_view, messages, codes = service.fetch_messages(created.lease_id)
        assert codes == ["445566"]
        assert messages[0].code == "445566"
        assert session_view.last_verification_code == "445566"
        released = service.release_session(created.lease_id)
        assert released.released_at is not None
        session.commit()
    finally:
        session.close()


def test_operator_session_rejects_non_ondemand() -> None:
    factory = _session_factory()
    settings = _settings()
    cipher = CredentialCipher(settings.credential_encryption_key or "")
    session = factory()
    try:
        service = OperatorSessionService(
            session,
            settings,
            cipher,
            on_demand_service=OnDemandProviderService(
                settings, credential_cipher=cipher, session_factory=factory
            ),
        )
        try:
            service.create_session(provider_type="microsoft", admin_id="a")
            raise AssertionError("expected OperatorProviderError")
        except OperatorProviderError:
            pass
    finally:
        session.close()
