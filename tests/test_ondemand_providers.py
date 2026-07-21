"""Unit tests for on-demand provider adapters, catalog, and settings."""

from __future__ import annotations

from mailbox_service.providers.catalog import (
    ALL_PROVIDER_TYPES,
    ON_DEMAND_PROVIDER_TYPES,
    PROVIDER_DEFINITIONS,
)
from mailbox_service.providers.ondemand_adapters import (
    CloudflareTempEmailAdapter,
    InbucketAdapter,
    OnDemandRuntimeConfig,
    TempMailLolAdapter,
)
from mailbox_service.providers.ports import OnDemandProvisionRequest, VerificationAllocationSnapshot, VerificationQuery
from mailbox_service.providers.registry import SUPPORTED_PROVIDER_TYPES, normalize_provider_type


class FakeHttpClient:
    def __init__(self, responses: list[object] | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._responses = list(responses or [])

    def request_json(self, method, url, **kwargs):
        self.calls.append((method.upper(), url))
        if self._responses:
            return self._responses.pop(0)
        return {}


def test_catalog_covers_all_planned_providers() -> None:
    expected = {
        "microsoft",
        "smsbower_gmail",
        "cloudflare_temp_email",
        "ddg_mail",
        "cloudmail_gen",
        "tempmail_lol",
        "duckmail",
        "gptmail",
        "moemail",
        "inbucket",
        "yyds_mail",
    }
    assert ALL_PROVIDER_TYPES == expected
    assert SUPPORTED_PROVIDER_TYPES == expected
    assert "mailbox_service" not in ALL_PROVIDER_TYPES
    assert len(PROVIDER_DEFINITIONS) == 11
    assert ON_DEMAND_PROVIDER_TYPES == expected - {"microsoft", "smsbower_gmail"}


def test_normalize_provider_type_accepts_ondemand_ids() -> None:
    assert normalize_provider_type("Cloudflare_Temp_Email") == "cloudflare_temp_email"


def test_cloudflare_temp_email_provision_and_evidence() -> None:
    http = FakeHttpClient(
        responses=[
            {"address": "user@example.com", "jwt": "jwt-token"},
            {"results": [{"subject": "Code 123456", "text": "Your code is 123456", "from": "a@b.c"}]},
        ]
    )
    runtime = OnDemandRuntimeConfig(
        provider_type="cloudflare_temp_email",
        instance_id="default",
        enabled=True,
        values={"api_base": "https://cf.example", "domain": ["example.com"]},
        secrets={"admin_password": "secret"},
        timeout_seconds=10,
    )
    adapter = CloudflareTempEmailAdapter(runtime, http_client=http)
    provisioned = adapter.provision(OnDemandProvisionRequest("cloudflare_temp_email", "default"))
    assert provisioned.address == "user@example.com"
    assert provisioned.secret_payload["token"] == "jwt-token"
    evidence = adapter.fetch_evidence(
        VerificationAllocationSnapshot(
            lease_id="l1",
            mailbox_id="m1",
            provider_type="cloudflare_temp_email",
            provider_instance_id="default",
            primary_email="user@example.com",
            allocated_email="user@example.com",
            access_context=dict(provisioned.secret_payload),
        ),
        VerificationQuery(),
    )
    assert len(evidence.messages) == 1
    assert "123456" in (evidence.messages[0].body_text or "")


def test_tempmail_lol_provision() -> None:
    http = FakeHttpClient(responses=[{"address": "a@tempmail.lol", "token": "tok"}])
    runtime = OnDemandRuntimeConfig(
        provider_type="tempmail_lol",
        instance_id="default",
        enabled=True,
        values={},
        secrets={},
        timeout_seconds=10,
    )
    adapter = TempMailLolAdapter(runtime, http_client=http)
    result = adapter.provision(OnDemandProvisionRequest("tempmail_lol", "default"))
    assert result.address == "a@tempmail.lol"
    assert result.secret_payload["token"] == "tok"


def test_inbucket_provision_local_only() -> None:
    runtime = OnDemandRuntimeConfig(
        provider_type="inbucket",
        instance_id="default",
        enabled=True,
        values={"api_base": "http://localhost:9000", "domain": ["local.test"], "random_subdomain": False},
        secrets={},
        timeout_seconds=5,
    )
    adapter = InbucketAdapter(runtime, http_client=FakeHttpClient())
    result = adapter.provision(OnDemandProvisionRequest("inbucket", "default", preferred_local_part="alice"))
    assert result.address.endswith("@local.test")
    assert result.address.startswith("alice@")
    assert result.secret_payload["mailbox_name"] == "alice"


def test_ondemand_acquire_does_not_write_mailboxes() -> None:
    """On-demand provision binds lease to provider resource only."""
    from base64 import urlsafe_b64encode
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from mailbox_service.client_key_service import ClientKeyService
    from mailbox_service.config import Settings
    from mailbox_service.database import Base
    from mailbox_service.lease_service import LeaseService, set_on_demand_provision_hook
    from mailbox_service.models import Lease, LeaseMode, Mailbox, MailboxProviderResource
    from mailbox_service.providers.ports import OnDemandProvisionResult
    from mailbox_service.proxy_service import MicrosoftTokenResponse
    from mailbox_service.security import CredentialCipher
    from mailbox_service.token_service import MailboxAccessTokenService

    class NoopOAuth:
        def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
            return MicrosoftTokenResponse(access_token="x", expires_in=3600)

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    key = urlsafe_b64encode(b"o" * 32).decode()
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", app_env="test", credential_encryption_key=key)
    cipher = CredentialCipher(key)
    token = MailboxAccessTokenService(session, settings, cipher, NoopOAuth(), session_factory=factory)
    lease_service = LeaseService(session, cipher, token, session_factory=factory)

    def _hook(request):
        return OnDemandProvisionResult(
            address="temp@provider.example",
            external_resource_id="ext-1",
            secret_payload={"token": "t"},
            metadata={"source": "test"},
        )

    set_on_demand_provision_hook(_hook)
    try:
        principal = ClientKeyService(session).authenticate(
            ClientKeyService(session)
            .create_client_key(
                name="od",
                scopes=["mailboxes:acquire", "providers:cloudflare_temp_email:acquire", "leases:release"],
            )
            .api_key
        )
        result = lease_service.acquire_lease(
            principal,
            mode=LeaseMode.MAIL_READ,
            ttl_seconds=300,
            provider="cloudflare_temp_email",
            explicit_provider_request=True,
        )
        assert result.mailbox_id is None
        assert result.provider_resource_id is not None
        assert result.primary_email == "temp@provider.example"
        assert session.scalars(select(Mailbox)).first() is None
        resource = session.get(MailboxProviderResource, result.provider_resource_id)
        assert resource is not None
        assert resource.lifecycle_state == "claimed"
        lease = session.get(Lease, result.lease_id)
        assert lease is not None
        assert lease.mailbox_id is None
        assert lease.provider_resource_id == resource.id
        lease_service.release_lease(principal, result.lease_id)
        session.flush()
        resource = session.get(MailboxProviderResource, result.provider_resource_id)
        assert resource.lifecycle_state == "retired"
        assert session.scalars(select(Mailbox)).first() is None
    finally:
        set_on_demand_provision_hook(None)
