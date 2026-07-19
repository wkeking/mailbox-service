"""Tests for verification-code authorization checkpoints."""

from __future__ import annotations

import asyncio

from base64 import urlsafe_b64encode
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseService
from mailbox_service.models import LeaseMode, Mailbox, MailboxCapability, utc_now
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.verification_authorization import (
    VerificationAuthorizationError,
    revalidate_verification_authorization,
)
from mailbox_service.verification_code_service import (
    VerificationCodeLookupOptions,
    VerificationCodeService,
)
from mailbox_service.verification_poll_capacity import (
    VerificationPollCapacityExceededError,
    acquire_verification_poll_slot,
    reset_verification_poll_capacity_for_tests,
)


class FakeOAuth:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="at", expires_in=3600)


def _context():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    key = urlsafe_b64encode(b"v" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=key,
        app_env="test",
        mail_poll_max_concurrency=2,
        mail_poll_max_concurrency_per_client=1,
        mail_poll_max_concurrency_per_lease=1,
    )
    cipher = CredentialCipher(key)
    access = MailboxAccessTokenService(session, settings, cipher, FakeOAuth(), session_factory=session_factory)
    client_keys = ClientKeyService(session)
    leases = LeaseService(session, cipher, access)
    return session, session_factory, settings, cipher, client_keys, leases



def _await_verification(service, *args, **kwargs):
    """Run async verification poll from sync tests."""
    return asyncio.run(service.wait_for_verification_code(*args, **kwargs))


def test_revalidate_rejects_disabled_client_key() -> None:
    session, _, _, cipher, client_keys, leases = _context()
    mailbox = Mailbox(
        primary_email="code@outlook.com",
        client_id="c",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        capability=MailboxCapability.IMAP,
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="poller",
        scopes=["mailboxes:acquire", "mail:verification-code:read", "leases:release"],
    )
    principal = client_keys.authenticate(created.api_key)
    # seed usage site for mail_read
    from mailbox_service.models import UsageSite

    session.add(UsageSite(code="openai", display_name="OpenAI", enabled=True))
    session.flush()
    result = leases.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        usage_site="openai",
    )
    session.flush()
    client_keys.disable_client_key(principal.client_key_id)
    session.flush()
    with pytest.raises(VerificationAuthorizationError) as raised:
        revalidate_verification_authorization(session, principal=principal, lease_id=result.lease_id)
    assert raised.value.code == "CLIENT_KEY_INACTIVE"


def test_checkpoint_blocks_returning_code_after_revoke() -> None:
    session, _, settings, cipher, client_keys, leases = _context()
    from mailbox_service.models import UsageSite

    session.add(UsageSite(code="openai", display_name="OpenAI", enabled=True))
    mailbox = Mailbox(
        primary_email="code2@outlook.com",
        client_id="c",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        capability=MailboxCapability.GRAPH,
    )
    session.add(mailbox)
    session.flush()
    created = client_keys.create_client_key(
        name="poller2",
        scopes=["mailboxes:acquire", "mail:verification-code:read"],
    )
    principal = client_keys.authenticate(created.api_key)
    lease_result = leases.acquire_lease(
        principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600, usage_site="openai"
    )
    session.flush()

    class AlwaysMatchGraph:
        def list_recent_messages(self, mailbox, access_token, *, since_at, max_messages=30):
            from mailbox_service.verification_code_service import InboxMessageCandidate

            return [
                InboxMessageCandidate(
                    from_address="noreply@example.com",
                    subject="ABC-123 xAI",
                    body_text="hi",
                    received_at=utc_now(),
                    channel="graph",
                    recipient_addresses=frozenset({mailbox.primary_email}),
                )
            ]

    class DummyImap:
        def connect(self, mailbox, access_token):
            raise AssertionError("IMAP should not be used in this graph-only test")

    service = VerificationCodeService(
        leases._access_token_service,
        imap_client=DummyImap(),
        graph_reader=AlwaysMatchGraph(),
        settings=settings,
        sleep_function=lambda _s: None,
    )
    calls = {"n": 0}

    def checkpoint():
        calls["n"] += 1
        if calls["n"] >= 2:
            raise VerificationAuthorizationError(code="CLIENT_KEY_INACTIVE", message="disabled")

    with pytest.raises(VerificationAuthorizationError):
        _await_verification(service, 
            mailbox,
            VerificationCodeLookupOptions(timeout_seconds=0, require_recipient_match=False),
            authorization_checkpoint=checkpoint,
        )


def test_poll_capacity_rejects_excess_immediately() -> None:
    reset_verification_poll_capacity_for_tests()
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        mail_poll_max_concurrency=1,
        mail_poll_max_concurrency_per_client=1,
        mail_poll_max_concurrency_per_lease=1,
    )
    with acquire_verification_poll_slot(settings, client_key_id="c1", lease_id="l1"):
        with pytest.raises(VerificationPollCapacityExceededError):
            with acquire_verification_poll_slot(settings, client_key_id="c2", lease_id="l2"):
                pass
    reset_verification_poll_capacity_for_tests()
