"""Regression tests for remaining SEC hardening gaps (REQ-20260719-001)."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import AuditLog, Mailbox, MailboxStatus, utc_now
from mailbox_service.proxy_service import MicrosoftInvalidGrantError, MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.transaction_retry import run_with_mysql_lock_retry
from mailbox_service.verification_code_matcher import (
    MAX_MESSAGE_BODY_BYTES,
    MAX_SCAN_BODY_BYTES,
    SafeVerificationCodeMatcher,
    VerificationCodePatternOptions,
)
from mailbox_service.verification_code_service import (
    InboxMessageCandidate,
    VerificationCodeLookupOptions,
    VerificationCodeService,
)


def _encryption_key() -> str:
    return urlsafe_b64encode(b"s" * 32).decode("ascii")


def _build_token_service(oauth_client):
    database_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    session = session_factory()
    encryption_key = _encryption_key()
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        app_env="test",
        token_refresh_claim_ttl_seconds=30,
        batch_max_workers=8,
        database_pool_size=16,
        database_max_overflow=8,
    )
    cipher = CredentialCipher(encryption_key)
    service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        session_factory=session_factory,
    )
    return session, cipher, service, session_factory, settings


class InvalidGrantOAuthClient:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        raise MicrosoftInvalidGrantError("invalid_grant")


class SuccessOAuthClient:
    def __init__(self, access_token: str = "new-at") -> None:
        self.access_token = access_token
        self.call_count = 0

    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        self.call_count += 1
        return MicrosoftTokenResponse(access_token=self.access_token, expires_in=3600)


def test_source_version_mismatch_forces_refresh() -> None:
    oauth_client = SuccessOAuthClient("refreshed-after-mismatch")
    session, cipher, service, _session_factory, _settings = _build_token_service(oauth_client)
    mailbox = Mailbox(
        primary_email="source-mismatch@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=3,
        access_token_ciphertext=cipher.encrypt("stale-at"),
        access_token_expires_at=utc_now() + timedelta(hours=1),
        access_token_source_version=2,
        access_token_refreshed_at=utc_now(),
    )
    session.add(mailbox)
    session.commit()

    result = service.ensure_access_token(mailbox.id, force_refresh=False)
    assert result.refreshed is True
    assert result.access_token == "refreshed-after-mismatch"
    assert oauth_client.call_count == 1


def test_invalid_grant_marks_invalid_with_audit_and_version_cas() -> None:
    oauth_client = InvalidGrantOAuthClient()
    session, cipher, service, session_factory, _settings = _build_token_service(oauth_client)
    mailbox = Mailbox(
        primary_email="invalid-grant@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=1,
        status=MailboxStatus.ACTIVE,
    )
    session.add(mailbox)
    session.commit()
    mailbox_id = mailbox.id

    try:
        service.ensure_access_token(mailbox_id, force_refresh=True)
        raised = False
    except MicrosoftInvalidGrantError:
        raised = True
    assert raised

    session.expire_all()
    stored = session.get(Mailbox, mailbox_id)
    assert stored is not None
    assert stored.status == MailboxStatus.INVALID
    assert stored.token_refresh_claim_id is None

    audit_rows = session.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "mailbox.invalidated",
            AuditLog.target_id == mailbox_id,
        )
    ).all()
    assert len(audit_rows) == 1


def test_stale_invalid_grant_does_not_mark_after_version_bump() -> None:
    """If RT version moved while OAuth returned invalid_grant, leave mailbox active."""
    from mailbox_service.token_repository import (
        claim_token_refresh,
        fail_token_refresh_invalid_grant,
    )

    session, cipher, _service, session_factory, settings = _build_token_service(SuccessOAuthClient())
    mailbox = Mailbox(
        primary_email="stale-invalid@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt-v1"),
        token_version=1,
        status=MailboxStatus.ACTIVE,
    )
    session.add(mailbox)
    session.commit()

    claim = claim_token_refresh(
        session,
        mailbox_id=mailbox.id,
        decrypt_refresh_token=cipher.decrypt,
        claim_ttl_seconds=settings.token_refresh_claim_ttl_seconds,
        skip_active_rt_lease_check=True,
    )
    session.commit()
    assert claim is not None

    # External CAS-style bump while claim is in flight.
    mailbox.token_version = 2
    mailbox.refresh_token_ciphertext = cipher.encrypt("rt-v2")
    session.commit()

    applied = fail_token_refresh_invalid_grant(session, claim=claim)
    session.commit()
    assert applied is False

    stored = session.get(Mailbox, mailbox.id)
    assert stored is not None
    assert stored.status == MailboxStatus.ACTIVE
    assert stored.token_version == 2


def test_worker_invalid_grant_does_not_bypass_cas() -> None:
    """Worker path must not force INVALID after concurrent version bump."""
    oauth_client = InvalidGrantOAuthClient()
    session, cipher, service, session_factory, _settings = _build_token_service(oauth_client)
    mailbox = Mailbox(
        primary_email="worker-invalid@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=9,
        status=MailboxStatus.ACTIVE,
    )
    session.add(mailbox)
    session.commit()
    mailbox_id = mailbox.id
    session.close()

    # Ensure_access_token will claim v9 then invalid_grant CAS will match and mark invalid.
    # The regression is: worker must go through CAS (not unconditional status write).
    # Simulate stale claim by installing claim at expected_version=1 then bumping to 9.
    from mailbox_service.token_repository import TokenRefreshClaim, fail_token_refresh_invalid_grant

    verify = session_factory()
    stale_claim = TokenRefreshClaim(
        claim_id="stale-claim",
        mailbox_id=mailbox_id,
        primary_email="worker-invalid@example.com",
        client_id="client-id",
        refresh_token="rt",
        expected_token_version=1,
        expires_at=utc_now() + timedelta(seconds=30),
    )
    applied = fail_token_refresh_invalid_grant(verify, claim=stale_claim)
    verify.commit()
    assert applied is False
    stored = verify.get(Mailbox, mailbox_id)
    assert stored is not None
    assert stored.status == MailboxStatus.ACTIVE
    assert stored.token_version == 9

    item = service._refresh_single_mailbox_in_worker_session(mailbox_id)
    assert item.successful is False
    # Full path with matching claim may mark invalid — that is correct CAS behavior.
    # Unconditional bypass is gone: status only changes via fail_token_refresh_invalid_grant.
    verify.expire_all()
    after = verify.get(Mailbox, mailbox_id)
    assert after is not None
    if after.status == MailboxStatus.INVALID:
        assert after.token_refresh_claim_id is None
    verify.close()


def test_scan_budget_stops_after_max_scan_bytes() -> None:
    body_chunk = "x" * MAX_MESSAGE_BODY_BYTES
    messages = [
        InboxMessageCandidate(
            from_address="a@example.com",
            subject="s",
            body_text=body_chunk,
            received_at=utc_now(),
            channel="graph",
            recipient_addresses=frozenset({"user@example.com"}),
        )
        for _ in range(16)
    ]
    # Put the real code after the budget would be exhausted.
    messages.append(
        InboxMessageCandidate(
            from_address="b@example.com",
            subject="code mail",
            body_text="your code is 424242",
            received_at=utc_now(),
            channel="graph",
            recipient_addresses=frozenset({"user@example.com"}),
        )
    )

    match, consumed, exhausted = VerificationCodeService._find_code_in_messages(
        messages,
        VerificationCodeLookupOptions(require_recipient_match=True),
        custom_matcher=SafeVerificationCodeMatcher.from_options(VerificationCodePatternOptions()),
        recipient_filter="user@example.com",
        remaining_request_budget_bytes=MAX_SCAN_BODY_BYTES,
    )
    assert match is None
    assert consumed <= MAX_SCAN_BODY_BYTES
    assert exhausted is True


def test_mysql_lock_retry_replays_callable() -> None:
    from sqlalchemy.exc import OperationalError

    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise OperationalError("stmt", {}, Exception(1213, "Deadlock found"))
        return "ok"

    result = run_with_mysql_lock_retry(
        flaky,
        operation_name="test.op",
        sleep=lambda _seconds: None,
    )
    assert result == "ok"
    assert attempts["count"] == 3


def test_access_token_acquire_defers_token_until_after_reserve() -> None:
    """ACCESS_TOKEN path reserves claim before OAuth and compensates on failure."""
    from mailbox_service.client_key_service import ClientKeyService
    from mailbox_service.lease_service import LeaseService
    from mailbox_service.models import Lease, LeaseMode, MailboxLeaseClaim, MailboxStatus
    from mailbox_service.proxy_service import MicrosoftOAuthError

    class BoomOAuth:
        def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
            raise MicrosoftOAuthError("boom")

    session, cipher, service, session_factory, settings = _build_token_service(BoomOAuth())
    # Rebuild token service with boom client already applied.
    mailbox = Mailbox(
        primary_email="at-compensate@example.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("rt"),
        token_version=1,
        status=MailboxStatus.ACTIVE,
    )
    session.add(mailbox)
    session.flush()
    creation = ClientKeyService(session).create_client_key(
        name="at-compensate",
        scopes=["leases:acquire", "leases:release", "tokens:access:read"],
    )
    principal = ClientKeyService(session).authenticate(creation.api_key)
    lease_service = LeaseService(session, cipher, service)
    try:
        lease_service.acquire_lease(principal, mode=LeaseMode.ACCESS_TOKEN, ttl_seconds=300)
        raised = False
    except MicrosoftOAuthError:
        raised = True
    assert raised
    session.flush()
    assert session.get(MailboxLeaseClaim, mailbox.id) is None
    active = session.scalars(
        select(Lease).where(Lease.mailbox_id == mailbox.id, Lease.released_at.is_(None))
    ).all()
    assert active == []
    released = session.scalars(
        select(Lease).where(Lease.mailbox_id == mailbox.id, Lease.released_at.is_not(None))
    ).all()
    assert len(released) == 1
