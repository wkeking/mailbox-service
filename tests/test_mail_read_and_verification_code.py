"""Regression tests for mail_read mailbox acquire and verification-code extraction."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseModeError, LeaseService, LeaseUnavailableError
from mailbox_service.models import LeaseMode, Mailbox, MailboxCapability, utc_now
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.verification_code_service import (
    InboxMessageCandidate,
    VerificationCodeLookupOptions,
    VerificationCodeService,
)


class FakeMicrosoftOAuthClient:
    """OAuth double that never refreshes during pure extraction tests."""

    def refresh_access_token(self, mailbox: Mailbox, refresh_token: str):
        raise AssertionError("verification-code extraction should reuse cached access tokens")


class FakeImapClient:
    """IMAP double that returns one RFC822 message with a verification code."""

    def __init__(self, raw_message: bytes) -> None:
        self._raw_message = raw_message
        self.connect_calls = 0

    def connect(self, mailbox: Mailbox, access_token: str):
        self.connect_calls += 1
        return FakeImapSession(self._raw_message)


class FakeImapSession:
    def __init__(self, raw_message: bytes) -> None:
        self._raw_message = raw_message
        self.logged_out = False

    def select(self, mailbox_name: str, readonly: bool = False):
        assert mailbox_name == "INBOX"
        assert readonly is True
        return "OK", [b"1"]

    def search(self, charset, *criteria):
        assert criteria[0] == "SINCE"
        return "OK", [b"1"]

    def fetch(self, message_id, parts):
        assert message_id == b"1"
        assert parts == "(RFC822)"
        return "OK", [(b"1 (RFC822)", self._raw_message)]

    def logout(self):
        self.logged_out = True
        return "BYE", []


class FakeGraphReader:
    def __init__(self, messages: list[InboxMessageCandidate] | None = None) -> None:
        self.messages = messages or []
        self.calls = 0

    def list_recent_messages(self, mailbox, access_token, *, since_at, max_messages=30):
        self.calls += 1
        return list(self.messages)


def create_mail_read_context() -> tuple[Session, CredentialCipher, ClientKeyService, LeaseService]:
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"m" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        access_token_refresh_skew_seconds=120,
    )
    credential_cipher = CredentialCipher(encryption_key)
    access_token_service = MailboxAccessTokenService(
        session,
        settings,
        credential_cipher,
        FakeMicrosoftOAuthClient(),
    )
    client_key_service = ClientKeyService(session)
    lease_service = LeaseService(session, credential_cipher, access_token_service)
    return session, credential_cipher, client_key_service, lease_service


def build_rfc822_message(*, subject: str, body: str, from_address: str) -> bytes:
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = "owner@outlook.com"
    message["Subject"] = subject
    message["Date"] = utc_now().strftime("%a, %d %b %Y %H:%M:%S +0000")
    message.set_content(body)
    return message.as_bytes()


def test_mail_read_acquire_returns_mailbox_without_tokens_and_skips_unusable() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    usable_mailbox = Mailbox(
        primary_email="usable@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.IMAP,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    unusable_mailbox = Mailbox(
        primary_email="broken@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.UNUSABLE,
    )
    session.add_all([unusable_mailbox, usable_mailbox])
    session.flush()

    creation = client_key_service.create_client_key(
        name="registration-bot",
        scopes=["mailboxes:acquire", "mail:verification-code:read", "leases:release"],
    )
    principal = client_key_service.authenticate(creation.api_key)

    result = lease_service.acquire_lease(principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600)

    assert result.primary_email == "usable@outlook.com"
    assert result.mode == LeaseMode.MAIL_READ
    assert result.access_token is None
    assert result.refresh_token is None
    assert result.client_id is None


def test_mail_read_acquire_requires_scope_and_rejects_all_unusable_pool() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    session.add(
        Mailbox(
            primary_email="only-unusable@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
            capability=MailboxCapability.UNUSABLE,
        )
    )
    session.flush()
    missing_scope = client_key_service.create_client_key(
        name="token-only",
        scopes=["leases:acquire", "tokens:access:read"],
    )
    principal = client_key_service.authenticate(missing_scope.api_key)

    try:
        lease_service.acquire_lease(principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600)
    except Exception as error:
        assert "mailboxes:acquire" in str(error)
    else:
        raise AssertionError("缺少 mailboxes:acquire 应被拒绝")

    allowed = client_key_service.create_client_key(
        name="mail-reader",
        scopes=["mailboxes:acquire"],
    )
    allowed_principal = client_key_service.authenticate(allowed.api_key)
    try:
        lease_service.acquire_lease(allowed_principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600)
    except LeaseUnavailableError:
        pass
    else:
        raise AssertionError("仅 unusable 邮箱时不应领取成功")


def test_verification_code_extracts_digits_from_imap_and_rejects_wrong_mode() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    mailbox = Mailbox(
        primary_email="code@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.IMAP,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    session.add(mailbox)
    session.flush()

    mail_reader_key = client_key_service.create_client_key(
        name="code-bot",
        scopes=["mailboxes:acquire", "mail:verification-code:read"],
    )
    principal = client_key_service.authenticate(mail_reader_key.api_key)
    lease = lease_service.acquire_lease(principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600)

    raw_message = build_rfc822_message(
        subject="Your code",
        body="请使用验证码 482917 完成登录",
        from_address="noreply@example.com",
    )
    imap_client = FakeImapClient(raw_message)
    graph_reader = FakeGraphReader()
    access_token_service = lease_service._access_token_service
    verification_service = VerificationCodeService(
        access_token_service,
        imap_client,
        graph_reader,
        sleep_function=lambda _seconds: None,
    )

    result = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )

    assert result.found is True
    assert result.code == "482917"
    assert result.channel == "imap"
    assert imap_client.connect_calls == 1
    assert graph_reader.calls == 0

    second_mailbox = Mailbox(
        primary_email="at@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.IMAP,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token-2"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    session.add(second_mailbox)
    session.flush()

    at_key = client_key_service.create_client_key(
        name="at-worker",
        scopes=["leases:acquire", "tokens:access:read", "mail:verification-code:read"],
    )
    at_principal = client_key_service.authenticate(at_key.api_key)
    at_lease = lease_service.acquire_lease(at_principal, mode=LeaseMode.ACCESS_TOKEN, ttl_seconds=600)
    try:
        lease_service.load_active_mail_read_lease(at_principal, at_lease.lease_id)
    except LeaseModeError:
        pass
    else:
        raise AssertionError("access_token 租约不能用于 verification-code")

    # Keep mail_read lease id used so the ownership path is exercised.
    assert lease.lease_id


def test_verification_code_prefers_imap_then_graph_when_capability_missing() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    mailbox = Mailbox(
        primary_email="unknown@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=None,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    session.add(mailbox)
    session.flush()

    class FailingImapClient:
        def connect(self, mailbox: Mailbox, access_token: str):
            raise RuntimeError("imap unavailable")

    graph_reader = FakeGraphReader(
        [
            InboxMessageCandidate(
                from_address="security@example.com",
                subject="Code",
                body_text="code is 778899",
                received_at=utc_now(),
                channel="graph",
            )
        ]
    )
    verification_service = VerificationCodeService(
        lease_service._access_token_service,
        FailingImapClient(),
        graph_reader,
        sleep_function=lambda _seconds: None,
    )
    result = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )
    assert result.found is True
    assert result.code == "778899"
    assert result.channel == "graph"
    assert graph_reader.calls == 1
