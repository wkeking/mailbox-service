"""Regression tests for mail_read mailbox acquire and verification-code extraction."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.lease_service import LeaseModeError, LeaseService, LeaseUnavailableError
from mailbox_service.models import Lease, LeaseMode, Mailbox, MailboxCapability, utc_now
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.verification_code_service import (
    IMAP_FETCH_ITEMS,
    InboxMessageCandidate,
    VerificationCodeLookupOptions,
    VerificationCodeService,
    expand_lookback_since_at,
    extract_verification_code,
    is_within_lookback_window,
)


class FakeMicrosoftOAuthClient:
    """OAuth double that never refreshes during pure extraction tests."""

    def refresh_access_token(self, mailbox: Mailbox, refresh_token: str):
        raise AssertionError("verification-code extraction should reuse cached access tokens")


class FakeImapClient:
    """IMAP double that returns RFC822 messages, optionally per folder."""

    def __init__(
        self,
        raw_message: bytes | None = None,
        *,
        internaldate: str | None = None,
        folder_messages: dict[str, bytes] | None = None,
    ) -> None:
        self._folder_messages = dict(folder_messages or {})
        if raw_message is not None:
            # Default fixture puts the code mail in INBOX for backward-compatible tests.
            self._folder_messages.setdefault("INBOX", raw_message)
        self._internaldate = internaldate
        self.connect_calls = 0

    def connect(self, mailbox: Mailbox, access_token: str):
        self.connect_calls += 1
        return FakeImapSession(self._folder_messages, internaldate=self._internaldate)


class FakeImapSession:
    def __init__(
        self,
        folder_messages: dict[str, bytes],
        *,
        internaldate: str | None = None,
    ) -> None:
        self._folder_messages = folder_messages
        self._internaldate = internaldate or utc_now().strftime("%d-%b-%Y %H:%M:%S +0000")
        self._selected_folder: str | None = None
        self.logged_out = False
        self.uid_commands: list[tuple[str, tuple]] = []
        self.selected_folders: list[str] = []

    def select(self, mailbox_name: str, readonly: bool = False):
        assert readonly is True
        self._selected_folder = mailbox_name
        self.selected_folders.append(mailbox_name)
        if mailbox_name in self._folder_messages:
            return "OK", [b"1"]
        # Optional folders such as Junk may be absent on some mailboxes.
        if mailbox_name != "INBOX":
            return "NO", [b"Mailbox does not exist"]
        return "OK", [b"0"]

    def uid(self, command: str, *arguments):
        self.uid_commands.append((command.lower(), arguments))
        selected_folder = self._selected_folder or "INBOX"
        raw_message = self._folder_messages.get(selected_folder)
        if command.lower() == "search":
            assert arguments == (None, "ALL")
            if raw_message is None:
                return "OK", [b""]
            return "OK", [b"1"]
        if command.lower() == "fetch":
            assert arguments[0] == b"1"
            assert arguments[1] == IMAP_FETCH_ITEMS
            if raw_message is None:
                return "OK", []
            metadata = f'1 (UID 1 INTERNALDATE "{self._internaldate}" RFC822 {{{len(raw_message)}}})'
            return "OK", [(metadata.encode("utf-8"), raw_message)]
        return "BAD", [b"unknown command"]

    def search(self, charset, *criteria):
        raise AssertionError("IMAP search should use UID SEARCH ALL, not sequence SEARCH SINCE")

    def fetch(self, message_id, parts):
        raise AssertionError("IMAP fetch should use UID FETCH, not sequence FETCH")

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


def build_rfc822_message(
    *,
    subject: str,
    body: str,
    from_address: str,
    to_address: str = "code@outlook.com",
    cc_address: str | None = None,
) -> bytes:
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = to_address
    if cc_address:
        message["Cc"] = cc_address
    message["Subject"] = subject
    message["Date"] = utc_now().strftime("%a, %d %b %Y %H:%M:%S +0000")
    message.set_content(body)
    return message.as_bytes()


def test_mail_read_acquire_returns_mailbox_without_tokens_and_skips_unproven() -> None:
    """mail_read should only select imap/graph rows, not unprobed/unknown/unusable."""
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
    unprobed_mailbox = Mailbox(
        primary_email="unprobed@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=None,
    )
    unknown_mailbox = Mailbox(
        primary_email="unknown@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.UNKNOWN,
    )
    session.add_all([unusable_mailbox, unprobed_mailbox, unknown_mailbox, usable_mailbox])
    session.flush()

    creation = client_key_service.create_client_key(
        name="registration-bot",
        scopes=["mailboxes:acquire", "mail:verification-code:read", "leases:release"],
    )
    principal = client_key_service.authenticate(creation.api_key)

    result = lease_service.acquire_lease(principal, mode=LeaseMode.MAIL_READ, ttl_seconds=600)

    assert result.primary_email == "usable@outlook.com"
    assert result.allocated_email == "usable@outlook.com"
    assert result.mode == LeaseMode.MAIL_READ
    assert result.access_token is None
    assert result.refresh_token is None
    assert result.client_id is None


def test_mail_read_acquire_can_allocate_plus_alias() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    session.add(
        Mailbox(
            primary_email="owner@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
            capability=MailboxCapability.IMAP,
            access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
            access_token_expires_at=utc_now() + timedelta(minutes=30),
        )
    )
    session.flush()
    creation = client_key_service.create_client_key(
        name="alias-bot",
        scopes=["mailboxes:acquire", "mail:verification-code:read"],
    )
    principal = client_key_service.authenticate(creation.api_key)

    result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        use_plus_alias=True,
        preferred_alias_suffix="reg01",
    )

    assert result.primary_email == "owner@outlook.com"
    assert result.allocated_email == "owner+reg01@outlook.com"
    lease = session.get(Lease, result.lease_id)
    assert lease is not None
    assert lease.allocated_email == "owner+reg01@outlook.com"

    random_alias_result_mailbox = Mailbox(
        primary_email="second@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.IMAP,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token-2"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    session.add(random_alias_result_mailbox)
    session.flush()
    random_result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        preferred_email="second@outlook.com",
        use_plus_alias=True,
    )
    assert random_result.primary_email == "second@outlook.com"
    assert random_result.allocated_email is not None
    assert random_result.allocated_email.startswith("second+")
    assert random_result.allocated_email.endswith("@outlook.com")
    assert random_result.allocated_email != "second@outlook.com"


def test_mail_read_acquire_requires_scope_and_rejects_unproven_pool() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    session.add_all(
        [
            Mailbox(
                primary_email="only-unusable@outlook.com",
                client_id="client-id",
                refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
                capability=MailboxCapability.UNUSABLE,
            ),
            Mailbox(
                primary_email="only-unprobed@outlook.com",
                client_id="client-id",
                refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
                capability=None,
            ),
            Mailbox(
                primary_email="only-unknown@outlook.com",
                client_id="client-id",
                refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
                capability=MailboxCapability.UNKNOWN,
            ),
        ]
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
        raise AssertionError("仅 unprobed/unknown/unusable 邮箱时不应领取成功")


def test_extract_verification_code_prefers_xai_then_digits() -> None:
    assert extract_verification_code("ABC-123 xAI", "ignore 999999") == "ABC-123"
    assert extract_verification_code("Login", "Your verification code is DEF-456.") == "DEF-456"
    assert extract_verification_code("Your code", "请使用验证码 482917 完成登录") == "482917"
    assert extract_verification_code("Hi", "verification code: 112233") == "112233"


def test_verification_code_reads_junk_folder_when_missing_from_inbox() -> None:
    """Personal/consumer mail may land in Junk; mail_read must still extract the code."""
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

    junk_message = build_rfc822_message(
        subject="123",
        body="验证码：666888",
        from_address="sender@example.com",
        to_address="code@outlook.com",
    )
    imap_client = FakeImapClient(folder_messages={"Junk": junk_message})
    verification_service = VerificationCodeService(
        lease_service._access_token_service,
        imap_client,
        FakeGraphReader(),
        sleep_function=lambda _seconds: None,
    )

    result = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )

    assert result.found is True
    assert result.code == "666888"
    assert result.channel == "imap"


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
        to_address="code@outlook.com",
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


def test_verification_code_prefers_xai_format_and_matches_plus_alias_recipient() -> None:
    session, credential_cipher, client_key_service, lease_service = create_mail_read_context()
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=credential_cipher.encrypt("refresh-token"),
        capability=MailboxCapability.IMAP,
        access_token_ciphertext=credential_cipher.encrypt("cached-access-token"),
        access_token_expires_at=utc_now() + timedelta(minutes=30),
    )
    session.add(mailbox)
    session.flush()

    mail_reader_key = client_key_service.create_client_key(
        name="alias-code-bot",
        scopes=["mailboxes:acquire", "mail:verification-code:read"],
    )
    principal = client_key_service.authenticate(mail_reader_key.api_key)
    lease_result = lease_service.acquire_lease(
        principal,
        mode=LeaseMode.MAIL_READ,
        ttl_seconds=600,
        use_plus_alias=True,
        preferred_alias_suffix="alias",
    )
    assert lease_result.allocated_email == "owner+alias@outlook.com"

    raw_message = build_rfc822_message(
        subject="ABC-123 xAI",
        body="Your verification code is ABC-123.",
        from_address="noreply@x.ai",
        to_address="owner+alias@outlook.com",
    )
    imap_client = FakeImapClient(raw_message)
    verification_service = VerificationCodeService(
        lease_service._access_token_service,
        imap_client,
        FakeGraphReader(),
        sleep_function=lambda _seconds: None,
    )

    # Default recipient uses primary when options.recipient is omitted.
    mismatched = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )
    assert mismatched.found is False

    # Lease allocated alias should match the message To header.
    matched = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(
            timeout_seconds=0,
            since_seconds=180,
            recipient=lease_result.allocated_email,
        ),
    )
    assert matched.found is True
    assert matched.code == "ABC-123"
    assert matched.channel == "imap"


def test_verification_code_rejects_non_matching_recipient_by_default() -> None:
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

    raw_message = build_rfc822_message(
        subject="Your code",
        body="请使用验证码 482917 完成登录",
        from_address="noreply@example.com",
        to_address="other@outlook.com",
    )
    verification_service = VerificationCodeService(
        lease_service._access_token_service,
        FakeImapClient(raw_message),
        FakeGraphReader(),
        sleep_function=lambda _seconds: None,
    )

    result = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )
    assert result.found is False

    relaxed = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(
            timeout_seconds=0,
            since_seconds=180,
            require_recipient_match=False,
        ),
    )
    assert relaxed.found is True
    assert relaxed.code == "482917"


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
                recipient_addresses=frozenset({"unknown@outlook.com"}),
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


def test_lookback_window_tolerates_clock_skew_and_missing_timestamps() -> None:
    since_at = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)
    expanded_since_at = expand_lookback_since_at(since_at)
    assert expanded_since_at == since_at - timedelta(minutes=15)

    # Within requested window.
    assert is_within_lookback_window(since_at + timedelta(minutes=1), since_at) is True
    # Outside requested window but inside clock-skew buffer.
    assert is_within_lookback_window(since_at - timedelta(minutes=10), since_at) is True
    # Older than requested window + skew buffer.
    assert is_within_lookback_window(since_at - timedelta(minutes=20), since_at) is False
    # Missing timestamps should not be dropped by the time filter.
    assert is_within_lookback_window(None, since_at) is True
    # Naive timestamps are treated as UTC for comparison.
    assert is_within_lookback_window(datetime(2026, 7, 17, 11, 55, 0), since_at) is True


def test_verification_code_prefers_imap_internaldate_over_stale_date_header() -> None:
    """A fresh INTERNALDATE should keep a message even if Date header looks old."""
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

    message = EmailMessage()
    message["From"] = "noreply@example.com"
    message["To"] = "code@outlook.com"
    message["Subject"] = "Your code"
    # Intentionally stale / local-looking Date that would fail a strict 180s Date filter.
    message["Date"] = (utc_now() - timedelta(hours=8)).strftime("%a, %d %b %Y %H:%M:%S")
    message.set_content("请使用验证码 654321 完成登录")
    raw_message = message.as_bytes()

    fresh_internaldate = utc_now().strftime("%d-%b-%Y %H:%M:%S +0000")
    verification_service = VerificationCodeService(
        lease_service._access_token_service,
        FakeImapClient(raw_message, internaldate=fresh_internaldate),
        FakeGraphReader(),
        sleep_function=lambda _seconds: None,
    )
    result = verification_service.wait_for_verification_code(
        mailbox,
        VerificationCodeLookupOptions(timeout_seconds=0, since_seconds=180),
    )
    assert result.found is True
    assert result.code == "654321"
    assert result.channel == "imap"
