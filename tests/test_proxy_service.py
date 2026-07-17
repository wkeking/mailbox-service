"""Focused regression tests for sticky egress proxy assignment behavior."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import EgressProxy, EgressProxyProtocol, EgressProxyStatus, Mailbox
from mailbox_service.proxy_service import EgressProxyService, NoHealthyEgressProxyError, ProxyIMAP4SSL
from mailbox_service.security import CredentialCipher


def create_test_service(failure_threshold: int = 3) -> tuple[Session, EgressProxyService]:
    """Build an isolated SQLite-backed service with a deterministic encryption key."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"p" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        proxy_failure_threshold=failure_threshold,
    )
    return session, EgressProxyService(session, settings, CredentialCipher(encryption_key))


def create_proxy(name: str, priority: int = 100) -> EgressProxy:
    """Create a healthy proxy suitable for deterministic selection assertions."""
    return EgressProxy(
        name=name,
        protocol=EgressProxyProtocol.SOCKS5,
        host=f"{name}.example.test",
        port=1080,
        priority=priority,
        status=EgressProxyStatus.HEALTHY,
    )


def test_mailbox_reuses_its_healthy_proxy_binding() -> None:
    """OAuth and IMAP callers resolve the same proxy while it remains healthy."""
    session, proxy_service = create_test_service()
    first_proxy = create_proxy("first", priority=10)
    second_proxy = create_proxy("second", priority=20)
    mailbox = Mailbox(primary_email="owner@outlook.com")
    session.add_all([first_proxy, second_proxy, mailbox])
    session.flush()

    first_resolution = proxy_service.resolve_for_mailbox(mailbox.id)
    second_resolution = proxy_service.resolve_for_mailbox(mailbox.id)

    assert first_resolution is not None
    assert second_resolution is not None
    assert first_resolution.id == first_proxy.id
    assert second_resolution.id == first_proxy.id
    assert mailbox.egress_proxy_id == first_proxy.id


def test_commit_open_transaction_releases_proxy_row_for_sibling_session() -> None:
    """After bind+commit, another session must be able to claim the same proxy row.

    Without an early commit, FOR UPDATE held across OAuth I/O makes concurrent batch
    workers observe SKIP LOCKED empty pools and fail with NoHealthyEgressProxyError.
    """
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False)
    encryption_key = urlsafe_b64encode(b"p" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        proxy_required=True,
        proxy_enabled=True,
    )
    cipher = CredentialCipher(encryption_key)

    seed_session = session_factory()
    sole_proxy = create_proxy("only", priority=10)
    first_mailbox = Mailbox(primary_email="first@outlook.com")
    second_mailbox = Mailbox(primary_email="second@outlook.com")
    seed_session.add_all([sole_proxy, first_mailbox, second_mailbox])
    seed_session.commit()
    sole_proxy_id = sole_proxy.id
    first_mailbox_id = first_mailbox.id
    second_mailbox_id = second_mailbox.id
    seed_session.close()

    worker_session = session_factory()
    worker_service = EgressProxyService(worker_session, settings, cipher)
    first_resolution = worker_service.resolve_for_mailbox(first_mailbox_id)
    assert first_resolution is not None
    assert first_resolution.id == sole_proxy_id
    # Critical: release FOR UPDATE before long network I/O / sibling workers bind.
    worker_service.commit_open_transaction()

    sibling_session = session_factory()
    sibling_service = EgressProxyService(sibling_session, settings, cipher)
    # Sticky reuse path should still work after sibling binds.
    second_resolution = sibling_service.resolve_for_mailbox(second_mailbox_id)
    assert second_resolution is not None
    assert second_resolution.id == sole_proxy_id
    sibling_service.commit_open_transaction()

    worker_session.close()
    sibling_session.close()


def test_failed_proxy_enters_cooldown_and_mailbox_switches() -> None:
    """A failed sticky proxy is excluded while a healthy alternative is available."""
    session, proxy_service = create_test_service(failure_threshold=1)
    first_proxy = create_proxy("first", priority=10)
    second_proxy = create_proxy("second", priority=20)
    mailbox = Mailbox(primary_email="owner@outlook.com")
    session.add_all([first_proxy, second_proxy, mailbox])
    session.flush()

    initial_resolution = proxy_service.resolve_for_mailbox(mailbox.id)
    assert initial_resolution is not None
    proxy_service.record_proxy_failure(initial_resolution.id, TimeoutError("connect timed out"))

    replacement_resolution = proxy_service.resolve_for_mailbox(mailbox.id)

    assert first_proxy.status == EgressProxyStatus.COOLDOWN
    assert replacement_resolution is not None
    assert replacement_resolution.id == second_proxy.id
    assert mailbox.egress_proxy_id == second_proxy.id


def test_required_proxy_policy_never_silently_falls_back_to_direct() -> None:
    """The resolver emits the stable error when a required pool is empty."""
    session, proxy_service = create_test_service()
    mailbox = Mailbox(primary_email="owner@outlook.com")
    session.add(mailbox)
    session.flush()
    policy = proxy_service.ensure_policy()
    policy.required = True

    with pytest.raises(NoHealthyEgressProxyError) as raised_error:
        proxy_service.resolve_for_mailbox(mailbox.id)

    assert raised_error.value.error_code == "NO_HEALTHY_EGRESS_PROXY"


def test_proxy_credentials_are_encrypted_and_hidden_from_representation() -> None:
    """Connection settings retain credentials only in non-repr in-memory fields."""
    session, proxy_service = create_test_service()
    encryption_key = urlsafe_b64encode(b"p" * 32).decode("ascii")
    cipher = CredentialCipher(encryption_key)
    proxy = EgressProxy(
        name="authenticated",
        protocol=EgressProxyProtocol.HTTP_CONNECT,
        host="proxy.example.test",
        port=8080,
        username_ciphertext=cipher.encrypt("proxy-user"),
        password_ciphertext=cipher.encrypt("proxy-secret"),
        status=EgressProxyStatus.HEALTHY,
    )
    mailbox = Mailbox(primary_email="owner@outlook.com")
    session.add_all([proxy, mailbox])
    session.flush()

    resolution = proxy_service.resolve_for_mailbox(mailbox.id)

    assert resolution is not None
    assert "proxy-secret" not in repr(resolution)
    assert "proxy-user" not in repr(resolution)
    assert proxy.password_ciphertext != "proxy-secret"


def test_orm_enum_values_match_the_mysql_migration_contract() -> None:
    """Avoid storing Python enum names that MySQL ENUM columns do not accept."""
    assert EgressProxy.__table__.c.protocol.type.enums == ["http_connect", "socks5"]


def test_proxy_imap_open_exposes_makefile_stream_for_current_python() -> None:
    """ProxyIMAP4SSL must wire the makefile stream so AUTHENTICATE can read responses.

    Production images currently run Python 3.12 where imaplib expects ``self.file``.
    Local/dev may already be on 3.14 where ``file`` is a read-only property over ``_file``.
    Either shape must expose a readable stream without falling through IMAP4.__getattr__.
    """

    class FakeSocket:
        def makefile(self, mode: str) -> object:
            assert mode == "rb"
            return object()

        def settimeout(self, timeout_seconds: float | None) -> None:
            return None

    client = ProxyIMAP4SSL.__new__(ProxyIMAP4SSL)
    client._connected_socket = FakeSocket()
    client._server_hostname = "outlook.office365.com"
    client._timeout_seconds = 5.0

    with patch("mailbox_service.proxy_service.ssl.create_default_context") as create_default_context:
        ssl_context = MagicMock()
        ssl_context.wrap_socket.return_value = FakeSocket()
        create_default_context.return_value = ssl_context
        ProxyIMAP4SSL.open(client, "outlook.office365.com", 993, 5.0)

    assert getattr(client, "_file", None) is not None
    # Accessing .file must resolve to the makefile stream, never IMAP4.__getattr__.
    assert client.file is client._file
