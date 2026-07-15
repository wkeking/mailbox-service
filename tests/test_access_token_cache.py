"""Regression tests for mailbox access-token cache and refresh behavior."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from datetime import timedelta
import hashlib
import json
import logging

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import Mailbox, utc_now
from mailbox_service.proxy_service import MicrosoftOAuthError, MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


def build_unsigned_jwt(payload: dict) -> str:
    """Build a JWT-shaped access token for scope-decoding tests."""
    header_segment = urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).rstrip(b"=").decode(
        "ascii"
    )
    payload_segment = urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{header_segment}.{payload_segment}.signature"


class FakeMicrosoftOAuthClient:
    """Small test double that records refresh attempts without real network calls."""

    def __init__(self, responses: list[MicrosoftTokenResponse | Exception]) -> None:
        self.responses = responses
        self.refresh_attempts: list[tuple[str, str]] = []

    def refresh_access_token(self, mailbox: Mailbox, refresh_token: str) -> MicrosoftTokenResponse:
        self.refresh_attempts.append((mailbox.primary_email, refresh_token))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def create_access_token_test_context(
    responses: list[MicrosoftTokenResponse | Exception] | None = None,
    *,
    app_env: str = "production",
    debug_token_logging: bool = False,
) -> tuple[Session, CredentialCipher, FakeMicrosoftOAuthClient, MailboxAccessTokenService]:
    """Build an isolated mailbox token service with deterministic encryption."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"a" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
        access_token_refresh_skew_seconds=120,
        app_env=app_env,
        debug_token_logging=debug_token_logging,
    )
    cipher = CredentialCipher(encryption_key)
    oauth_client = FakeMicrosoftOAuthClient(responses or [])
    service = MailboxAccessTokenService(session, settings, cipher, oauth_client)
    return session, cipher, oauth_client, service


def test_unexpired_cached_access_token_is_returned_without_refresh() -> None:
    """A still-valid cached AT should not trigger a Microsoft refresh request."""
    session, cipher, oauth_client, service = create_access_token_test_context()
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
        access_token_ciphertext=cipher.encrypt("cached-access-token"),
        access_token_expires_at=utc_now() + timedelta(minutes=20),
        access_token_refreshed_at=utc_now() - timedelta(minutes=5),
    )
    session.add(mailbox)
    session.flush()

    result = service.ensure_access_token(mailbox.id)

    assert result.access_token == "cached-access-token"
    assert result.refreshed is False
    assert result.refresh_token_rotated is False
    assert result.expires_at == mailbox.access_token_expires_at
    assert oauth_client.refresh_attempts == []


def test_expired_access_token_refreshes_and_persists_rotated_refresh_token() -> None:
    """Expired AT refresh should update AT metadata and rotated RT version atomically."""
    new_access_token = build_unsigned_jwt(
        {"scp": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"}
    )
    session, cipher, oauth_client, service = create_access_token_test_context(
        [
            MicrosoftTokenResponse(
                access_token=new_access_token,
                expires_in=3600,
                rotated_refresh_token="new-refresh-token",
                scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            )
        ]
    )
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("old-refresh-token"),
        access_token_ciphertext=cipher.encrypt("expired-access-token"),
        access_token_expires_at=utc_now() - timedelta(minutes=1),
        access_token_refreshed_at=utc_now() - timedelta(hours=2),
        token_version=3,
    )
    session.add(mailbox)
    session.flush()

    result = service.ensure_access_token(mailbox.id)

    assert result.access_token == new_access_token
    assert result.refreshed is True
    assert result.refresh_token_rotated is True
    assert result.token_version == 4
    assert mailbox.token_version == 4
    assert mailbox.access_token_ciphertext is not None
    assert mailbox.refresh_token_ciphertext is not None
    assert cipher.decrypt(mailbox.access_token_ciphertext) == new_access_token
    assert cipher.decrypt(mailbox.refresh_token_ciphertext) == "new-refresh-token"
    assert mailbox.scope == "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    assert mailbox.access_token_expires_at is not None
    assert mailbox.access_token_refreshed_at is not None
    assert oauth_client.refresh_attempts == [("owner@outlook.com", "old-refresh-token")]


def test_cached_access_token_backfills_missing_scope_without_refresh() -> None:
    """A still-valid AT should classify scope once when the mailbox has never been inspected."""
    cached_access_token = build_unsigned_jwt({"scp": "Mail.Read offline_access"})
    session, cipher, oauth_client, service = create_access_token_test_context()
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
        access_token_ciphertext=cipher.encrypt(cached_access_token),
        access_token_expires_at=utc_now() + timedelta(minutes=20),
        access_token_refreshed_at=utc_now() - timedelta(minutes=5),
        scope=None,
    )
    session.add(mailbox)
    session.flush()

    result = service.ensure_access_token(mailbox.id)

    assert result.access_token == cached_access_token
    assert result.refreshed is False
    assert mailbox.scope == "Mail.Read offline_access"
    assert oauth_client.refresh_attempts == []


def test_development_token_logging_reports_fingerprints_without_plaintext(caplog) -> None:
    """Development diagnostics should compare Tokens without logging usable credentials."""
    old_refresh_token = "old-refresh-token-that-must-never-appear-in-logs"
    old_access_token = "old-access-token-that-must-never-appear-in-logs"
    new_refresh_token = "new-refresh-token-that-must-never-appear-in-logs"
    new_access_token = "new-access-token-that-must-never-appear-in-logs"
    session, cipher, _, service = create_access_token_test_context(
        [
            MicrosoftTokenResponse(
                access_token=new_access_token,
                expires_in=3600,
                rotated_refresh_token=new_refresh_token,
            )
        ],
        app_env="development",
        debug_token_logging=True,
    )
    mailbox = Mailbox(
        primary_email="debug-owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt(old_refresh_token),
        access_token_ciphertext=cipher.encrypt(old_access_token),
        access_token_expires_at=utc_now() - timedelta(minutes=1),
    )
    session.add(mailbox)
    session.flush()

    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        service.ensure_access_token(mailbox.id, force_refresh=True)

    combined_log_messages = "\n".join(caplog.messages)
    assert "development_token_refresh_response" in combined_log_messages
    assert "refresh_token_changed=true" in combined_log_messages
    assert "access_token_changed=true" in combined_log_messages
    assert hashlib.sha256(old_refresh_token.encode("utf-8")).hexdigest()[:12] in combined_log_messages
    assert hashlib.sha256(new_refresh_token.encode("utf-8")).hexdigest()[:12] in combined_log_messages
    assert hashlib.sha256(old_access_token.encode("utf-8")).hexdigest()[:12] in combined_log_messages
    assert hashlib.sha256(new_access_token.encode("utf-8")).hexdigest()[:12] in combined_log_messages
    assert old_refresh_token not in combined_log_messages
    assert new_refresh_token not in combined_log_messages
    assert old_access_token not in combined_log_messages
    assert new_access_token not in combined_log_messages


def test_token_logging_stays_disabled_outside_development(caplog) -> None:
    """The debug switch must not expose Token metadata outside development."""
    session, cipher, _, service = create_access_token_test_context(
        [MicrosoftTokenResponse(access_token="new-access-token", expires_in=3600)],
        app_env="production",
        debug_token_logging=True,
    )
    mailbox = Mailbox(
        primary_email="production-owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
    )
    session.add(mailbox)
    session.flush()

    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        service.ensure_access_token(mailbox.id, force_refresh=True)

    assert not any("development_token_refresh" in message for message in caplog.messages)


def test_bulk_refresh_continues_after_one_mailbox_failure() -> None:
    """Batch refresh should report per-mailbox failures without skipping later mailboxes."""
    session, cipher, oauth_client, service = create_access_token_test_context(
        [
            MicrosoftTokenResponse(access_token="first-access-token", expires_in=1800),
            MicrosoftOAuthError("Microsoft Token 请求失败，HTTP 500"),
            MicrosoftTokenResponse(access_token="third-access-token", expires_in=1800),
        ]
    )
    mailboxes = [
        Mailbox(
            primary_email="first@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=cipher.encrypt("first-refresh-token"),
        ),
        Mailbox(
            primary_email="second@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=cipher.encrypt("second-refresh-token"),
        ),
        Mailbox(
            primary_email="third@outlook.com",
            client_id="client-id",
            refresh_token_ciphertext=cipher.encrypt("third-refresh-token"),
        ),
    ]
    session.add_all(mailboxes)
    session.flush()

    result = service.refresh_access_tokens([mailbox.id for mailbox in mailboxes])
    stored_mailboxes = session.scalars(select(Mailbox).order_by(Mailbox.primary_email.asc())).all()

    assert result.successful == 2
    assert result.failed == 1
    assert [item.successful for item in result.results] == [True, False, True]
    assert result.results[1].error_summary == "Microsoft Token 请求失败，HTTP 500"
    assert cipher.decrypt(stored_mailboxes[0].access_token_ciphertext or "") == "first-access-token"
    assert stored_mailboxes[1].access_token_ciphertext is None
    assert cipher.decrypt(stored_mailboxes[2].access_token_ciphertext or "") == "third-access-token"


def test_bulk_refresh_deduplicates_selected_mailbox_ids() -> None:
    """A repeated selected mailbox ID should only trigger one Microsoft refresh request."""
    session, cipher, oauth_client, service = create_access_token_test_context(
        [MicrosoftTokenResponse(access_token="new-access-token", expires_in=1800)]
    )
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
    )
    session.add(mailbox)
    session.flush()

    result = service.refresh_access_tokens([mailbox.id, mailbox.id])

    assert result.successful == 1
    assert result.failed == 0
    assert len(result.results) == 1
    assert oauth_client.refresh_attempts == [("owner@outlook.com", "refresh-token")]
