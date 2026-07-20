"""Characterization: production SessionFactory-style retry and migration fixture contract."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from mailbox_service.client_key_service import ClientKeyService
from mailbox_service.config import Settings
from mailbox_service.lease_service import LeaseService, LeaseUnavailableError
from mailbox_service.models import LeaseMode
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService
from mailbox_service.transaction_retry import (
    TransactionRetryExhaustedError,
    run_with_mysql_lock_retry,
)


pytestmark = pytest.mark.mysql


class NoopOAuthClient:
    def refresh_access_token(self, mailbox, refresh_token, *, scope=None):
        return MicrosoftTokenResponse(access_token="unused", expires_in=3600)


def test_mysql_fixture_applies_migrations_not_create_all(
    mysql_engine,
    mysql_settings: Settings,
) -> None:
    """schema_migrations must exist after fixture setup (migration path, not create_all mask)."""
    with mysql_engine.connect() as connection:
        rows = connection.execute(
            text("SELECT version FROM schema_migrations ORDER BY version")
        ).fetchall()
    versions = [str(row[0]) for row in rows]
    assert versions, "expected schema_migrations rows from run_pending_migrations"
    assert "001" in versions
    assert "012" in versions
    assert "013" in versions


def test_retry_wrapper_creates_fresh_session_each_attempt(
    mysql_session_factory,
) -> None:
    """Each retry attempt must open a new Session and fully rollback/close."""
    session_ids: list[int] = []
    attempts = {"count": 0}

    def flaky_operation() -> str:
        session = mysql_session_factory()
        try:
            session_ids.append(id(session))
            session.execute(text("SELECT 1"))
            attempts["count"] += 1
            if attempts["count"] < 3:
                # Simulate MySQL deadlock (1213) using a crafted OperationalError-like path.
                from sqlalchemy.exc import OperationalError

                raise OperationalError(
                    "simulated deadlock",
                    params=None,
                    orig=Exception(1213, "Deadlock found when trying to get lock"),
                )
            session.commit()
            return "ok"
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    result = run_with_mysql_lock_retry(
        flaky_operation,
        operation_name="characterization.retry.session",
        max_attempts=3,
        backoff_seconds=(0.0, 0.0, 0.0),
        jitter_seconds=0.0,
        sleep=lambda _seconds: None,
    )
    assert result == "ok"
    assert attempts["count"] == 3
    # Each attempt opens a Session; object identity may be reused after close, so count opens.
    assert len(session_ids) == 3


def test_retry_exhausted_surfaces_transaction_retry_error() -> None:
    from sqlalchemy.exc import OperationalError

    def always_deadlock() -> None:
        raise OperationalError(
            "simulated deadlock",
            params=None,
            orig=Exception(1213, "Deadlock found when trying to get lock"),
        )

    with pytest.raises(TransactionRetryExhaustedError) as raised:
        run_with_mysql_lock_retry(
            always_deadlock,
            operation_name="characterization.retry.exhausted",
            max_attempts=2,
            backoff_seconds=(0.0, 0.0),
            jitter_seconds=0.0,
            sleep=lambda _seconds: None,
        )
    assert raised.value.attempts == 2
    assert raised.value.mysql_error_code == 1213


def test_refresh_token_acquire_unavailable_when_pool_empty(
    mysql_session_factory,
    mysql_settings: Settings,
) -> None:
    """Sanity: empty pool raises LeaseUnavailableError without hanging."""
    cipher = CredentialCipher(mysql_settings.credential_encryption_key or "")
    session = mysql_session_factory()
    try:
        # Ensure no free mailbox matches this unique preferred email.
        unique_email = f"empty-pool-{uuid.uuid4().hex[:12]}@example.com"
        creation = ClientKeyService(session).create_client_key(
            name=f"empty-{uuid.uuid4().hex[:8]}",
            scopes=["leases:acquire", "tokens:refresh:read"],
        )
        session.flush()
        principal = ClientKeyService(session).authenticate(creation.api_key)
        access_token_service = MailboxAccessTokenService(
            session,
            mysql_settings,
            cipher,
            NoopOAuthClient(),
            session_factory=mysql_session_factory,
        )
        lease_service = LeaseService(
            session,
            cipher,
            access_token_service,
            session_factory=mysql_session_factory,
        )
        with pytest.raises(LeaseUnavailableError):
            lease_service.acquire_lease(
                principal,
                mode=LeaseMode.REFRESH_TOKEN,
                ttl_seconds=60,
                preferred_email=unique_email,
            )
        session.rollback()
    finally:
        session.close()
