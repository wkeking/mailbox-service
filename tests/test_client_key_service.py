"""Regression tests for external Client API Key lifecycle and authentication."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.client_key_service import ClientKeyAuthenticationError, ClientKeyService
from mailbox_service.database import Base
from mailbox_service.models import ClientKey


def create_client_key_test_session() -> Session:
    """Build an isolated database session for Client Key tests."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    return sessionmaker(bind=database_engine, expire_on_commit=False)()


def test_client_key_is_returned_once_and_only_digest_is_persisted() -> None:
    """Created API Key plaintext must not be stored in the database."""
    session = create_client_key_test_session()
    service = ClientKeyService(session)

    creation_result = service.create_client_key(
        name="registration-worker",
        scopes=["leases:acquire", "leases:release", "tokens:access:read"],
    )
    stored_client_key = session.get(ClientKey, creation_result.client_key.id)

    assert creation_result.api_key.startswith(f"mbx_{creation_result.client_key.id}.")
    assert stored_client_key is not None
    assert stored_client_key.secret_digest != creation_result.api_key
    assert creation_result.api_key not in stored_client_key.secret_digest

    principal = service.authenticate(creation_result.api_key)
    assert principal.client_key_id == creation_result.client_key.id
    assert principal.scopes == frozenset(["leases:acquire", "leases:release", "tokens:access:read"])


def test_disabled_client_key_cannot_authenticate() -> None:
    """Disabled Client Keys must stop authorizing external requests immediately."""
    session = create_client_key_test_session()
    service = ClientKeyService(session)
    creation_result = service.create_client_key(name="disabled-worker", scopes=["leases:acquire"])
    service.disable_client_key(creation_result.client_key.id)

    try:
        service.authenticate(creation_result.api_key)
    except ClientKeyAuthenticationError:
        pass
    else:
        raise AssertionError("已停用 Client Key 不应通过认证")
