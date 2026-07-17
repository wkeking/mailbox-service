"""Regression tests for egress proxy unique-constraint API mapping."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings, get_settings
from mailbox_service.database import Base, get_session
from mailbox_service.main import app
from mailbox_service.security import build_proxy_credential_fingerprint


def create_admin_test_client() -> TestClient:
    """Build an isolated app client with an in-memory SQLite database."""
    database_engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(database_engine)
    session_factory = sessionmaker(bind=database_engine, expire_on_commit=False, future=True)
    encryption_key = urlsafe_b64encode(b"p" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite://",
        admin_api_token="test-admin-token",
        credential_encryption_key=encryption_key,
    )

    def override_get_session():
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def override_get_settings() -> Settings:
        return settings

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_settings] = override_get_settings
    return TestClient(app)


def test_create_egress_proxy_returns_full_host_for_admin_copy() -> None:
    """Admin list/create responses include full host so the console can prefill copy dialogs."""
    client = create_admin_test_client()
    headers = {"X-Admin-Token": "test-admin-token"}
    create_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={
            "name": "source-proxy",
            "protocol": "socks5",
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "secret",
            "enabled": True,
            "priority": 50,
        },
        headers=headers,
    )
    assert create_response.status_code == 201
    created_body = create_response.json()
    assert created_body["host"] == "proxy.example.com"
    assert created_body["host_preview"] != "proxy.example.com"
    assert created_body["has_credentials"] is True

    list_response = client.get("/api/v1/admin/egress-proxies", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()[0]["host"] == "proxy.example.com"
    app.dependency_overrides.clear()


def test_create_egress_proxy_can_clone_encrypted_credentials_from_source() -> None:
    """Copy flow decrypts source secrets once and re-encrypts; never double-encrypts ciphertext."""
    from sqlalchemy import select

    from mailbox_service.models import EgressProxy
    from mailbox_service.security import CredentialCipher

    client = create_admin_test_client()
    headers = {"X-Admin-Token": "test-admin-token"}
    encryption_key = urlsafe_b64encode(b"p" * 32).decode("ascii")
    source_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={
            "name": "source-proxy",
            "protocol": "socks5",
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "secret",
            "enabled": True,
            "priority": 50,
        },
        headers=headers,
    )
    assert source_response.status_code == 201
    source_proxy_id = source_response.json()["id"]

    clone_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={
            "name": "source-proxy-copy",
            "protocol": "socks5",
            "host": "proxy-copy.example.com",
            "port": 1081,
            "enabled": True,
            "priority": 50,
            "copy_credentials_from_proxy_id": source_proxy_id,
        },
        headers=headers,
    )
    assert clone_response.status_code == 201
    assert clone_response.json()["has_credentials"] is True
    assert clone_response.json()["host"] == "proxy-copy.example.com"

    # Resolve the same session factory used by the overridden dependency via a fresh engine query
    # is not available; re-open through the app override by probing decrypt via create+session.
    # The clone must decrypt back to the original plaintext password.
    with next(app.dependency_overrides[get_session]()) as session:
        cloned_proxy = session.scalar(
            select(EgressProxy).where(EgressProxy.id == clone_response.json()["id"])
        )
        source_proxy = session.scalar(select(EgressProxy).where(EgressProxy.id == source_proxy_id))
        assert cloned_proxy is not None
        assert source_proxy is not None
        cipher = CredentialCipher(encryption_key)
        assert cipher.decrypt(cloned_proxy.password_ciphertext) == "secret"
        assert cipher.decrypt(cloned_proxy.username_ciphertext) == "user"
        # Ciphertext blobs may differ due to random nonce, but both must decrypt to the same secret.
        assert cipher.decrypt(source_proxy.password_ciphertext) == "secret"

    app.dependency_overrides.clear()


def test_create_egress_proxy_allows_same_endpoint_with_different_credentials() -> None:
    """Proxy-pool nodes that share host/port but differ by username/password must both save."""
    client = create_admin_test_client()
    headers = {"X-Admin-Token": "test-admin-token"}
    base_payload = {
        "protocol": "socks5",
        "host": "resin.wkeking.cloud",
        "port": 2260,
        "enabled": True,
        "priority": 100,
    }

    first_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={**base_payload, "name": "pool-user-a", "username": "user-a", "password": "secret-a"},
        headers=headers,
    )
    second_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={**base_payload, "name": "pool-user-b", "username": "user-b", "password": "secret-b"},
        headers=headers,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    app.dependency_overrides.clear()


def test_create_egress_proxy_returns_conflict_for_duplicate_endpoint_and_credentials() -> None:
    """Identical protocol/host/port/username/password still collides."""
    client = create_admin_test_client()
    headers = {"X-Admin-Token": "test-admin-token"}
    payload = {
        "name": "first-proxy",
        "protocol": "socks5",
        "host": "resin.wkeking.cloud",
        "port": 2260,
        "username": "user",
        "password": "secret",
        "enabled": True,
        "priority": 100,
    }

    first_response = client.post("/api/v1/admin/egress-proxies", json=payload, headers=headers)
    second_payload = {**payload, "name": "second-proxy"}
    second_response = client.post("/api/v1/admin/egress-proxies", json=second_payload, headers=headers)

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"]["code"] == "EGRESS_PROXY_ENDPOINT_CONFLICT"
    app.dependency_overrides.clear()


def test_create_egress_proxy_returns_conflict_for_duplicate_name() -> None:
    """Creating two proxies with the same name should return a stable 409 response."""
    client = create_admin_test_client()
    headers = {"X-Admin-Token": "test-admin-token"}

    first_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={
            "name": "shared-name",
            "protocol": "socks5",
            "host": "proxy-a.example.com",
            "port": 1080,
            "enabled": True,
            "priority": 100,
        },
        headers=headers,
    )
    second_response = client.post(
        "/api/v1/admin/egress-proxies",
        json={
            "name": "shared-name",
            "protocol": "socks5",
            "host": "proxy-b.example.com",
            "port": 1081,
            "enabled": True,
            "priority": 100,
        },
        headers=headers,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"]["code"] == "EGRESS_PROXY_NAME_CONFLICT"
    app.dependency_overrides.clear()


def test_proxy_credential_fingerprint_differs_for_different_usernames() -> None:
    """Fingerprint identity must treat username/password as part of the proxy key."""
    first_fingerprint = build_proxy_credential_fingerprint("user-a", "secret")
    second_fingerprint = build_proxy_credential_fingerprint("user-b", "secret")
    third_fingerprint = build_proxy_credential_fingerprint("user-a", "secret")

    assert first_fingerprint != second_fingerprint
    assert first_fingerprint == third_fingerprint
