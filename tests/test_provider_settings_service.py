"""Admin-editable SMSBower settings (DB overrides env; secrets encrypted)."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import ProviderInstanceSettings
from mailbox_service.provider_settings_service import ProviderSettingsService
from mailbox_service.security import CredentialCipher


def _build(*, env_enabled: bool = False, env_key: str | None = None):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    key = urlsafe_b64encode(b"p" * 32).decode()
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        credential_encryption_key=key,
        smsbower_enabled=env_enabled,
        smsbower_api_key=env_key,
        smsbower_instance_id="default",
    )
    cipher = CredentialCipher(key)
    service = ProviderSettingsService(session, settings, cipher)
    return session, cipher, service, settings


def test_env_fallback_when_no_db_row() -> None:
    _, _, service, _ = _build(env_enabled=True, env_key="env-secret")
    view = service.get_smsbower_admin_view()
    assert view.enabled is True
    assert view.has_api_key is True
    assert view.source == "environment"
    runtime = service.resolve_smsbower_runtime()
    assert runtime.api_key == "env-secret"


def test_update_encrypts_api_key_and_never_returns_plaintext() -> None:
    session, cipher, service, _ = _build(env_enabled=False, env_key=None)
    view = service.update_smsbower(enabled=True, api_key="page-secret-key", service="openai")
    assert view.enabled is True
    assert view.has_api_key is True
    assert view.source == "database"
    assert "page-secret" not in str(view)

    row = session.get(ProviderInstanceSettings, ("smsbower_gmail", "default"))
    assert row is not None
    assert row.api_key_ciphertext
    assert "page-secret" not in row.api_key_ciphertext
    assert cipher.decrypt(row.api_key_ciphertext) == "page-secret-key"

    runtime = service.resolve_smsbower_runtime()
    assert runtime.api_key == "page-secret-key"
    assert runtime.enabled is True


def test_db_overrides_env_enabled_flag() -> None:
    _, _, service, _ = _build(env_enabled=True, env_key="env-key")
    service.update_smsbower(enabled=False)
    runtime = service.resolve_smsbower_runtime()
    assert runtime.enabled is False
    assert runtime.source == "database"


def test_clear_api_key() -> None:
    _, _, service, _ = _build()
    service.update_smsbower(api_key="to-clear")
    assert service.resolve_smsbower_runtime().has_api_key is True
    service.update_smsbower(clear_api_key=True)
    runtime = service.resolve_smsbower_runtime()
    # No env key either
    assert runtime.has_api_key is False


def test_catalog_lists_all_planned_providers() -> None:
    _, _, service, _ = _build()
    items = service.list_provider_summaries()
    types = {item["provider_type"] for item in items}
    assert "microsoft" in types
    assert "smsbower_gmail" in types
    assert "cloudflare_temp_email" in types
    assert "ddg_mail" in types
    assert len(types) == 11
    microsoft = next(item for item in items if item["provider_type"] == "microsoft")
    assert microsoft["configurable_in_ui"] is False
    ondemand = next(item for item in items if item["provider_type"] == "inbucket")
    assert ondemand["configurable_in_ui"] is True
