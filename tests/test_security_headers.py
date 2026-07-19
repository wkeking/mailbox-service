"""Security response header tests."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mailbox_service.config import Settings, get_settings
from mailbox_service.database import Base, get_session
from mailbox_service.main import app


def test_health_responses_include_security_headers() -> None:
    encryption_key = urlsafe_b64encode(b"s" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        credential_encryption_key=encryption_key,
        admin_api_token="test-admin-token-with-enough-length",
        enable_hsts=False,
    )
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_settings() -> Settings:
        return settings

    def override_session():
        session = session_factory()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_session] = override_session
    try:
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("Referrer-Policy") == "no-referrer"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    finally:
        app.dependency_overrides.clear()
