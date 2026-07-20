"""MySQL 8 integration fixtures.

These tests require TEST_DATABASE_URL pointing at a disposable MySQL 8 schema.
They must not run against SQLite: FOR UPDATE / SKIP LOCKED / 1205 / 1213 behavior differs.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.migration_runner import run_pending_migrations


def pytest_collection_modifyitems(config, items):  # noqa: ANN001
    """Skip mysql-marked tests when TEST_DATABASE_URL is not a MySQL URL."""
    database_url = os.environ.get("TEST_DATABASE_URL", "")
    if database_url.startswith("mysql"):
        return
    skip_mysql = pytest.mark.skip(reason="TEST_DATABASE_URL MySQL 8 is required for mysql tests")
    for item in items:
        if "mysql" in item.keywords:
            item.add_marker(skip_mysql)


@pytest.fixture
def mysql_settings() -> Settings:
    database_url = os.environ.get("TEST_DATABASE_URL", "")
    if not database_url.startswith("mysql"):
        pytest.skip("TEST_DATABASE_URL MySQL 8 is required")
    return Settings(
        database_url=database_url,
        app_env="test",
        auto_migrate_on_startup=True,
        admin_api_token="mysql-test-admin-token-long-enough",
        credential_encryption_key=os.environ.get(
            "TEST_CREDENTIAL_ENCRYPTION_KEY",
            # 32 zero bytes urlsafe base64 for disposable test DBs only.
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        cors_allow_origins="http://localhost:5173",
        tls_mode="disabled",
    )


@pytest.fixture
def mysql_engine(mysql_settings: Settings):
    if not mysql_settings.database_url.startswith("mysql"):
        pytest.skip("refusing non-MySQL URL for mysql tests")
    # Allow 32-thread lease races without pool exhaustion (each worker opens a Session).
    engine = create_engine(
        mysql_settings.database_url,
        pool_pre_ping=True,
        pool_size=40,
        max_overflow=16,
        pool_timeout=10,
        future=True,
    )
    with engine.connect() as connection:
        connection.execute(text("SET SESSION innodb_lock_wait_timeout = 2"))
        connection.commit()
    # Migration failure must fail the suite — never mask with Base.metadata.create_all().
    run_pending_migrations(engine, mysql_settings)
    yield engine
    engine.dispose()


@pytest.fixture
def mysql_session_factory(mysql_engine):
    return sessionmaker(bind=mysql_engine, autoflush=False, expire_on_commit=False)
