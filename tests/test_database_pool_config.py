"""Database pool configuration tests."""

from __future__ import annotations

from mailbox_service.config import Settings
from mailbox_service.database import create_database_engine


def test_worker_budget_respects_pool() -> None:
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        batch_max_workers=32,
        database_pool_size=8,
        database_max_overflow=0,
    )
    assert settings.database_worker_budget <= 8
    assert settings.database_worker_budget >= 1


def test_sqlite_engine_skips_mysql_pool_args() -> None:
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", app_env="test")
    engine = create_database_engine(settings)
    assert engine.dialect.name == "sqlite"
