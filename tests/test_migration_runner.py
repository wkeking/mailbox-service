"""Unit tests for startup SQL migration version tracking."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from mailbox_service.config import Settings
from mailbox_service.migration_runner import (
    MigrationError,
    discover_migration_scripts,
    run_pending_migrations,
)


def _write_migration(directory: Path, filename: str, sql_text: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(sql_text, encoding="utf-8")


def test_discover_migration_scripts_sorts_by_version(tmp_path: Path) -> None:
    """Migration files are ordered by numeric version prefix."""
    _write_migration(tmp_path, "002_second.sql", "SELECT 2;")
    _write_migration(tmp_path, "001_first.sql", "SELECT 1;")
    _write_migration(tmp_path, "readme.sql", "SELECT 0;")

    scripts = discover_migration_scripts(tmp_path)

    assert [script.version for script in scripts] == ["001", "002"]
    assert [script.filename for script in scripts] == ["001_first.sql", "002_second.sql"]


def test_run_pending_migrations_applies_once(tmp_path: Path) -> None:
    """Pending scripts run on first call and are skipped afterwards."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        auto_migrate_on_startup=True,
        app_env="test",
    )
    _write_migration(
        tmp_path,
        "001_create_items.sql",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
    )
    _write_migration(
        tmp_path,
        "002_seed_item.sql",
        "INSERT INTO items (id, name) VALUES (1, 'alpha');",
    )

    first_applied = run_pending_migrations(
        database_engine,
        settings,
        migrations_directory=tmp_path,
    )
    second_applied = run_pending_migrations(
        database_engine,
        settings,
        migrations_directory=tmp_path,
    )

    assert first_applied == ["001", "002"]
    assert second_applied == []

    with database_engine.connect() as connection:
        item_count = connection.execute(text("SELECT COUNT(*) FROM items")).scalar_one()
        version_rows = connection.execute(
            text("SELECT version, filename FROM schema_migrations ORDER BY version")
        ).fetchall()

    assert item_count == 1
    assert [(row[0], row[1]) for row in version_rows] == [
        ("001", "001_create_items.sql"),
        ("002", "002_seed_item.sql"),
    ]


def test_run_pending_migrations_respects_disable_flag(tmp_path: Path) -> None:
    """AUTO_MIGRATE_ON_STARTUP=false leaves the database untouched."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        auto_migrate_on_startup=False,
        app_env="test",
    )
    _write_migration(tmp_path, "001_create_items.sql", "CREATE TABLE items (id INTEGER PRIMARY KEY);")

    applied_versions = run_pending_migrations(
        database_engine,
        settings,
        migrations_directory=tmp_path,
    )

    assert applied_versions == []
    with database_engine.connect() as connection:
        tables = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'table'")
        ).fetchall()
    assert tables == []


def test_duplicate_version_raises(tmp_path: Path) -> None:
    """Two scripts sharing the same version number are rejected."""
    _write_migration(tmp_path, "001_a.sql", "SELECT 1;")
    _write_migration(tmp_path, "001_b.sql", "SELECT 2;")

    with pytest.raises(MigrationError, match="重复的迁移版本号"):
        discover_migration_scripts(tmp_path)


def test_mysql_connection_args_use_real_password_not_obfuscated_url() -> None:
    """SQLAlchemy str(engine.url) hides the password as '***'; migration must not use that."""
    from mailbox_service.migration_runner import _resolve_mysql_connect_kwargs

    database_engine = create_engine(
        "mysql+pymysql://root:s3cret@mysql-host:3306/mailbox_service",
        future=True,
    )
    connect_kwargs = _resolve_mysql_connect_kwargs(database_engine)

    assert connect_kwargs["user"] == "root"
    assert connect_kwargs["password"] == "s3cret"
    assert connect_kwargs["host"] == "mysql-host"
    assert connect_kwargs["database"] == "mailbox_service"
    assert connect_kwargs["port"] == 3306
    assert "***" not in connect_kwargs["password"]


def test_failed_migration_is_not_recorded(tmp_path: Path) -> None:
    """A failing script must not leave a success row in schema_migrations."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        auto_migrate_on_startup=True,
        app_env="test",
    )
    _write_migration(
        tmp_path,
        "001_good.sql",
        "CREATE TABLE items (id INTEGER PRIMARY KEY);",
    )
    _write_migration(
        tmp_path,
        "002_bad.sql",
        "INSERT INTO missing_table (id) VALUES (1);",
    )

    with pytest.raises(MigrationError, match="002_bad.sql"):
        run_pending_migrations(database_engine, settings, migrations_directory=tmp_path)

    with database_engine.connect() as connection:
        versions = {
            row[0]
            for row in connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
        }

    assert versions == {"001"}
