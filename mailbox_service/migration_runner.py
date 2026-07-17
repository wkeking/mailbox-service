"""Apply versioned SQL migrations on application startup.

Keeps the existing ``migrations/*.sql`` files and records applied versions in
``schema_migrations`` so each file runs at most once after tracking is enabled.
Scripts are expected to be re-runnable (``IF NOT EXISTS`` / information_schema gates).
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from mailbox_service.config import Settings

# Prefer uvicorn's error logger so startup migration lines appear in process stdout.
logger = logging.getLogger("uvicorn.error")

MIGRATION_FILE_PATTERN = re.compile(r"^(?P<version>\d{3,})_.+\.sql$")
SCHEMA_MIGRATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    applied_at DATETIME(6) NOT NULL,
    PRIMARY KEY (version)
)
"""
SCHEMA_MIGRATIONS_TABLE_SQL_SQLITE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) NOT NULL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    applied_at DATETIME NOT NULL
)
"""
MYSQL_MIGRATION_LOCK_NAME = "mailbox_service_schema_migrate"
MYSQL_MIGRATION_LOCK_TIMEOUT_SECONDS = 60


@dataclass(frozen=True, slots=True)
class MigrationScript:
    """One ordered SQL migration discovered on disk."""

    version: str
    filename: str
    path: Path
    checksum: str
    sql_text: str


class MigrationError(RuntimeError):
    """Raised when schema migration discovery or application fails."""


def resolve_migrations_directory(configured_path: str | None = None) -> Path:
    """Locate the migrations directory from config, CWD, or package root."""
    if configured_path:
        configured_directory = Path(configured_path).expanduser().resolve()
        if not configured_directory.is_dir():
            raise MigrationError(f"配置的 migrations 目录不存在: {configured_directory}")
        return configured_directory

    candidate_directories = [
        Path.cwd() / "migrations",
        Path(__file__).resolve().parent.parent / "migrations",
    ]
    for candidate_directory in candidate_directories:
        if candidate_directory.is_dir():
            return candidate_directory.resolve()

    searched_paths = ", ".join(str(path) for path in candidate_directories)
    raise MigrationError(f"未找到 migrations 目录，已搜索: {searched_paths}")


def discover_migration_scripts(migrations_directory: Path) -> list[MigrationScript]:
    """Load and sort numbered ``*.sql`` migration files."""
    migration_scripts: list[MigrationScript] = []
    for migration_path in sorted(migrations_directory.glob("*.sql")):
        filename = migration_path.name
        pattern_match = MIGRATION_FILE_PATTERN.match(filename)
        if pattern_match is None:
            logger.warning("跳过不符合命名规范的 SQL 文件: %s", filename)
            continue

        sql_text = migration_path.read_text(encoding="utf-8")
        migration_scripts.append(
            MigrationScript(
                version=pattern_match.group("version"),
                filename=filename,
                path=migration_path,
                checksum=_compute_checksum(sql_text),
                sql_text=sql_text,
            )
        )

    migration_scripts.sort(key=lambda script: (script.version, script.filename))
    _assert_unique_versions(migration_scripts)
    return migration_scripts


def run_pending_migrations(
    engine: Engine,
    settings: Settings,
    *,
    migrations_directory: Path | None = None,
) -> list[str]:
    """Ensure the schema is up to date; return newly applied version ids."""
    if not settings.auto_migrate_on_startup:
        logger.info("已关闭启动时自动迁移 (AUTO_MIGRATE_ON_STARTUP=false)")
        return []

    resolved_migrations_directory = migrations_directory or resolve_migrations_directory(
        settings.migrations_dir
    )
    migration_scripts = discover_migration_scripts(resolved_migrations_directory)
    if not migration_scripts:
        logger.warning("migrations 目录中没有可执行的 SQL 文件: %s", resolved_migrations_directory)
        return []

    logger.info(
        "准备检查数据库迁移: directory=%s scripts=%s",
        resolved_migrations_directory,
        len(migration_scripts),
    )

    dialect_name = engine.dialect.name
    _ensure_schema_migrations_table(engine, dialect_name)

    with engine.connect() as connection:
        lock_acquired = _try_acquire_migration_lock(connection, dialect_name)
        try:
            applied_versions = _load_applied_versions(connection)
            pending_scripts = [
                script for script in migration_scripts if script.version not in applied_versions
            ]
            if not pending_scripts:
                logger.info("数据库 schema 已是最新，无需执行迁移")
                return []

            applied_now: list[str] = []
            for migration_script in pending_scripts:
                logger.info(
                    "正在应用迁移 %s (%s)",
                    migration_script.version,
                    migration_script.filename,
                )
                try:
                    _execute_sql_script(engine, migration_script.sql_text)
                    _record_applied_migration(connection, migration_script)
                    connection.commit()
                except Exception as error:
                    connection.rollback()
                    raise MigrationError(
                        f"迁移失败: {migration_script.filename}: {error}"
                    ) from error

                applied_now.append(migration_script.version)
                logger.info("迁移已应用: %s", migration_script.filename)

            logger.info("自动迁移完成，新应用版本: %s", ", ".join(applied_now))
            return applied_now
        finally:
            if lock_acquired:
                _release_migration_lock(connection, dialect_name)
                connection.commit()


def _assert_unique_versions(migration_scripts: list[MigrationScript]) -> None:
    seen_versions: set[str] = set()
    for migration_script in migration_scripts:
        if migration_script.version in seen_versions:
            raise MigrationError(
                f"存在重复的迁移版本号 {migration_script.version}: {migration_script.filename}"
            )
        seen_versions.add(migration_script.version)


def _compute_checksum(sql_text: str) -> str:
    return hashlib.sha256(sql_text.encode("utf-8")).hexdigest()


def _ensure_schema_migrations_table(engine: Engine, dialect_name: str) -> None:
    create_table_sql = (
        SCHEMA_MIGRATIONS_TABLE_SQL_SQLITE
        if dialect_name == "sqlite"
        else SCHEMA_MIGRATIONS_TABLE_SQL
    )
    with engine.begin() as connection:
        connection.execute(text(create_table_sql))


def _load_applied_versions(connection: Connection) -> set[str]:
    rows = connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
    return {str(row[0]) for row in rows}


def _record_applied_migration(connection: Connection, migration_script: MigrationScript) -> None:
    applied_at = datetime.now(timezone.utc).replace(tzinfo=None)
    connection.execute(
        text(
            "INSERT INTO schema_migrations (version, filename, checksum, applied_at) "
            "VALUES (:version, :filename, :checksum, :applied_at)"
        ),
        {
            "version": migration_script.version,
            "filename": migration_script.filename,
            "checksum": migration_script.checksum,
            "applied_at": applied_at,
        },
    )


def _try_acquire_migration_lock(connection: Connection, dialect_name: str) -> bool:
    if dialect_name != "mysql":
        return False

    row = connection.execute(
        text("SELECT GET_LOCK(:lock_name, :timeout_seconds)"),
        {
            "lock_name": MYSQL_MIGRATION_LOCK_NAME,
            "timeout_seconds": MYSQL_MIGRATION_LOCK_TIMEOUT_SECONDS,
        },
    ).fetchone()
    lock_result = row[0] if row is not None else 0
    if lock_result != 1:
        raise MigrationError(
            "无法获取数据库迁移锁，可能有其他实例正在执行迁移；"
            f"lock={MYSQL_MIGRATION_LOCK_NAME}"
        )
    return True


def _release_migration_lock(connection: Connection, dialect_name: str) -> None:
    if dialect_name != "mysql":
        return
    connection.execute(
        text("SELECT RELEASE_LOCK(:lock_name)"),
        {"lock_name": MYSQL_MIGRATION_LOCK_NAME},
    )


def _execute_sql_script(engine: Engine, sql_text: str) -> None:
    """Execute a multi-statement migration script against the target database."""
    stripped_sql = sql_text.strip()
    if not stripped_sql:
        return

    dialect_name = engine.dialect.name
    if dialect_name == "sqlite":
        with engine.begin() as connection:
            dbapi_connection = connection.connection.dbapi_connection
            dbapi_connection.executescript(stripped_sql)
        return

    if dialect_name != "mysql":
        raise MigrationError(f"不支持的数据库方言自动迁移: {dialect_name}")

    _execute_mysql_sql_script(engine, stripped_sql)


def _resolve_mysql_connect_kwargs(engine: Engine) -> dict[str, object]:
    """Build PyMySQL connect kwargs from the engine URL without password obfuscation.

    Never use ``str(engine.url)`` / ``make_url(str(engine.url))``: SQLAlchemy
    renders the password as ``***``, which then becomes the literal login password.
    """
    database_url = engine.url
    password = database_url.password
    if callable(password):
        password = password()
    if password is not None and not isinstance(password, str):
        password = password.decode("utf-8") if isinstance(password, bytes) else str(password)

    return {
        "host": database_url.host or "127.0.0.1",
        "user": database_url.username or "",
        "password": password or "",
        "database": database_url.database,
        "port": database_url.port or 3306,
        "charset": "utf8mb4",
        "autocommit": True,
    }


def _execute_mysql_sql_script(engine: Engine, sql_text: str) -> None:
    """Run MySQL scripts that may contain multiple statements and session variables."""
    import pymysql
    from pymysql.constants import CLIENT

    connect_kwargs = _resolve_mysql_connect_kwargs(engine)
    connection = pymysql.connect(
        **connect_kwargs,
        client_flag=CLIENT.MULTI_STATEMENTS,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql_text)
            while cursor.nextset():
                pass
    except Exception as error:
        raise MigrationError(f"执行 MySQL 迁移脚本失败: {error}") from error
    finally:
        connection.close()


def create_migration_engine(settings: Settings) -> Engine:
    """Create a short-lived engine for migrations when the app engine is unavailable."""
    return create_engine(settings.database_url, pool_pre_ping=True, future=True)
