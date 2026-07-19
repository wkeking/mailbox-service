"""SQLAlchemy engine and request-scoped database sessions."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from mailbox_service.config import Settings, get_settings


class Base(DeclarativeBase):
    """Base class for all persisted domain models."""


def create_database_engine(settings: Settings | None = None) -> Engine:
    """Create the synchronous engine with explicit pool and connect budgets."""
    resolved_settings = settings or get_settings()
    engine_kwargs: dict[str, object] = {
        "pool_pre_ping": True,
        "future": True,
    }
    database_url = resolved_settings.database_url
    is_sqlite = database_url.startswith("sqlite")
    if not is_sqlite:
        engine_kwargs.update(
            {
                "pool_size": resolved_settings.database_pool_size,
                "max_overflow": resolved_settings.database_max_overflow,
                "pool_timeout": resolved_settings.database_pool_timeout_seconds,
                "pool_recycle": resolved_settings.database_pool_recycle_seconds,
                "pool_use_lifo": True,
                "connect_args": {
                    "connect_timeout": int(resolved_settings.database_connect_timeout_seconds),
                },
            }
        )
    engine = create_engine(database_url, **engine_kwargs)
    if not is_sqlite:

        @event.listens_for(engine, "connect")
        def _set_mysql_session_defaults(dbapi_connection, connection_record) -> None:  # noqa: ANN001
            # Short enough to fail fast under true deadlocks, long enough that brief proxy
            # rebind / claim contention does not surface as 1205 during mail-read scans.
            with dbapi_connection.cursor() as cursor:
                cursor.execute("SET SESSION innodb_lock_wait_timeout = 15")

    return engine


database_engine = create_database_engine()
SessionFactory = sessionmaker(bind=database_engine, autoflush=False, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    """Yield a transactional request session and roll it back on failures."""
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
