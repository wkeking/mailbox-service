"""SQLAlchemy engine and request-scoped database sessions."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from mailbox_service.config import get_settings


class Base(DeclarativeBase):
    """Base class for all persisted domain models."""


def create_database_engine():
    """Create the synchronous engine used by the single-instance service."""
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True, future=True)


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
