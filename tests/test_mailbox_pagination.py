"""Regression tests for paginated mailbox administration responses."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.database import Base
from mailbox_service.main import list_mailboxes
from mailbox_service.models import Mailbox, utc_now


def create_mailbox_pagination_test_session() -> Session:
    """Build an isolated SQLite session for mailbox list tests."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    return sessionmaker(bind=database_engine, expire_on_commit=False)()


def test_mailbox_list_returns_requested_page_with_metadata() -> None:
    """Mailbox list pagination should preserve newest-first ordering and totals."""
    session = create_mailbox_pagination_test_session()
    reference_time = utc_now()
    mailboxes = [
        Mailbox(
            primary_email="oldest@outlook.com",
            scope=None,
            updated_at=reference_time - timedelta(minutes=3),
        ),
        Mailbox(
            primary_email="middle@outlook.com",
            scope="Mail.Read offline_access",
            updated_at=reference_time - timedelta(minutes=2),
        ),
        Mailbox(
            primary_email="newest@outlook.com",
            scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            updated_at=reference_time - timedelta(minutes=1),
        ),
    ]
    session.add_all(mailboxes)
    session.flush()

    first_page = list_mailboxes(session, "test-admin", page=1, page_size=2)
    response = list_mailboxes(session, "test-admin", page=2, page_size=2)

    assert first_page.items[0].scope == "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    assert first_page.items[1].scope == "Mail.Read offline_access"
    assert response.total == 3
    assert response.page == 2
    assert response.page_size == 2
    assert response.total_pages == 2
    assert [item.primary_email for item in response.items] == ["oldest@outlook.com"]
    assert response.items[0].scope is None
