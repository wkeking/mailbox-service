"""Regression tests for admin dashboard overview metrics."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.database import Base
from mailbox_service.main import get_dashboard_summary
from mailbox_service.models import Mailbox, MailboxCapability, MailboxStatus


def create_dashboard_test_session() -> Session:
    """Build an isolated SQLite session for dashboard metric tests."""
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    return sessionmaker(bind=database_engine, expire_on_commit=False)()


def test_dashboard_summary_includes_status_and_capability_counts() -> None:
    """Overview metrics should separate mailbox status from runtime capability."""
    session = create_dashboard_test_session()
    session.add_all(
        [
            Mailbox(
                primary_email="imap-active@outlook.com",
                status=MailboxStatus.ACTIVE,
                capability=MailboxCapability.IMAP,
            ),
            Mailbox(
                primary_email="graph-active@outlook.com",
                status=MailboxStatus.ACTIVE,
                capability=MailboxCapability.GRAPH,
            ),
            Mailbox(
                primary_email="unusable-active@outlook.com",
                status=MailboxStatus.ACTIVE,
                capability=MailboxCapability.UNUSABLE,
            ),
            Mailbox(
                primary_email="unprobed-active@outlook.com",
                status=MailboxStatus.ACTIVE,
                capability=None,
            ),
            Mailbox(
                primary_email="invalid@outlook.com",
                status=MailboxStatus.INVALID,
                capability=MailboxCapability.UNUSABLE,
            ),
            Mailbox(
                primary_email="disabled@outlook.com",
                status=MailboxStatus.DISABLED,
                capability=MailboxCapability.IMAP,
            ),
            Mailbox(
                primary_email="cooldown@outlook.com",
                status=MailboxStatus.COOLDOWN,
                capability=None,
            ),
        ]
    )
    session.flush()

    summary = get_dashboard_summary(session, "test-admin")

    assert summary.total_mailbox_count == 7
    assert summary.active_mailbox_count == 4
    # Only active mailboxes with verified IMAP/Graph capability count as usable.
    assert summary.usable_mailbox_count == 2
    assert summary.invalid_mailbox_count == 1
    assert summary.disabled_mailbox_count == 1
    assert summary.cooldown_mailbox_count == 1
    assert summary.imap_capable_mailbox_count == 2
    assert summary.graph_capable_mailbox_count == 1
    assert summary.unusable_mailbox_count == 2
    assert summary.unprobed_capability_mailbox_count == 2
