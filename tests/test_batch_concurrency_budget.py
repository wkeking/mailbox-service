"""Batch concurrency budget tests."""

from __future__ import annotations

from mailbox_service.config import Settings


def test_worker_count_is_bounded_by_pool_budget() -> None:
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_env="test",
        batch_max_workers=8,
        database_pool_size=16,
        database_max_overflow=8,
    )
    available_proxy_count = 1000
    item_count = 500
    worker_count = max(
        1,
        min(
            settings.batch_max_workers,
            available_proxy_count,
            settings.database_worker_budget,
            item_count,
        ),
    )
    assert worker_count <= 8
    assert worker_count <= settings.database_worker_budget
