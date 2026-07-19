"""Shared pytest fixtures and marker registration helpers."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "mysql: tests that require a real MySQL 8 database")
    config.addinivalue_line("markers", "stress: long-running concurrency or load tests")
    config.addinivalue_line("markers", "container: container and TLS smoke tests")
