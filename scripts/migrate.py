#!/usr/bin/env python3
"""Apply pending SQL migrations outside the application process.

Production deployments should set AUTO_MIGRATE_ON_STARTUP=false and run this CLI
with a migrator account that has DDL privileges limited to the application schema.
"""

from __future__ import annotations

import argparse
import sys

from mailbox_service.config import Settings
from mailbox_service.migration_runner import create_migration_engine, run_pending_migrations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply mailbox-service SQL migrations")
    parser.add_argument(
        "--database-url",
        default=None,
        help="Override DATABASE_URL (defaults to environment / Settings)",
    )
    parser.add_argument(
        "--migrations-dir",
        default=None,
        help="Optional migrations directory path",
    )
    arguments = parser.parse_args(argv)

    settings_kwargs: dict[str, object] = {
        "auto_migrate_on_startup": True,
        "app_env": "development",
    }
    if arguments.database_url:
        settings_kwargs["database_url"] = arguments.database_url
    if arguments.migrations_dir:
        settings_kwargs["migrations_dir"] = arguments.migrations_dir
    settings = Settings(**settings_kwargs)
    engine = create_migration_engine(settings)
    try:
        applied = run_pending_migrations(engine, settings)
    finally:
        engine.dispose()
    if applied:
        print("applied:", ", ".join(applied))
    else:
        print("schema already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
