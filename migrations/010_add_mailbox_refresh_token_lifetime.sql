-- Persist refresh-token sliding lifetime metadata for keepalive selection.
-- Safe to run multiple times on MySQL 8 because each ALTER is gated by information_schema.

SET @refresh_token_updated_at_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'refresh_token_updated_at'
);

SET @add_refresh_token_updated_at_column = IF(
    @refresh_token_updated_at_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN refresh_token_updated_at DATETIME(6) NULL AFTER refresh_token_ciphertext',
    'SELECT ''mailboxes.refresh_token_updated_at already exists'''
);

PREPARE add_refresh_token_updated_at_column_statement FROM @add_refresh_token_updated_at_column;
EXECUTE add_refresh_token_updated_at_column_statement;
DEALLOCATE PREPARE add_refresh_token_updated_at_column_statement;

SET @refresh_token_expires_at_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'refresh_token_expires_at'
);

SET @add_refresh_token_expires_at_column = IF(
    @refresh_token_expires_at_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN refresh_token_expires_at DATETIME(6) NULL AFTER refresh_token_updated_at',
    'SELECT ''mailboxes.refresh_token_expires_at already exists'''
);

PREPARE add_refresh_token_expires_at_column_statement FROM @add_refresh_token_expires_at_column;
EXECUTE add_refresh_token_expires_at_column_statement;
DEALLOCATE PREPARE add_refresh_token_expires_at_column_statement;

-- Backfill existing rows that already hold a refresh token.
-- Prefer the last successful OAuth refresh time; fall back to mailbox creation time.
-- Lifetime matches the service default (90 days); subsequent refreshes rewrite the exact values.
UPDATE mailboxes
SET
    refresh_token_updated_at = COALESCE(access_token_refreshed_at, created_at),
    refresh_token_expires_at = DATE_ADD(
        COALESCE(access_token_refreshed_at, created_at),
        INTERVAL 90 DAY
    )
WHERE refresh_token_ciphertext IS NOT NULL
  AND (
      refresh_token_updated_at IS NULL
      OR refresh_token_expires_at IS NULL
  );

SET @ix_mailboxes_rt_expires_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND INDEX_NAME = 'ix_mailboxes_refresh_token_expires_at'
);

SET @add_ix_mailboxes_rt_expires = IF(
    @ix_mailboxes_rt_expires_exists = 0,
    'CREATE INDEX ix_mailboxes_refresh_token_expires_at ON mailboxes (status, refresh_token_expires_at)',
    'SELECT ''ix_mailboxes_refresh_token_expires_at already exists'''
);

PREPARE add_ix_mailboxes_rt_expires_statement FROM @add_ix_mailboxes_rt_expires;
EXECUTE add_ix_mailboxes_rt_expires_statement;
DEALLOCATE PREPARE add_ix_mailboxes_rt_expires_statement;
