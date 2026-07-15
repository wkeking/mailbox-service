-- Add encrypted access-token cache metadata for service-side AT reuse.
-- Safe to run multiple times on MySQL 8 because each ALTER is gated by information_schema.

SET @access_token_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'access_token_ciphertext'
);

SET @add_access_token_column = IF(
    @access_token_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN access_token_ciphertext TEXT NULL AFTER refresh_token_ciphertext',
    'SELECT ''mailboxes.access_token_ciphertext already exists'''
);

PREPARE add_access_token_column_statement FROM @add_access_token_column;
EXECUTE add_access_token_column_statement;
DEALLOCATE PREPARE add_access_token_column_statement;

SET @access_token_expires_at_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'access_token_expires_at'
);

SET @add_access_token_expires_at_column = IF(
    @access_token_expires_at_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN access_token_expires_at DATETIME(6) NULL AFTER access_token_ciphertext',
    'SELECT ''mailboxes.access_token_expires_at already exists'''
);

PREPARE add_access_token_expires_at_column_statement FROM @add_access_token_expires_at_column;
EXECUTE add_access_token_expires_at_column_statement;
DEALLOCATE PREPARE add_access_token_expires_at_column_statement;

SET @access_token_refreshed_at_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'access_token_refreshed_at'
);

SET @add_access_token_refreshed_at_column = IF(
    @access_token_refreshed_at_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN access_token_refreshed_at DATETIME(6) NULL AFTER access_token_expires_at',
    'SELECT ''mailboxes.access_token_refreshed_at already exists'''
);

PREPARE add_access_token_refreshed_at_column_statement FROM @add_access_token_refreshed_at_column;
EXECUTE add_access_token_refreshed_at_column_statement;
DEALLOCATE PREPARE add_access_token_refreshed_at_column_statement;
