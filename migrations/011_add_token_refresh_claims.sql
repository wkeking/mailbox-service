-- Token refresh single-flight claim fields and AT revision binding.
-- Existing AT cache cannot prove which RT revision produced it; leave
-- access_token_source_version NULL so the first ensure forces a refresh.

SET @db_name = DATABASE();

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'access_token_source_version'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN access_token_source_version INT NULL AFTER access_token_refreshed_at',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'token_refresh_claim_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN token_refresh_claim_id VARCHAR(36) NULL AFTER token_version',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'token_refresh_claim_expires_at'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN token_refresh_claim_expires_at DATETIME(6) NULL AFTER token_refresh_claim_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND INDEX_NAME = 'ix_mailboxes_token_refresh_claim_expires_at'
);
SET @ddl = IF(
    @index_exists = 0,
    'ALTER TABLE mailboxes ADD INDEX ix_mailboxes_token_refresh_claim_expires_at (token_refresh_claim_expires_at)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
