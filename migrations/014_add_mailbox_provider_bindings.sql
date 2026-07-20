-- Provider-aware bindings for inventory multi-provider (CASE-20260720-001).
-- Idempotent: information_schema column/index gates.

SET @db_name = DATABASE();

-- mailboxes.provider_type
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'provider_type'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN provider_type VARCHAR(64) NOT NULL DEFAULT ''microsoft'' AFTER id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- mailboxes.provider_config_json (non-sensitive metadata only)
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'provider_config_json'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN provider_config_json JSON NULL AFTER capability_probe_error',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill any NULL provider_type rows (defensive; DEFAULT covers new inserts).
UPDATE mailboxes
SET provider_type = 'microsoft'
WHERE provider_type IS NULL OR provider_type = '';

-- Index for provider-aware pool selection
SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailboxes'
      AND INDEX_NAME = 'ix_mailboxes_provider_status'
);
SET @ddl = IF(
    @index_exists = 0,
    'CREATE INDEX ix_mailboxes_provider_status ON mailboxes (provider_type, status, capability)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- leases.provider_type (immutable Lease Provider binding)
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'provider_type'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE leases ADD COLUMN provider_type VARCHAR(64) NOT NULL DEFAULT ''microsoft'' AFTER mode',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'provider_instance_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE leases ADD COLUMN provider_instance_id VARCHAR(64) NULL AFTER provider_type',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'provider_config_revision'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE leases ADD COLUMN provider_config_revision VARCHAR(64) NULL AFTER provider_instance_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE leases
SET provider_type = 'microsoft'
WHERE provider_type IS NULL OR provider_type = '';

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND INDEX_NAME = 'ix_leases_provider_type'
);
SET @ddl = IF(
    @index_exists = 0,
    'CREATE INDEX ix_leases_provider_type ON leases (provider_type, released_at, expires_at)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
