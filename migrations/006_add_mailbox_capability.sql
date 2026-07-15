-- Persist runtime IMAP/Graph capability probe results for mailboxes.
-- Safe to run multiple times on MySQL 8 because each ALTER is gated by information_schema.

SET @capability_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'capability'
);

SET @add_capability_column = IF(
    @capability_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN capability VARCHAR(20) NULL AFTER scope',
    'SELECT ''mailboxes.capability already exists'''
);

PREPARE add_capability_column_statement FROM @add_capability_column;
EXECUTE add_capability_column_statement;
DEALLOCATE PREPARE add_capability_column_statement;

SET @capability_probed_at_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'capability_probed_at'
);

SET @add_capability_probed_at_column = IF(
    @capability_probed_at_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN capability_probed_at DATETIME(6) NULL AFTER capability',
    'SELECT ''mailboxes.capability_probed_at already exists'''
);

PREPARE add_capability_probed_at_column_statement FROM @add_capability_probed_at_column;
EXECUTE add_capability_probed_at_column_statement;
DEALLOCATE PREPARE add_capability_probed_at_column_statement;

SET @capability_probe_error_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'capability_probe_error'
);

SET @add_capability_probe_error_column = IF(
    @capability_probe_error_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN capability_probe_error VARCHAR(500) NULL AFTER capability_probed_at',
    'SELECT ''mailboxes.capability_probe_error already exists'''
);

PREPARE add_capability_probe_error_column_statement FROM @add_capability_probe_error_column;
EXECUTE add_capability_probe_error_column_statement;
DEALLOCATE PREPARE add_capability_probe_error_column_statement;
