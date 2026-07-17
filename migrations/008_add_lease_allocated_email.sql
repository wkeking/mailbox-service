-- Persist the email address allocated for a lease (primary or plus alias).
-- OAuth / IMAP still use mailboxes.primary_email; recipient matching uses this field.
-- Safe to run multiple times on MySQL 8 because each step is gated by information_schema.

SET @allocated_email_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'allocated_email'
);

SET @add_allocated_email_column = IF(
    @allocated_email_column_exists = 0,
    'ALTER TABLE leases ADD COLUMN allocated_email VARCHAR(320) NULL AFTER purpose',
    'SELECT ''leases.allocated_email already exists'''
);

PREPARE add_allocated_email_column_statement FROM @add_allocated_email_column;
EXECUTE add_allocated_email_column_statement;
DEALLOCATE PREPARE add_allocated_email_column_statement;

SET @allocated_email_index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'leases'
      AND INDEX_NAME = 'ix_leases_allocated_email'
);

SET @add_allocated_email_index = IF(
    @allocated_email_index_exists = 0,
    'CREATE INDEX ix_leases_allocated_email ON leases (allocated_email)',
    'SELECT ''ix_leases_allocated_email already exists'''
);

PREPARE add_allocated_email_index_statement FROM @add_allocated_email_index;
EXECUTE add_allocated_email_index_statement;
DEALLOCATE PREPARE add_allocated_email_index_statement;
