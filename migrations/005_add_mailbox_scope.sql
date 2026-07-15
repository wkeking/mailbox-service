-- Persist OAuth scopes decoded from a mailbox access token after successful refresh.
-- Safe to run multiple times on MySQL 8 because each ALTER is gated by information_schema.

SET @scope_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'scope'
);

SET @add_scope_column = IF(
    @scope_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN scope TEXT NULL AFTER access_token_refreshed_at',
    'SELECT ''mailboxes.scope already exists'''
);

PREPARE add_scope_column_statement FROM @add_scope_column;
EXECUTE add_scope_column_statement;
DEALLOCATE PREPARE add_scope_column_statement;
