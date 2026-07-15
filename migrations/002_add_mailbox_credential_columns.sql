-- Add mailbox credential storage columns for deployments created before 001 included them.
-- Safe to run multiple times on MySQL 8 because each ALTER is gated by information_schema.

SET @mail_password_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'mail_password_ciphertext'
);

SET @add_mail_password_column = IF(
    @mail_password_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN mail_password_ciphertext TEXT NULL AFTER client_id',
    'SELECT ''mailboxes.mail_password_ciphertext already exists'''
);

PREPARE add_mail_password_column_statement FROM @add_mail_password_column;
EXECUTE add_mail_password_column_statement;
DEALLOCATE PREPARE add_mail_password_column_statement;

SET @refresh_token_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'mailboxes'
      AND COLUMN_NAME = 'refresh_token_ciphertext'
);

SET @add_refresh_token_column = IF(
    @refresh_token_column_exists = 0,
    'ALTER TABLE mailboxes ADD COLUMN refresh_token_ciphertext TEXT NULL AFTER mail_password_ciphertext',
    'SELECT ''mailboxes.refresh_token_ciphertext already exists'''
);

PREPARE add_refresh_token_column_statement FROM @add_refresh_token_column;
EXECUTE add_refresh_token_column_statement;
DEALLOCATE PREPARE add_refresh_token_column_statement;
