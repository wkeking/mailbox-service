-- Allow proxy-pool members that share host/port but differ by username/password.
-- Safe to run multiple times on MySQL 8 because each step is gated by information_schema.

SET @credential_fingerprint_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'egress_proxies'
      AND COLUMN_NAME = 'credential_fingerprint'
);

SET @add_credential_fingerprint_column = IF(
    @credential_fingerprint_column_exists = 0,
    'ALTER TABLE egress_proxies ADD COLUMN credential_fingerprint VARCHAR(64) NOT NULL DEFAULT '''' AFTER password_ciphertext',
    'SELECT ''egress_proxies.credential_fingerprint already exists'''
);

PREPARE add_credential_fingerprint_column_statement FROM @add_credential_fingerprint_column;
EXECUTE add_credential_fingerprint_column_statement;
DEALLOCATE PREPARE add_credential_fingerprint_column_statement;

-- Existing rows keep a stable unique placeholder until the next Admin save backfills a real fingerprint.
UPDATE egress_proxies
SET credential_fingerprint = CONCAT('legacy:', id)
WHERE credential_fingerprint = '' OR credential_fingerprint IS NULL;

SET @old_endpoint_index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'egress_proxies'
      AND INDEX_NAME = 'uq_egress_proxies_endpoint'
);

SET @drop_old_endpoint_index = IF(
    @old_endpoint_index_exists > 0,
    'ALTER TABLE egress_proxies DROP INDEX uq_egress_proxies_endpoint',
    'SELECT ''uq_egress_proxies_endpoint already dropped'''
);

PREPARE drop_old_endpoint_index_statement FROM @drop_old_endpoint_index;
EXECUTE drop_old_endpoint_index_statement;
DEALLOCATE PREPARE drop_old_endpoint_index_statement;

SET @new_endpoint_index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'egress_proxies'
      AND INDEX_NAME = 'uq_egress_proxies_endpoint_credentials'
);

SET @add_new_endpoint_index = IF(
    @new_endpoint_index_exists = 0,
    'ALTER TABLE egress_proxies ADD UNIQUE KEY uq_egress_proxies_endpoint_credentials (protocol, host, port, credential_fingerprint)',
    'SELECT ''uq_egress_proxies_endpoint_credentials already exists'''
);

PREPARE add_new_endpoint_index_statement FROM @add_new_endpoint_index;
EXECUTE add_new_endpoint_index_statement;
DEALLOCATE PREPARE add_new_endpoint_index_statement;
