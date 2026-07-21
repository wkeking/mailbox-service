-- Detach non-owned (on-demand / smsbower) inventory from mailboxes.
-- mailbox_provider_resources becomes the primary store for those rows.
-- Idempotent information_schema gates for MySQL.

SET @db_name = DATABASE();

-- ---------------------------------------------------------------------------
-- 1) mailbox_provider_resources: add id + primary_email
-- ---------------------------------------------------------------------------
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND COLUMN_NAME = 'id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailbox_provider_resources ADD COLUMN id VARCHAR(36) NULL AFTER mailbox_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND COLUMN_NAME = 'primary_email'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailbox_provider_resources ADD COLUMN primary_email VARCHAR(320) NULL AFTER external_resource_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Reuse legacy mailbox_id as resource id so existing lease.mailbox_id values can be remapped.
UPDATE mailbox_provider_resources
SET id = mailbox_id
WHERE id IS NULL AND mailbox_id IS NOT NULL;

UPDATE mailbox_provider_resources r
INNER JOIN mailboxes m ON m.id = r.mailbox_id
SET r.primary_email = LOWER(m.primary_email)
WHERE r.primary_email IS NULL OR r.primary_email = '';

UPDATE mailbox_provider_resources
SET primary_email = CONCAT('unknown+', external_resource_id, '@provider.invalid')
WHERE primary_email IS NULL OR primary_email = '';

UPDATE mailbox_provider_resources
SET id = REPLACE(UUID(), '-', '')
WHERE id IS NULL OR id = '';

-- ---------------------------------------------------------------------------
-- 2) leases / claims / operations: provider_resource_id
-- ---------------------------------------------------------------------------
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'provider_resource_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE leases ADD COLUMN provider_resource_id VARCHAR(36) NULL AFTER mailbox_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND COLUMN_NAME = 'provider_resource_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailbox_lease_claims ADD COLUMN provider_resource_id VARCHAR(36) NULL AFTER mailbox_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_operations'
      AND COLUMN_NAME = 'provider_resource_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE mailbox_provider_operations ADD COLUMN provider_resource_id VARCHAR(36) NULL AFTER mailbox_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Remap non-microsoft leases/claims/ops onto provider resources (id == old mailbox_id).
UPDATE leases
SET provider_resource_id = mailbox_id
WHERE (provider_type IS NULL OR provider_type <> 'microsoft')
  AND provider_resource_id IS NULL
  AND mailbox_id IS NOT NULL;

UPDATE mailbox_lease_claims c
INNER JOIN leases l ON l.id = c.lease_id
SET c.provider_resource_id = c.mailbox_id
WHERE (l.provider_type IS NULL OR l.provider_type <> 'microsoft')
  AND c.provider_resource_id IS NULL
  AND c.mailbox_id IS NOT NULL;

UPDATE mailbox_provider_operations
SET provider_resource_id = mailbox_id
WHERE provider_resource_id IS NULL
  AND mailbox_id IS NOT NULL
  AND (provider_type IS NULL OR provider_type <> 'microsoft');

-- ---------------------------------------------------------------------------
-- 3) Drop FK constraints that block PK / nullability changes
-- ---------------------------------------------------------------------------
-- leases.mailbox_id FK (name may vary; drop if present)
SET @fk_name = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'mailbox_id'
      AND REFERENCED_TABLE_NAME = 'mailboxes'
    LIMIT 1
);
SET @ddl = IF(
    @fk_name IS NOT NULL,
    CONCAT('ALTER TABLE leases DROP FOREIGN KEY `', @fk_name, '`'),
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_name = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND COLUMN_NAME = 'mailbox_id'
      AND REFERENCED_TABLE_NAME = 'mailboxes'
    LIMIT 1
);
SET @ddl = IF(
    @fk_name IS NOT NULL,
    CONCAT('ALTER TABLE mailbox_lease_claims DROP FOREIGN KEY `', @fk_name, '`'),
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_name = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND COLUMN_NAME = 'mailbox_id'
      AND REFERENCED_TABLE_NAME = 'mailboxes'
    LIMIT 1
);
SET @ddl = IF(
    @fk_name IS NOT NULL,
    CONCAT('ALTER TABLE mailbox_provider_resources DROP FOREIGN KEY `', @fk_name, '`'),
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_name = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_operations'
      AND COLUMN_NAME = 'mailbox_id'
      AND REFERENCED_TABLE_NAME = 'mailboxes'
    LIMIT 1
);
SET @ddl = IF(
    @fk_name IS NOT NULL,
    CONCAT('ALTER TABLE mailbox_provider_operations DROP FOREIGN KEY `', @fk_name, '`'),
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_name = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'email_site_usages'
      AND COLUMN_NAME = 'mailbox_id'
      AND REFERENCED_TABLE_NAME = 'mailboxes'
    LIMIT 1
);
SET @ddl = IF(
    @fk_name IS NOT NULL,
    CONCAT('ALTER TABLE email_site_usages DROP FOREIGN KEY `', @fk_name, '`'),
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 4) Null out non-microsoft mailbox_id references; make mailbox_id nullable
-- ---------------------------------------------------------------------------
UPDATE leases
SET mailbox_id = NULL
WHERE provider_type IS NOT NULL AND provider_type <> 'microsoft';

UPDATE mailbox_lease_claims c
INNER JOIN leases l ON l.id = c.lease_id
SET c.mailbox_id = NULL
WHERE l.provider_type IS NOT NULL AND l.provider_type <> 'microsoft';

UPDATE mailbox_provider_operations
SET mailbox_id = NULL
WHERE provider_type IS NOT NULL AND provider_type <> 'microsoft';

UPDATE email_site_usages u
INNER JOIN mailboxes m ON m.id = u.mailbox_id
SET u.mailbox_id = NULL
WHERE m.provider_type IS NOT NULL AND m.provider_type <> 'microsoft';

SET @is_nullable = (
    SELECT IS_NULLABLE
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND COLUMN_NAME = 'mailbox_id'
);
SET @ddl = IF(
    @is_nullable = 'NO',
    'ALTER TABLE leases MODIFY COLUMN mailbox_id VARCHAR(36) NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @is_nullable = (
    SELECT IS_NULLABLE
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND COLUMN_NAME = 'mailbox_id'
);
SET @ddl = IF(
    @is_nullable = 'NO',
    'ALTER TABLE mailbox_lease_claims MODIFY COLUMN mailbox_id VARCHAR(36) NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 5) Rebuild mailbox_provider_resources primary key on id
-- ---------------------------------------------------------------------------
-- Drop old primary key if still on mailbox_id
SET @pk_col = (
    SELECT COLUMN_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND CONSTRAINT_NAME = 'PRIMARY'
    LIMIT 1
);
SET @ddl = IF(
    @pk_col = 'mailbox_id',
    'ALTER TABLE mailbox_provider_resources DROP PRIMARY KEY, MODIFY COLUMN id VARCHAR(36) NOT NULL, ADD PRIMARY KEY (id)',
    IF(
        @pk_col IS NULL OR @pk_col <> 'id',
        'ALTER TABLE mailbox_provider_resources MODIFY COLUMN id VARCHAR(36) NOT NULL, ADD PRIMARY KEY (id)',
        'SELECT 1'
    )
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @is_nullable = (
    SELECT IS_NULLABLE
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND COLUMN_NAME = 'primary_email'
);
SET @ddl = IF(
    @is_nullable = 'YES',
    'ALTER TABLE mailbox_provider_resources MODIFY COLUMN primary_email VARCHAR(320) NOT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop legacy mailbox_id column from resources when present
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND COLUMN_NAME = 'mailbox_id'
);
SET @ddl = IF(
    @column_exists = 1,
    'ALTER TABLE mailbox_provider_resources DROP COLUMN mailbox_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_resources'
      AND INDEX_NAME = 'ix_provider_resources_email'
);
SET @ddl = IF(
    @index_exists = 0,
    'CREATE INDEX ix_provider_resources_email ON mailbox_provider_resources (primary_email)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 6) Delete non-owned mailboxes (on-demand / smsbower pollution)
-- ---------------------------------------------------------------------------
DELETE FROM mailboxes
WHERE provider_type IS NOT NULL AND provider_type <> 'microsoft';

-- ---------------------------------------------------------------------------
-- 7) Re-add FKs (nullable mailbox_id; provider_resource_id)
-- ---------------------------------------------------------------------------
SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND CONSTRAINT_NAME = 'fk_leases_mailbox'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE leases ADD CONSTRAINT fk_leases_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND CONSTRAINT_NAME = 'fk_leases_provider_resource'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE leases ADD CONSTRAINT fk_leases_provider_resource FOREIGN KEY (provider_resource_id) REFERENCES mailbox_provider_resources (id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND CONSTRAINT_NAME = 'fk_claims_mailbox'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE mailbox_lease_claims ADD CONSTRAINT fk_claims_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND CONSTRAINT_NAME = 'fk_claims_provider_resource'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE mailbox_lease_claims ADD CONSTRAINT fk_claims_provider_resource FOREIGN KEY (provider_resource_id) REFERENCES mailbox_provider_resources (id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_operations'
      AND CONSTRAINT_NAME = 'fk_provider_ops_mailbox'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE mailbox_provider_operations ADD CONSTRAINT fk_provider_ops_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_provider_operations'
      AND CONSTRAINT_NAME = 'fk_provider_ops_resource'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE mailbox_provider_operations ADD CONSTRAINT fk_provider_ops_resource FOREIGN KEY (provider_resource_id) REFERENCES mailbox_provider_resources (id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'email_site_usages'
      AND CONSTRAINT_NAME = 'fk_email_site_usages_mailbox'
);
SET @ddl = IF(
    @fk_exists = 0,
    'ALTER TABLE email_site_usages ADD CONSTRAINT fk_email_site_usages_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'leases'
      AND INDEX_NAME = 'ix_leases_provider_resource'
);
SET @ddl = IF(
    @index_exists = 0,
    'CREATE INDEX ix_leases_provider_resource ON leases (provider_resource_id, released_at, expires_at)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'mailbox_lease_claims'
      AND INDEX_NAME = 'ix_mailbox_lease_claims_provider_resource'
);
SET @ddl = IF(
    @index_exists = 0,
    'CREATE INDEX ix_mailbox_lease_claims_provider_resource ON mailbox_lease_claims (provider_resource_id)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
