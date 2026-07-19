-- Cluster-wide scheduler job leases and proxy health observation metadata.

CREATE TABLE IF NOT EXISTS scheduled_job_leases (
    job_name VARCHAR(128) NOT NULL,
    owner_id VARCHAR(128) NOT NULL,
    lease_until DATETIME(6) NOT NULL,
    fencing_token BIGINT NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (job_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET @db_name = DATABASE();

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'egress_proxies'
      AND COLUMN_NAME = 'last_observed_at'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE egress_proxies ADD COLUMN last_observed_at DATETIME(6) NULL',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'egress_proxies'
      AND COLUMN_NAME = 'health_version'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE egress_proxies ADD COLUMN health_version BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS proxy_health_events (
    id VARCHAR(36) NOT NULL,
    operation_id VARCHAR(36) NOT NULL,
    proxy_id VARCHAR(36) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    observed_at DATETIME(6) NOT NULL,
    latency_ms INT NULL,
    error_summary VARCHAR(512) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_proxy_health_events_operation_id (operation_id),
    INDEX ix_proxy_health_events_proxy_observed (proxy_id, observed_at),
    CONSTRAINT fk_proxy_health_events_proxy
        FOREIGN KEY (proxy_id) REFERENCES egress_proxies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Optional idempotent audit key for item/chunk events (nullable for legacy rows).
SET @column_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'audit_logs'
      AND COLUMN_NAME = 'operation_id'
);
SET @ddl = IF(
    @column_exists = 0,
    'ALTER TABLE audit_logs ADD COLUMN operation_id VARCHAR(36) NULL AFTER target_id',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @index_exists = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db_name
      AND TABLE_NAME = 'audit_logs'
      AND INDEX_NAME = 'uq_audit_logs_operation_resource_event'
);
SET @ddl = IF(
    @index_exists = 0,
    'ALTER TABLE audit_logs ADD UNIQUE KEY uq_audit_logs_operation_resource_event (operation_id, target_id, event_type)',
    'SELECT 1'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
