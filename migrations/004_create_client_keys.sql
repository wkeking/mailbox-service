-- MySQL 8 migration for external Client API Key metadata.
-- API Key plaintext is returned once and never persisted.

CREATE TABLE IF NOT EXISTS client_keys (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(100) NOT NULL,
    secret_digest CHAR(64) NOT NULL,
    scopes JSON NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at DATETIME(6) NULL,
    last_used_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uq_client_keys_name UNIQUE (name),
    CONSTRAINT uq_client_keys_secret_digest UNIQUE (secret_digest),
    INDEX ix_client_keys_enabled_expires (enabled, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- leases.client_key_id already exists in the initial schema. Historical values
-- are intentionally preserved, so this migration does not add a foreign key.
