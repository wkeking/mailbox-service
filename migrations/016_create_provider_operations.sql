-- Durable provider operations for replenish / release / reconcile (CASE-20260720-001).

CREATE TABLE IF NOT EXISTS mailbox_provider_operations (
    id VARCHAR(36) NOT NULL,
    operation_type VARCHAR(32) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    provider_instance_id VARCHAR(64) NOT NULL,
    mailbox_id VARCHAR(36) NULL,
    lease_id VARCHAR(36) NULL,
    external_resource_id VARCHAR(255) NULL,
    resource_generation BIGINT NULL,
    expected_state_version BIGINT NULL,
    status VARCHAR(32) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    last_error_class VARCHAR(64) NULL,
    result_summary_json JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_provider_ops_idempotency (idempotency_key),
    INDEX ix_provider_ops_status (status, updated_at),
    INDEX ix_provider_ops_mailbox (mailbox_id, status),
    CONSTRAINT fk_provider_ops_mailbox
        FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE SET NULL
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;
