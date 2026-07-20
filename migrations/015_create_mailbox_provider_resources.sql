-- Provider resource lifecycle for non-Microsoft inventory (CASE-20260720-001).

CREATE TABLE IF NOT EXISTS mailbox_provider_resources (
    mailbox_id VARCHAR(36) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    provider_instance_id VARCHAR(64) NOT NULL,
    external_resource_id VARCHAR(255) NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL,
    readiness VARCHAR(32) NOT NULL,
    state_version BIGINT NOT NULL DEFAULT 0,
    resource_generation BIGINT NOT NULL DEFAULT 0,
    encrypted_secret TEXT NULL,
    secret_expires_at DATETIME(6) NULL,
    metadata_json JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (mailbox_id),
    UNIQUE KEY uq_provider_instance_external (provider_instance_id, external_resource_id),
    INDEX ix_provider_resources_lifecycle (provider_type, lifecycle_state, readiness),
    CONSTRAINT fk_provider_resources_mailbox
        FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;
