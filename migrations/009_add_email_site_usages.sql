-- Whitelist of registration sites and global email/site usage occupancy.
-- Safe to run multiple times on MySQL 8 because each step is gated by information_schema.

CREATE TABLE IF NOT EXISTS usage_sites (
    code VARCHAR(64) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (code),
    INDEX ix_usage_sites_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO usage_sites (code, display_name, enabled)
SELECT 'openai', 'OpenAI', TRUE
WHERE NOT EXISTS (SELECT 1 FROM usage_sites WHERE code = 'openai');

INSERT INTO usage_sites (code, display_name, enabled)
SELECT 'grok', 'Grok', TRUE
WHERE NOT EXISTS (SELECT 1 FROM usage_sites WHERE code = 'grok');

CREATE TABLE IF NOT EXISTS email_site_usages (
    id VARCHAR(36) NOT NULL,
    allocated_email VARCHAR(320) NOT NULL,
    usage_site_code VARCHAR(64) NOT NULL,
    mailbox_id VARCHAR(36) NULL,
    lease_id VARCHAR(36) NULL,
    client_key_id VARCHAR(255) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at DATETIME(6) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uq_email_site_usages_email_site UNIQUE (allocated_email, usage_site_code),
    CONSTRAINT fk_email_site_usages_usage_site
        FOREIGN KEY (usage_site_code) REFERENCES usage_sites (code),
    CONSTRAINT fk_email_site_usages_mailbox
        FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE SET NULL,
    CONSTRAINT fk_email_site_usages_lease
        FOREIGN KEY (lease_id) REFERENCES leases (id) ON DELETE SET NULL,
    INDEX ix_email_site_usages_site_revoked (usage_site_code, revoked_at),
    INDEX ix_email_site_usages_mailbox (mailbox_id),
    INDEX ix_email_site_usages_lease (lease_id),
    INDEX ix_email_site_usages_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
