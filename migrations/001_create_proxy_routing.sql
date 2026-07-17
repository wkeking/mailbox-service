-- MySQL 8 migration for sticky global egress proxy routing.
-- Applied automatically on API startup (schema_migrations) or manually before start.

CREATE TABLE IF NOT EXISTS egress_proxies (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(100) NOT NULL,
    protocol ENUM('http_connect', 'socks5') NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT UNSIGNED NOT NULL,
    username_ciphertext TEXT NULL,
    password_ciphertext TEXT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INT NOT NULL DEFAULT 100,
    status ENUM('healthy', 'cooldown', 'unknown') NOT NULL DEFAULT 'unknown',
    consecutive_failure_count INT UNSIGNED NOT NULL DEFAULT 0,
    cooldown_until DATETIME(6) NULL,
    last_success_at DATETIME(6) NULL,
    last_failure_at DATETIME(6) NULL,
    last_error_summary VARCHAR(500) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uq_egress_proxies_name UNIQUE (name),
    CONSTRAINT uq_egress_proxies_endpoint UNIQUE (protocol, host, port),
    INDEX ix_egress_proxies_selection (enabled, status, priority, cooldown_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS mailboxes (
    id VARCHAR(36) NOT NULL,
    primary_email VARCHAR(320) NOT NULL,
    status ENUM('active', 'disabled', 'invalid', 'cooldown') NOT NULL DEFAULT 'active',
    client_id VARCHAR(255) NULL,
    mail_password_ciphertext TEXT NULL,
    refresh_token_ciphertext TEXT NULL,
    token_version INT UNSIGNED NOT NULL DEFAULT 1,
    egress_proxy_id VARCHAR(36) NULL,
    proxy_bound_at DATETIME(6) NULL,
    proxy_last_switch_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uq_mailboxes_primary_email UNIQUE (primary_email),
    CONSTRAINT fk_mailboxes_egress_proxy
        FOREIGN KEY (egress_proxy_id) REFERENCES egress_proxies(id) ON DELETE SET NULL,
    INDEX ix_mailboxes_egress_proxy_id (egress_proxy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS proxy_policy (
    id TINYINT UNSIGNED NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_protocols JSON NOT NULL,
    connect_timeout_seconds INT UNSIGNED NOT NULL DEFAULT 10,
    read_timeout_seconds INT UNSIGNED NOT NULL DEFAULT 30,
    health_check_interval_seconds INT UNSIGNED NOT NULL DEFAULT 300,
    failure_threshold INT UNSIGNED NOT NULL DEFAULT 3,
    cooldown_seconds INT UNSIGNED NOT NULL DEFAULT 300,
    switch_minimum_interval_seconds INT UNSIGNED NOT NULL DEFAULT 60,
    allow_direct_development BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT ck_proxy_policy_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS leases (
    id VARCHAR(36) NOT NULL,
    mailbox_id VARCHAR(36) NOT NULL,
    client_key_id VARCHAR(255) NULL,
    client_tag VARCHAR(100) NULL,
    purpose VARCHAR(100) NULL,
    mode ENUM('refresh_token', 'access_token', 'mail_read') NOT NULL DEFAULT 'access_token',
    expires_at DATETIME(6) NOT NULL,
    released_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT fk_leases_mailbox
        FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE,
    INDEX ix_leases_mailbox_id (mailbox_id),
    INDEX ix_leases_mailbox_active (mailbox_id, released_at, expires_at),
    INDEX ix_leases_client_created (client_key_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) NOT NULL,
    actor_type VARCHAR(30) NOT NULL,
    actor_id VARCHAR(255) NULL,
    event_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(36) NULL,
    metadata_json JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    INDEX ix_audit_logs_target (target_type, target_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
