-- Current exclusive lease occupancy. leases keeps history; this table is the
-- single active claim per mailbox enforced by PRIMARY KEY (mailbox_id).

CREATE TABLE IF NOT EXISTS mailbox_lease_claims (
    mailbox_id VARCHAR(36) NOT NULL,
    lease_id VARCHAR(36) NOT NULL,
    client_key_id VARCHAR(255) NULL,
    mode ENUM('refresh_token', 'access_token', 'mail_read') NOT NULL,
    allocated_email VARCHAR(320) NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (mailbox_id),
    UNIQUE KEY uq_mailbox_lease_claims_lease_id (lease_id),
    UNIQUE KEY uq_mailbox_lease_claims_allocated_email (allocated_email),
    INDEX ix_mailbox_lease_claims_expires_at (expires_at),
    INDEX ix_mailbox_lease_claims_client (client_key_id, expires_at),
    CONSTRAINT fk_mailbox_lease_claims_mailbox
        FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id) ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;

-- Fail migration when historical data has multiple active leases for one mailbox.
SET @conflict_count = (
    SELECT COUNT(*) FROM (
        SELECT mailbox_id
        FROM leases
        WHERE released_at IS NULL
          AND expires_at > UTC_TIMESTAMP(6)
        GROUP BY mailbox_id
        HAVING COUNT(*) > 1
    ) AS conflicting_mailboxes
);
SET @conflict_message = IF(
    @conflict_count > 0,
    CONCAT(
        'migration 012 refused: ',
        @conflict_count,
        ' mailbox(es) have multiple active leases; resolve before creating mailbox_lease_claims'
    ),
    NULL
);
-- SIGNAL only when conflicts exist (MySQL requires a statement; use prepared no-op otherwise).
SET @signal_sql = IF(
    @conflict_count > 0,
    CONCAT('SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''', @conflict_message, ''''),
    'SELECT 1'
);
PREPARE conflict_stmt FROM @signal_sql;
EXECUTE conflict_stmt;
DEALLOCATE PREPARE conflict_stmt;

-- Backfill one claim per mailbox from the newest active lease.
INSERT IGNORE INTO mailbox_lease_claims (
    mailbox_id,
    lease_id,
    client_key_id,
    mode,
    allocated_email,
    expires_at,
    created_at
)
SELECT
    ranked.mailbox_id,
    ranked.id,
    ranked.client_key_id,
    ranked.mode,
    ranked.allocated_email,
    ranked.expires_at,
    ranked.created_at
FROM (
    SELECT
        leases.mailbox_id,
        leases.id,
        leases.client_key_id,
        leases.mode,
        leases.allocated_email,
        leases.expires_at,
        leases.created_at,
        ROW_NUMBER() OVER (
            PARTITION BY leases.mailbox_id
            ORDER BY leases.created_at DESC, leases.id DESC
        ) AS row_rank
    FROM leases
    WHERE leases.released_at IS NULL
      AND leases.expires_at > UTC_TIMESTAMP(6)
) AS ranked
WHERE ranked.row_rank = 1;
