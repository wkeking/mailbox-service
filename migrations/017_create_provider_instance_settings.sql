-- 017: Admin-editable Provider instance settings (SMSBower etc.)
-- Secrets live only in encrypted columns; never in config_json.

CREATE TABLE IF NOT EXISTS provider_instance_settings (
    provider_type VARCHAR(64) NOT NULL,
    instance_id VARCHAR(64) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    api_base VARCHAR(512) NULL,
    api_key_ciphertext TEXT NULL,
    service_code VARCHAR(64) NULL,
    domain VARCHAR(255) NULL,
    max_price DOUBLE NULL,
    request_timeout_seconds DOUBLE NOT NULL DEFAULT 30,
    config_json JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (provider_type, instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
