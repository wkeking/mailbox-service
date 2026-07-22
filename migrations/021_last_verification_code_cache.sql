-- Cache last successfully extracted verification code for admin/operator debugging.
-- Sensitive: only expose via Admin APIs; never log plaintext codes.

ALTER TABLE mailbox_provider_resources
  ADD COLUMN last_verification_code VARCHAR(32) NULL AFTER metadata_json,
  ADD COLUMN last_code_checked_at DATETIME(6) NULL AFTER last_verification_code,
  ADD COLUMN last_code_message_id VARCHAR(255) NULL AFTER last_code_checked_at;

ALTER TABLE mailboxes
  ADD COLUMN last_verification_code VARCHAR(32) NULL AFTER capability_probe_error,
  ADD COLUMN last_code_checked_at DATETIME(6) NULL AFTER last_verification_code,
  ADD COLUMN last_code_message_id VARCHAR(255) NULL AFTER last_code_checked_at;
