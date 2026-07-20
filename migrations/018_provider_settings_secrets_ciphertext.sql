-- Extra encrypted secrets JSON for multi-field provider credentials
-- (e.g. admin_password + ddg_token alongside primary api_key_ciphertext).
ALTER TABLE provider_instance_settings
    ADD COLUMN secrets_ciphertext TEXT NULL;
