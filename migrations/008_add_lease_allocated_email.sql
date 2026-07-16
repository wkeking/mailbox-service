-- Persist the email address allocated for a lease (primary or plus alias).
-- OAuth / IMAP still use mailboxes.primary_email; recipient matching uses this field.

ALTER TABLE leases
    ADD COLUMN allocated_email VARCHAR(320) NULL AFTER purpose;

CREATE INDEX ix_leases_allocated_email ON leases (allocated_email);
