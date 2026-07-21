-- Allow concurrent plus-alias mail_read leases on the same mailbox.
-- Exclusive modes (access_token / refresh_token / primary mail_read) still
-- enforce at most one exclusive claim per mailbox in application logic.
--
-- Schema change: PRIMARY KEY becomes lease_id (was mailbox_id).

ALTER TABLE mailbox_lease_claims
    DROP PRIMARY KEY,
    DROP INDEX uq_mailbox_lease_claims_lease_id,
    ADD PRIMARY KEY (lease_id),
    ADD INDEX ix_mailbox_lease_claims_mailbox_id (mailbox_id);
