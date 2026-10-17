-- First-contact unlinkability (TASK-001 C, §7.2.1): prekey-issuance idempotency
-- is no longer keyed by requester. Storing the requester is exactly the
-- initiator -> target linkage this change removes, so the requester columns go
-- away. Idempotency is now per (target, 24 h window): one OTPK per target per
-- window, shared by every fetch in that window.
DROP TABLE prekey_issuances;
CREATE TABLE prekey_issuances (
    target_user_id   UUID NOT NULL,
    target_device_id INTEGER NOT NULL,
    window_start     TIMESTAMPTZ NOT NULL,
    prekey_id        INTEGER NOT NULL,
    public_key       BYTEA NOT NULL,
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (target_user_id, target_device_id, window_start)
);
