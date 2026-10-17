-- Quietly home server — initial schema (PROTOCOL.md §2, §7, §11).

CREATE TABLE IF NOT EXISTS users (
    id         UUID PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id                 INTEGER NOT NULL,
    identity_key_dh    BYTEA NOT NULL,
    identity_key_sig   BYTEA NOT NULL,
    identity_binding   BYTEA NOT NULL,
    signed_prekey_id   INTEGER NOT NULL,
    signed_prekey      BYTEA NOT NULL,
    signed_prekey_sig  BYTEA NOT NULL,
    signed_prekey_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivery_token     BYTEA NOT NULL,
    delivery_token_hash BYTEA NOT NULL,
    push_endpoint      TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ,
    PRIMARY KEY (user_id, id),
    CONSTRAINT devices_id_range CHECK (id BETWEEN 1 AND 65535)
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    device_user_id UUID NOT NULL,
    device_id      INTEGER NOT NULL,
    prekey_id      INTEGER NOT NULL,
    public_key     BYTEA NOT NULL,
    used           BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (device_user_id, device_id, prekey_id),
    FOREIGN KEY (device_user_id, device_id)
        REFERENCES devices(user_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id                  TEXT PRIMARY KEY,
    recipient_user_id   UUID NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    sealed              BYTEA NOT NULL,
    server_ts           TIMESTAMPTZ NOT NULL,
    ttl_expires_at      TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (recipient_user_id, recipient_device_id)
        REFERENCES devices(user_id, id) ON DELETE CASCADE
);
-- Messages are deleted on ack; there is no delivered flag (audit F-17).

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages (recipient_user_id, recipient_device_id, server_ts);
CREATE INDEX IF NOT EXISTS idx_messages_ttl ON messages (ttl_expires_at);
CREATE INDEX IF NOT EXISTS idx_prekeys_available
    ON one_time_prekeys (device_user_id, device_id) WHERE NOT used;

-- Per-pair prekey-fetch idempotency (§7.2.1 mitigation 2): repeat fetches by
-- the same requester for the same target within the window return the same key.
CREATE TABLE IF NOT EXISTS prekey_issuances (
    requester_user_id   UUID NOT NULL,
    requester_device_id INTEGER NOT NULL,
    target_user_id      UUID NOT NULL,
    target_device_id    INTEGER NOT NULL,
    prekey_id           INTEGER NOT NULL,
    public_key          BYTEA NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (requester_user_id, requester_device_id, target_user_id, target_device_id)
);
