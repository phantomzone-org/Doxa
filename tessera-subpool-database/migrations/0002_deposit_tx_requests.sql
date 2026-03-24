CREATE TYPE deposit_tx_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

CREATE TABLE deposit_tx_requests (
    id                       BIGSERIAL PRIMARY KEY,
    recipient_acc_address    TEXT               NOT NULL REFERENCES accounts(private_acc_address),
    eth_address              TEXT               NOT NULL,
    deposit_note_identifier  BYTEA              NOT NULL UNIQUE, -- [F;2] = 16 bytes
    deposit_amount           BYTEA              NOT NULL,        -- U256 = 32 bytes
    asset_id                 BYTEA              NOT NULL,        -- F = 8 bytes
    signed_public_tx         BYTEA              NOT NULL,        -- RLP-encoded signed ETH tx
    status                   deposit_tx_status  NOT NULL DEFAULT 'PENDING',
    approval_signature       BYTEA,
    rejection_reason         TEXT,
    created_at               TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ        NOT NULL DEFAULT NOW()
);
