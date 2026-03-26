-- Add deposit_tx_hash column missed in initial migration
ALTER TABLE deposit_tx_requests ADD COLUMN IF NOT EXISTS deposit_tx_hash TEXT;

CREATE TYPE spend_tx_status   AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE input_note_status AS ENUM ('APPROVED', 'REJECTED');

CREATE TABLE spend_tx_requests (
    id                 BIGSERIAL PRIMARY KEY,
    priv_acc_address   TEXT      NOT NULL,
    inote_identifiers  TEXT[]    NOT NULL,
    onote_identifiers  TEXT[]    NOT NULL,
    dinotes            TEXT[]    NOT NULL,
    donotes            TEXT[]    NOT NULL,
    status             spend_tx_status NOT NULL DEFAULT 'PENDING',
    approval_signature BYTEA,
    rejection_reason   TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE input_notes (
    id                BIGSERIAL PRIMARY KEY,
    identifier        TEXT        NOT NULL UNIQUE,
    asset_id          BYTEA       NOT NULL,
    amount            BYTEA       NOT NULL,
    recipient_address TEXT        NOT NULL,
    sender_address    TEXT        NOT NULL,
    status            input_note_status NOT NULL DEFAULT 'APPROVED',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE output_notes (
    id                BIGSERIAL PRIMARY KEY,
    identifier        TEXT        NOT NULL UNIQUE,
    asset_id          BYTEA       NOT NULL,
    amount            BYTEA       NOT NULL,
    recipient_address TEXT        NOT NULL,
    sender_address    TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
