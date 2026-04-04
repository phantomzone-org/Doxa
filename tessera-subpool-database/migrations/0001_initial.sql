-- ── Enum types ────────────────────────────────────────────────────────────────

CREATE TYPE freshacc_status        AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE deposit_tx_status      AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE deposit_check_status   AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE spend_tx_status        AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE input_note_status      AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE withdrawal_tx_status   AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- ── accounts ──────────────────────────────────────────────────────────────────
-- All Goldilocks field elements stored as BYTEA via to_canonical_u64().to_le_bytes().
-- PrivateIdentifier([F;2]): 16 bytes (2×u64 LE)
-- SubpoolId(F):              8 bytes (1×u64 LE)
-- Nonce(F):                  8 bytes (1×u64 LE)
-- CompressedPublicKey<F>:   40 bytes (5×u64 LE); all-zeros when absent
-- U256:                     32 bytes (4×u64 LE)

CREATE TABLE accounts (
    id                       BIGSERIAL   PRIMARY KEY,
    private_acc_address      TEXT        NOT NULL UNIQUE,
    eth_address              TEXT        NOT NULL,
    private_identifier       TEXT        NOT NULL UNIQUE,
    subpool_id               BYTEA       NOT NULL,
    nonce                    BYTEA       NOT NULL,
    spend_auth               BYTEA       NOT NULL,
    consume_auth             BYTEA       NOT NULL,
    ast                      JSONB       NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── users ─────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id                       BIGSERIAL   PRIMARY KEY,
    private_acc_address      TEXT        NOT NULL UNIQUE,
    name                     TEXT        NOT NULL,
    physical_address         TEXT        NOT NULL,
    dob                      DATE        NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── freshacc_requests ─────────────────────────────────────────────────────────

CREATE TABLE freshacc_requests (
    id                       BIGSERIAL       PRIMARY KEY,
    private_acc_address      TEXT            NOT NULL UNIQUE,
    private_identifier       TEXT            NOT NULL UNIQUE,
    spend_auth               BYTEA           NOT NULL,
    approval_signature       BYTEA,
    rejection_msg            TEXT,
    status                   freshacc_status NOT NULL DEFAULT 'PENDING',
    created_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ── deposit_tx_requests ───────────────────────────────────────────────────────
-- deposit_note_identifier:  [F;2] = 16 bytes
-- deposit_amount:           U256  = 32 bytes
-- asset_id:                 F     =  8 bytes
-- deposit_type_signature:   EIP-712 typed-data signature (65 bytes)

CREATE TABLE deposit_tx_requests (
    id                       BIGSERIAL         PRIMARY KEY,
    recipient_address    TEXT              NOT NULL,
    eth_address              TEXT              NOT NULL,
    deposit_note_identifier  BYTEA             NOT NULL UNIQUE,
    deposit_amount           BYTEA             NOT NULL,
    asset_id                 BYTEA             NOT NULL,
    deposit_type_signature   BYTEA             NOT NULL,
    deposit_tx_hash          TEXT,
    status                   deposit_tx_status NOT NULL DEFAULT 'PENDING',
    approval_signature       BYTEA,
    rejection_reason         TEXT,
    created_at               TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ       NOT NULL DEFAULT NOW()
);

-- ── deposit_checks ────────────────────────────────────────────────────────────

CREATE TABLE deposit_checks (
    id                     BIGSERIAL            PRIMARY KEY,
    deposit_tx_request_id  BIGINT               NOT NULL REFERENCES deposit_tx_requests(id),
    eth_address            TEXT                 NOT NULL,
    check_response         TEXT,
    status                 deposit_check_status NOT NULL DEFAULT 'PENDING',
    created_at             TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ          NOT NULL DEFAULT NOW()
);

-- ── faucet_requests ───────────────────────────────────────────────────────────

CREATE TABLE faucet_requests (
    id          BIGSERIAL   PRIMARY KEY,
    eth_address TEXT        NOT NULL UNIQUE,
    tx_hash     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── spend_tx_requests ─────────────────────────────────────────────────────────

CREATE TABLE spend_tx_requests (
    id                 BIGSERIAL       PRIMARY KEY,
    priv_acc_address   TEXT            NOT NULL,
    inote_identifiers  TEXT[]          NOT NULL,
    onote_identifiers  TEXT[]          NOT NULL,
    dinotes            TEXT[]          NOT NULL,
    donotes            TEXT[]          NOT NULL,
    spend_tx_signature BYTEA           NOT NULL,
    status             spend_tx_status NOT NULL DEFAULT 'PENDING',
    approval_signature BYTEA,
    rejection_reason   TEXT,
    created_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ── input_notes ───────────────────────────────────────────────────────────────

CREATE TABLE input_notes (
    id                BIGSERIAL         PRIMARY KEY,
    identifier        TEXT              NOT NULL UNIQUE,
    asset_id          BYTEA             NOT NULL,
    amount            BYTEA             NOT NULL,
    recipient_address TEXT              NOT NULL,
    sender_address    TEXT              NOT NULL,
    memo              BYTEA             NOT NULL DEFAULT '\x'::bytea,
    consume           BOOLEAN           NOT NULL DEFAULT FALSE,
    status            input_note_status NOT NULL DEFAULT 'APPROVED',
    created_at        TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ       NOT NULL DEFAULT NOW()
);

-- ── withdrawal_tx_requests ────────────────────────────────────────────────────
-- amount:   U256 = 32 bytes LE
-- asset_id: F    =  8 bytes LE

CREATE TABLE withdrawal_tx_requests (
    id                     BIGSERIAL            PRIMARY KEY,
    priv_acc_address       TEXT                 NOT NULL,
    withdrawal_eth_address TEXT                 NOT NULL,
    amount                 BYTEA                NOT NULL,
    asset_id               BYTEA                NOT NULL,
    status                 withdrawal_tx_status NOT NULL DEFAULT 'PENDING',
    rejection_reason       TEXT,
    created_at             TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ          NOT NULL DEFAULT NOW()
);

-- ── output_notes ──────────────────────────────────────────────────────────────

CREATE TABLE output_notes (
    id                BIGSERIAL   PRIMARY KEY,
    identifier        TEXT        NOT NULL UNIQUE,
    asset_id          BYTEA       NOT NULL,
    amount            BYTEA       NOT NULL,
    recipient_address TEXT        NOT NULL,
    sender_address    TEXT        NOT NULL,
    memo              BYTEA       NOT NULL DEFAULT '\x'::bytea,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
