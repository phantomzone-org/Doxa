-- ── Enum types ────────────────────────────────────────────────────────────────

CREATE TYPE freshacc_status   AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE deposit_tx_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

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
    private_identifier       BYTEA       NOT NULL,
    subpool_id               BYTEA       NOT NULL,
    balance                  BYTEA       NOT NULL,
    nonce                    BYTEA       NOT NULL,
    spend_auth               BYTEA       NOT NULL,
    consume_auth             BYTEA       NOT NULL,
    ast                      JSONB       NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── users ─────────────────────────────────────────────────────────────────────
-- No FK to accounts — account row is created separately after approval.

CREATE TABLE users (
    id                       BIGSERIAL   PRIMARY KEY,
    private_acc_address      TEXT        NOT NULL UNIQUE,
    name                     TEXT        NOT NULL,
    physical_address         TEXT        NOT NULL,
    dob                      DATE        NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── freshacc_requests ─────────────────────────────────────────────────────────
-- No FK to accounts — submitted before account is approved/created.

CREATE TABLE freshacc_requests (
    id                       BIGSERIAL       PRIMARY KEY,
    private_acc_address      TEXT            NOT NULL UNIQUE,
    spend_auth               BYTEA           NOT NULL,
    approval_signature       BYTEA,
    rejection_msg            TEXT,
    status                   freshacc_status NOT NULL DEFAULT 'PENDING',
    created_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ── deposit_tx_requests ───────────────────────────────────────────────────────
-- deposit_note_identifier: [F;2] = 16 bytes
-- deposit_amount:          U256  = 32 bytes
-- asset_id:                F     =  8 bytes
-- signed_public_tx:        RLP-encoded signed ETH tx (variable length)

CREATE TABLE deposit_tx_requests (
    id                       BIGSERIAL         PRIMARY KEY,
    recipient_acc_address    TEXT              NOT NULL,
    eth_address              TEXT              NOT NULL,
    deposit_note_identifier  BYTEA             NOT NULL UNIQUE,
    deposit_amount           BYTEA             NOT NULL,
    asset_id                 BYTEA             NOT NULL,
    signed_public_tx         BYTEA             NOT NULL,
    status                   deposit_tx_status NOT NULL DEFAULT 'PENDING',
    approval_signature       BYTEA,
    rejection_reason         TEXT,
    created_at               TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ       NOT NULL DEFAULT NOW()
);

-- ── faucet_requests ───────────────────────────────────────────────────────────

CREATE TABLE faucet_requests (
    id          BIGSERIAL   PRIMARY KEY,
    eth_address TEXT        NOT NULL UNIQUE,
    tx_hash     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
