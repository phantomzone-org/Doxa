CREATE TYPE freshacc_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- accounts (inserted first; users and freshacc_requests FK reference it)
-- All Goldilocks field elements stored as BYTEA via to_canonical_u64().to_le_bytes().
-- PrivateIdentifier([F;2]): 16 bytes (2×u64 LE)
-- SubpoolId(F):              8 bytes (1×u64 LE), always SUBPOOL_ID=1
-- Nonce(F):                  8 bytes (1×u64 LE)
-- CompressedPublicKey<F>:   40 bytes (5×u64 LE via encode()); all-zeros when absent
-- U256:                     32 bytes (4×u64 LE matching U256.0: [u64;4])
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

    -- {"<asset_id_decimal>": {"leaf_index": <u64>, "amount": "<hex_u256_64chars>"}}
    ast                      JSONB       NOT NULL DEFAULT '{}',

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id                       BIGSERIAL   PRIMARY KEY,
    private_acc_address      TEXT        NOT NULL UNIQUE
                               REFERENCES accounts(private_acc_address),
    name                     TEXT        NOT NULL,
    physical_address         TEXT        NOT NULL,
    dob                      DATE        NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE freshacc_requests (
    id                       BIGSERIAL       PRIMARY KEY,
    private_acc_address      TEXT            NOT NULL UNIQUE
                               REFERENCES accounts(private_acc_address),
    spend_auth               BYTEA           NOT NULL,
    approval_signature       BYTEA,
    rejection_msg            TEXT,
    status                   freshacc_status NOT NULL DEFAULT 'PENDING',
    created_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);
