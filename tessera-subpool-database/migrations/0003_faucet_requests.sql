CREATE TABLE faucet_requests (
    id          BIGSERIAL   PRIMARY KEY,
    eth_address TEXT        NOT NULL UNIQUE,
    tx_hash     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
