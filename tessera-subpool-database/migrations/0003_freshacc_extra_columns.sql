-- Add columns to freshacc_requests that the operator needs to reconstruct the
-- account and create the accounts + users rows after approval.

ALTER TABLE freshacc_requests ADD COLUMN IF NOT EXISTS private_identifier BYTEA;
ALTER TABLE freshacc_requests ADD COLUMN IF NOT EXISTS eth_address TEXT;
ALTER TABLE freshacc_requests ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE freshacc_requests ADD COLUMN IF NOT EXISTS physical_address TEXT;
ALTER TABLE freshacc_requests ADD COLUMN IF NOT EXISTS dob DATE;
