-- Move account+user creation from the register endpoint to the operator.
-- freshacc_requests now stores all registration data so the operator
-- can create the account row after approval.

-- Drop FK constraints so freshacc_requests and users can exist without accounts.
ALTER TABLE freshacc_requests DROP CONSTRAINT IF EXISTS freshacc_requests_private_acc_address_fkey;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_private_acc_address_fkey;

-- Add registration data columns to freshacc_requests.
ALTER TABLE freshacc_requests
    ADD COLUMN private_identifier BYTEA,
    ADD COLUMN eth_address        TEXT,
    ADD COLUMN name               TEXT,
    ADD COLUMN physical_address   TEXT,
    ADD COLUMN dob                DATE;
