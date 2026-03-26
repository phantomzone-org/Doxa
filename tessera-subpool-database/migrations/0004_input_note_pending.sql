-- Add PENDING status to input_note_status and a note_commitment column
-- so that deposit-originated notes can be confirmed on-chain before use.

ALTER TYPE input_note_status ADD VALUE IF NOT EXISTS 'PENDING' BEFORE 'APPROVED';

ALTER TABLE input_notes ADD COLUMN IF NOT EXISTS note_commitment BYTEA;
