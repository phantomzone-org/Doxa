-- Create 3 schemas for 3 subpools in a single database.
-- Table creation is handled by sqlx::migrate! when each DB API service starts.
CREATE SCHEMA IF NOT EXISTS subpool_1;
CREATE SCHEMA IF NOT EXISTS subpool_2;
CREATE SCHEMA IF NOT EXISTS subpool_3;
