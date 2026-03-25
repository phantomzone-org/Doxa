use std::time::Duration;

use anyhow::{Context, Result};

pub struct OperatorConfig {
    /// PostgreSQL connection string. Env: DATABASE_URL (required).
    pub database_url: String,
    /// Max DB connections in pool. Env: DATABASE_MAX_CONNECTIONS (default 5).
    pub db_max_connections: u32,
    /// Sequencer HTTP URL. Env: SEQUENCER_URL (required).
    pub sequencer_url: String,
    /// Approval private key as 40-byte hex (5 × u64 LE). Env: APPROVAL_PRIVATE_KEY (required).
    pub approval_private_key: String,
    /// How often to poll for pending FreshAcc requests. Env: POLL_INTERVAL_SECS (default 5).
    pub poll_interval: Duration,
}

impl OperatorConfig {
    pub fn from_env() -> Result<Self> {
        let database_url =
            std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;

        let db_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

        let sequencer_url =
            std::env::var("SEQUENCER_URL").context("SEQUENCER_URL not set")?;

        let approval_private_key =
            std::env::var("APPROVAL_PRIVATE_KEY").context("APPROVAL_PRIVATE_KEY not set")?;

        let poll_interval = Duration::from_secs(
            std::env::var("POLL_INTERVAL_SECS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .context("POLL_INTERVAL_SECS must be a positive integer")?,
        );

        Ok(Self {
            database_url,
            db_max_connections,
            sequencer_url,
            approval_private_key,
            poll_interval,
        })
    }
}
