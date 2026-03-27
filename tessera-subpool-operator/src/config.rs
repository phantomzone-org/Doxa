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
	/// Ethereum JSON-RPC URL for broadcasting deposit transactions. Env: RPC_URL (required).
	pub rpc_url: String,
	/// How often to poll for pending FreshAcc requests. Env: POLL_INTERVAL_SECS (default 5).
	pub poll_interval: Duration,
	/// Subpool ID for this operator instance. Env: SUBPOOL_ID (default 1).
	pub subpool_id: u64,
	/// Deployed rollup contract address. Env: ROLLUP_ADDRESS (required).
	pub rollup_address: String,
}

impl OperatorConfig {
	pub fn from_env() -> Result<Self> {
		let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;

		let db_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
			.unwrap_or_else(|_| "5".to_string())
			.parse::<u32>()
			.context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

		let sequencer_url = std::env::var("SEQUENCER_URL").context("SEQUENCER_URL not set")?;

		let approval_private_key =
			std::env::var("APPROVAL_PRIVATE_KEY").context("APPROVAL_PRIVATE_KEY not set")?;

		let rpc_url = std::env::var("RPC_URL").context("RPC_URL not set")?;

		let poll_interval = Duration::from_secs(
			std::env::var("POLL_INTERVAL_SECS")
				.unwrap_or_else(|_| "5".to_string())
				.parse()
				.context("POLL_INTERVAL_SECS must be a positive integer")?,
		);

		let subpool_id = std::env::var("SUBPOOL_ID")
			.unwrap_or_else(|_| "1".to_string())
			.parse::<u64>()
			.context("SUBPOOL_ID must be a positive integer")?;

		let rollup_address = std::env::var("ROLLUP_ADDRESS").context("ROLLUP_ADDRESS not set")?;

		Ok(Self {
			database_url,
			db_max_connections,
			sequencer_url,
			approval_private_key,
			rpc_url,
			poll_interval,
			subpool_id,
			rollup_address,
		})
	}
}
