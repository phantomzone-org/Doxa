use std::path::PathBuf;

use alloy::primitives::Address;
use anyhow::{Context, Result};

/// Configuration for the sequencer, loaded from environment variables.
pub struct SequencerConfig {
	/// Ethereum JSON-RPC URL (e.g., http://localhost:8545 for anvil).
	pub rpc_url: String,
	/// Operator private key (hex-encoded, with or without 0x prefix).
	pub operator_private_key: String,
	/// DepositsRollupBridge contract address.
	pub bridge_address: Address,
	/// Chain ID.
	pub chain_id: u64,
	/// Path to plonky2 circuit data directory.
	pub plonky2_data_path: PathBuf,
	/// Path to Groth16 trusted setup artifacts directory.
	pub groth16_artifacts_path: PathBuf,
	/// Polling interval in seconds for on-chain events (default: 12).
	pub poll_interval_secs: u64,
	/// HTTP bind address for direct consume requests API (default: 127.0.0.1:8081).
	pub api_bind_addr: String,
}

/// Subdirectory names under the pending-deposits artifacts base path.
pub const PENDING_DEPOSITS_PLONKY2_DIR: &str = "plonky2-proof";
pub const PENDING_DEPOSITS_GROTH16_DIR: &str = "groth-artifacts";

impl SequencerConfig {
	/// Load configuration from environment variables.
	///
	/// Required:
	///   TESSERA_RPC_URL, TESSERA_OPERATOR_KEY, TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS,
	///   TESSERA_CHAIN_ID, TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH
	///
	/// Optional (with defaults):
	///   TESSERA_POLL_INTERVAL_SECS (default 12)
	///   TESSERA_SEQUENCER_API_ADDR (default 127.0.0.1:8081)
	pub fn from_env() -> Result<Self> {
		let rpc_url = std::env::var("TESSERA_RPC_URL").context("TESSERA_RPC_URL not set")?;

		let operator_private_key =
			std::env::var("TESSERA_OPERATOR_KEY").context("TESSERA_OPERATOR_KEY not set")?;

		let bridge_address: Address = std::env::var("TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")
			.context("TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS not set")?
			.parse()
			.context("invalid TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")?;

		let chain_id: u64 = std::env::var("TESSERA_CHAIN_ID")
			.context("TESSERA_CHAIN_ID not set")?
			.parse()
			.context("invalid TESSERA_CHAIN_ID")?;

		let artifacts_base: PathBuf = std::env::var("TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH")
			.context("TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH not set")?
			.into();

		let plonky2_data_path = artifacts_base.join(PENDING_DEPOSITS_PLONKY2_DIR);
		let groth16_artifacts_path = artifacts_base.join(PENDING_DEPOSITS_GROTH16_DIR);

		let poll_interval_secs: u64 = std::env::var("TESSERA_POLL_INTERVAL_SECS")
			.unwrap_or_else(|_| "12".to_string())
			.parse()
			.context("invalid TESSERA_POLL_INTERVAL_SECS")?;
		let api_bind_addr = std::env::var("TESSERA_SEQUENCER_API_ADDR")
			.unwrap_or_else(|_| "127.0.0.1:8081".to_string());

		Ok(Self {
			rpc_url,
			operator_private_key,
			bridge_address,
			chain_id,
			plonky2_data_path,
			groth16_artifacts_path,
			poll_interval_secs,
			api_bind_addr,
		})
	}
}
