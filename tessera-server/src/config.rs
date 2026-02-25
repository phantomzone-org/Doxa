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
	/// Polling interval in seconds for on-chain events (default: 12).
	pub poll_interval_secs: u64,
	/// Max time to wait before flushing a partially filled batch (default: 12).
	pub batch_timeout_secs: u64,
	/// HTTP bind address for direct consume requests API (default: 127.0.0.1:8081).
	pub api_bind_addr: String,
	/// Base directory for persisted tree state (WAL + snapshots).
	pub tree_store_path: PathBuf,
	/// Snapshot frequency in committed batches (default: 1).
	pub snapshot_every_batches: u64,
	/// Dedicated prover service base URL (default: http://127.0.0.1:8091).
	pub prover_api_url: String,
	/// Timeout in seconds for one prover request (default: 1800).
	pub prover_api_timeout_secs: u64,
	/// Optional path to pre-built `GenericAggregator` artifacts.
	/// When set, the API layer validates private-tx proof bytes cryptographically.
	/// Set via `TESSERA_AGGREGATOR_ARTIFACTS_PATH`.
	pub aggregator_artifacts_path: Option<PathBuf>,
	/// Optional path to pre-built consume-circuit artifacts.
	/// When set, the API layer validates /consume-request proof bytes cryptographically.
	/// Set via `TESSERA_CONSUME_ARTIFACTS_PATH`.
	pub consume_artifacts_path: Option<PathBuf>,
	/// Optional path to pre-built account-circuit artifacts.
	/// When set, the API layer validates /accounts/commitment proof bytes cryptographically.
	/// Set via `TESSERA_ACCOUNT_ARTIFACTS_PATH`.
	pub account_artifacts_path: Option<PathBuf>,
}

/// Configuration for the standalone prover service.
pub struct ProverConfig {
	/// Note-tree batch size expected by the note-tree circuits (notes-commitment +
	/// notes-nullifier).
	pub note_batch_size: usize,
	/// Account-tree batch size expected by the account-tree circuits (accounts-commitment +
	/// accounts-nullifier). Must equal `note_batch_size / 8`.
	pub account_batch_size: usize,
	/// HTTP bind address for prover API.
	pub api_bind_addr: String,
	/// Path to pre-built SuperAggregator artifacts directory.
	/// Set via `TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH`.
	pub super_aggregator_artifacts_path: PathBuf,
	/// Optional path to pre-built `GenericAggregator` artifacts for aggregating
	/// `PrivateTx` leaf proofs.  When `None` the prover accepts only dummy proofs.
	/// Set via `TESSERA_AGGREGATOR_ARTIFACTS_PATH`.
	pub aggregator_artifacts_path: Option<PathBuf>,
	/// Comma-separated list of remote aggregation prover base URLs.
	/// When empty (default) the coordinator uses only a local prover.
	/// Set via `TESSERA_AGGREGATION_PROVER_URLS`.
	pub aggregation_prover_urls: Vec<String>,
	/// Per-request HTTP timeout for remote aggregation provers (seconds).
	/// Set via `TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS` (default 300).
	pub aggregation_prover_timeout_secs: u64,
}

/// Configuration for the standalone `aggregation_prover` service.
pub struct AggregatorProverConfig {
	/// Path to pre-built `GenericAggregator` artifacts.
	/// Set via `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (required).
	pub artifacts_path: PathBuf,
	/// HTTP bind address for the aggregation prover API.
	/// Set via `TESSERA_AGGREGATION_PROVER_ADDR` (default `0.0.0.0:8092`).
	pub api_bind_addr: String,
}

impl AggregatorProverConfig {
	/// Load configuration from environment variables.
	///
	/// # Required env vars
	/// - `TESSERA_AGGREGATOR_ARTIFACTS_PATH`: path to pre-built `GenericAggregator` artifacts.
	///
	/// # Optional env vars (with defaults)
	/// - `TESSERA_AGGREGATION_PROVER_ADDR` (default `0.0.0.0:8092`): HTTP listen address.
	///
	/// # Errors
	/// Returns `Err` if any required variable is absent.
	pub fn from_env() -> anyhow::Result<Self> {
		let artifacts_path = std::env::var("TESSERA_AGGREGATOR_ARTIFACTS_PATH")
			.context("TESSERA_AGGREGATOR_ARTIFACTS_PATH not set")?
			.into();
		let api_bind_addr = std::env::var("TESSERA_AGGREGATION_PROVER_ADDR")
			.unwrap_or_else(|_| "0.0.0.0:8092".to_string());
		Ok(Self {
			artifacts_path,
			api_bind_addr,
		})
	}
}

impl SequencerConfig {
	/// Load sequencer configuration from environment variables.
	///
	/// # Required env vars
	/// - `TESSERA_RPC_URL`: Ethereum JSON-RPC endpoint.
	/// - `TESSERA_OPERATOR_KEY`: operator private key (hex, with or without `0x`).
	/// - `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`: `DepositsRollupBridge` contract address.
	/// - `TESSERA_CHAIN_ID`: EVM chain ID.
	///
	/// # Optional env vars (with defaults)
	/// - `TESSERA_POLL_INTERVAL_SECS` (default `12`): polling interval for on-chain events.
	/// - `TESSERA_BATCH_TIMEOUT_SECS` (default `12`): max wait before flushing a partial batch.
	/// - `TESSERA_SEQUENCER_API_ADDR` (default `127.0.0.1:8081`): HTTP API listen address.
	/// - `TESSERA_TREE_STORE_PATH` (default `<crate>/data/trees`): WAL + snapshot directory.
	/// - `TESSERA_TREE_SNAPSHOT_EVERY_BATCHES` (default `1`): snapshot frequency.
	/// - `TESSERA_PROVER_API_URL` (default `http://127.0.0.1:8091`): remote prover base URL.
	/// - `TESSERA_PROVER_API_TIMEOUT_SECS` (default `1800`): prover request timeout.
	/// - `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (unset = disabled): aggregator artifacts path.
	///
	/// # Errors
	/// Returns `Err` if any required variable is absent or any value fails to parse.
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

		let poll_interval_secs: u64 = std::env::var("TESSERA_POLL_INTERVAL_SECS")
			.unwrap_or_else(|_| "12".to_string())
			.parse()
			.context("invalid TESSERA_POLL_INTERVAL_SECS")?;
		let batch_timeout_secs: u64 = std::env::var("TESSERA_BATCH_TIMEOUT_SECS")
			.unwrap_or_else(|_| "12".to_string())
			.parse()
			.context("invalid TESSERA_BATCH_TIMEOUT_SECS")?;
		let api_bind_addr = std::env::var("TESSERA_SEQUENCER_API_ADDR")
			.unwrap_or_else(|_| "127.0.0.1:8081".to_string());

		let tree_store_path: PathBuf = std::env::var("TESSERA_TREE_STORE_PATH")
			.map(PathBuf::from)
			.unwrap_or_else(|_| {
				PathBuf::from(env!("CARGO_MANIFEST_DIR"))
					.join("data")
					.join("trees")
			});

		let snapshot_every_batches: u64 = std::env::var("TESSERA_TREE_SNAPSHOT_EVERY_BATCHES")
			.unwrap_or_else(|_| "1".to_string())
			.parse()
			.context("invalid TESSERA_TREE_SNAPSHOT_EVERY_BATCHES")?;
		let prover_api_url = std::env::var("TESSERA_PROVER_API_URL")
			.unwrap_or_else(|_| "http://127.0.0.1:8091".to_string());
		let prover_api_timeout_secs: u64 = std::env::var("TESSERA_PROVER_API_TIMEOUT_SECS")
			.unwrap_or_else(|_| "1800".to_string())
			.parse()
			.context("invalid TESSERA_PROVER_API_TIMEOUT_SECS")?;

		let aggregator_artifacts_path = std::env::var("TESSERA_AGGREGATOR_ARTIFACTS_PATH")
			.ok()
			.map(PathBuf::from);

		let consume_artifacts_path = std::env::var("TESSERA_CONSUME_ARTIFACTS_PATH")
			.ok()
			.map(PathBuf::from);

		let account_artifacts_path = std::env::var("TESSERA_ACCOUNT_ARTIFACTS_PATH")
			.ok()
			.map(PathBuf::from);

		Ok(Self {
			rpc_url,
			operator_private_key,
			bridge_address,
			chain_id,
			poll_interval_secs,
			batch_timeout_secs,
			api_bind_addr,
			tree_store_path,
			snapshot_every_batches,
			prover_api_url,
			prover_api_timeout_secs,
			aggregator_artifacts_path,
			consume_artifacts_path,
			account_artifacts_path,
		})
	}
}

impl ProverConfig {
	/// Load standalone prover configuration from environment variables.
	///
	/// # Required env vars
	/// - `TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH`: path to pre-built SuperAggregator artifacts.
	///
	/// # Optional env vars (with defaults)
	/// - `TESSERA_NOTE_BATCH_SIZE` (default `128`): leaf count per note-tree batch.
	/// - `TESSERA_ACCOUNT_BATCH_SIZE` (default `16`): leaf count per account-tree batch (must be
	///   1/8 of note size).
	/// - `TESSERA_PROVER_API_ADDR` (default `127.0.0.1:8091`): HTTP listen address.
	/// - `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (unset = disabled): aggregator artifacts path.
	/// - `TESSERA_AGGREGATION_PROVER_URLS` (default empty): comma-separated remote prover URLs.
	/// - `TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS` (default `300`): remote prover timeout.
	///
	/// # Errors
	/// Returns `Err` if any required variable is absent or any value fails to parse.
	pub fn from_env() -> Result<Self> {
		let super_aggregator_artifacts_path =
			std::env::var("TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH")
				.context("TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH not set")?
				.into();

		let note_batch_size: usize = std::env::var("TESSERA_NOTE_BATCH_SIZE")
			.unwrap_or_else(|_| "128".to_string())
			.parse()
			.context("invalid TESSERA_NOTE_BATCH_SIZE")?;
		let account_batch_size: usize = std::env::var("TESSERA_ACCOUNT_BATCH_SIZE")
			.unwrap_or_else(|_| "16".to_string())
			.parse()
			.context("invalid TESSERA_ACCOUNT_BATCH_SIZE")?;
		anyhow::ensure!(
			note_batch_size == account_batch_size * 8,
			"TESSERA_NOTE_BATCH_SIZE ({note_batch_size}) must be exactly 8 × TESSERA_ACCOUNT_BATCH_SIZE ({account_batch_size})"
		);
		let api_bind_addr = std::env::var("TESSERA_PROVER_API_ADDR")
			.unwrap_or_else(|_| "127.0.0.1:8091".to_string());
		let aggregator_artifacts_path = std::env::var("TESSERA_AGGREGATOR_ARTIFACTS_PATH")
			.ok()
			.map(PathBuf::from);

		let aggregation_prover_urls: Vec<String> = std::env::var("TESSERA_AGGREGATION_PROVER_URLS")
			.unwrap_or_default()
			.split(',')
			.map(str::trim)
			.filter(|s| !s.is_empty())
			.map(String::from)
			.collect();

		let aggregation_prover_timeout_secs: u64 =
			std::env::var("TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS")
				.unwrap_or_else(|_| "300".to_string())
				.parse()
				.context("invalid TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS")?;

		Ok(Self {
			note_batch_size,
			account_batch_size,
			api_bind_addr,
			super_aggregator_artifacts_path,
			aggregator_artifacts_path,
			aggregation_prover_urls,
			aggregation_prover_timeout_secs,
		})
	}
}
