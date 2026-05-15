use std::time::Duration;

use alloy::primitives::Address;

/// Configuration for the demo sequencer.
pub struct DemoSequencerConfig {
	/// Ethereum JSON-RPC endpoint.
	pub rpc_url: String,
	/// Operator private key (hex-encoded, with or without `0x`).
	pub operator_key: String,
	/// EVM chain ID.
	pub chain_id: u64,
	/// TesseraContract address.
	pub bridge_address: Address,
	/// ERC-20 token address (ToyUSDT or USDC).
	pub token_address: Address,
	/// HTTP listen address (e.g. `127.0.0.1:3000`).
	pub bind_addr: String,
	/// Max time before flushing a partial batch.
	pub batch_timeout: Duration,
	/// Delay before sending zero proof after batch submission.
	pub prove_delay: Duration,
	/// Background loop poll interval.
	pub poll_interval: Duration,
}

impl DemoSequencerConfig {
	/// Load configuration from environment variables.
	///
	/// Required: `DEMO_RPC_URL`, `DEMO_OPERATOR_KEY`, `DEMO_BRIDGE_ADDRESS`,
	/// `DEMO_TOKEN_ADDRESS`.
	///
	/// Optional: `DEMO_BIND_ADDR` (default `127.0.0.1:3000`),
	/// `DEMO_BATCH_TIMEOUT_SECS` (default `10`), `DEMO_PROVE_DELAY_SECS`
	/// (default `10`), `DEMO_CHAIN_ID` (default `31337`).
	pub fn from_env() -> Self {
		Self {
			rpc_url: std::env::var("DEMO_RPC_URL").expect("DEMO_RPC_URL required"),
			operator_key: std::env::var("DEMO_OPERATOR_KEY").expect("DEMO_OPERATOR_KEY required"),
			chain_id: std::env::var("DEMO_CHAIN_ID")
				.unwrap_or_else(|_| "31337".to_string())
				.parse()
				.expect("invalid DEMO_CHAIN_ID"),
			bridge_address: std::env::var("DEMO_BRIDGE_ADDRESS")
				.expect("DEMO_BRIDGE_ADDRESS required")
				.parse()
				.expect("invalid DEMO_BRIDGE_ADDRESS"),
			token_address: std::env::var("DEMO_TOKEN_ADDRESS")
				.expect("DEMO_TOKEN_ADDRESS required")
				.parse()
				.expect("invalid DEMO_TOKEN_ADDRESS"),
			bind_addr: std::env::var("DEMO_BIND_ADDR")
				.unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
			batch_timeout: Duration::from_secs(
				std::env::var("DEMO_BATCH_TIMEOUT_SECS")
					.unwrap_or_else(|_| "10".to_string())
					.parse()
					.expect("invalid DEMO_BATCH_TIMEOUT_SECS"),
			),
			prove_delay: Duration::from_secs(
				std::env::var("DEMO_PROVE_DELAY_SECS")
					.unwrap_or_else(|_| "10".to_string())
					.parse()
					.expect("invalid DEMO_PROVE_DELAY_SECS"),
			),
			poll_interval: Duration::from_secs(2),
		}
	}
}
