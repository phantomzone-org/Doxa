use alloy::primitives::Address;

/// Configuration for the [`ProverService`](super::ProverService).
#[derive(Debug, Clone)]
pub struct ProverServiceConfig {
	/// HTTP(S) URL of the Ethereum-compatible RPC node.
	pub rpc_url: String,
	/// Address of the deployed `DoxaRollupV2` contract.
	pub bridge_address: Address,
	/// Hex-encoded private key for the operator wallet (used to sign on-chain
	/// `submitTransactionBatch` and `proveTransactionBatch` calls).
	pub operator_private_key: String,
	/// EIP-155 chain ID (e.g. 31337 for a local Anvil devnet).
	pub chain_id: u64,
	/// Seconds to wait before flushing a non-full batch to the chain.
	pub batch_timeout_secs: u64,
}
