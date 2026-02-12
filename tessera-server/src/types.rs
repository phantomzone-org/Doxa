use alloy::primitives::U256;
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof};

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
pub struct ProveRequest {
	/// The Merkle batch proof (root_old, root_new, leaves, siblings).
	pub batch_proof: BatchCommitmentProof<Hash>,
	/// The deposit start index for this batch.
	pub deposit_start_index: u64,
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
pub enum ProveOutcome {
	/// Proof succeeded — ready for on-chain finalization.
	Success {
		/// The deposit start index (echoed back for correlation).
		deposit_start_index: u64,
		/// The new Merkle root after batch insertion.
		new_root: Hash,
		/// Groth16 proof formatted for the Solidity contract.
		solidity_proof: SolidityProof,
	},
	/// Proof failed — sequencer must reset `batch_in_flight`.
	Failure {
		/// The deposit start index identifying the failed batch.
		deposit_start_index: u64,
		/// Human-readable error message.
		error: String,
	},
}

/// Parsed proof ready for the contract's `finalizeBatch` call.
///
/// Corresponds to `DepositsRollupBridge.Proof` in Solidity.
pub struct SolidityProof {
	pub proof: [U256; 8],
	pub commitments: [U256; 2],
	pub commitment_pok: [U256; 2],
}
