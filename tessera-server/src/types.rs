use alloy::primitives::U256;
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof};

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
pub struct ProveRequest {
	/// The append-only commitment batch insertion proof (native witness).
	pub batch_proof: BatchCommitmentProof<Hash>,
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
pub enum ProveOutcome {
	Success {
		/// The new consumed root after insertion.
		new_root: Hash,
		/// Groth16 proof formatted for the Solidity contract.
		solidity_proof: SolidityProof,
	},
	Failure {
		error: String,
	},
}

/// Parsed proof ready for the contract's `finalizeConsumeBatch` call.
///
/// Corresponds to `DepositsRollupBridge.Proof` in Solidity.
pub struct SolidityProof {
	pub proof: [U256; 8],
	pub commitments: [U256; 2],
	pub commitment_pok: [U256; 2],
}
