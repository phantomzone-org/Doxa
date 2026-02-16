use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof, NullifierChainedInsertProof};

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveRequest {
	Commitment {
		/// The append-only commitment batch insertion proof (native witness).
		batch_proof: BatchCommitmentProof<Hash>,
	},
	Nullifier {
		/// The chained nullifier insertion proof (native witness).
		batch_proof: NullifierChainedInsertProof<Hash>,
	},
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityProof {
	pub proof: [U256; 8],
	pub commitments: [U256; 2],
	pub commitment_pok: [U256; 2],
}
