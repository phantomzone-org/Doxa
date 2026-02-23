use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof, NullifierChainedInsertProof};

/// Tree-index constants mirroring the Solidity `TREE_*` constants in `TesseraRollup.sol`.
/// Used in `ProveRequest` and `ProveOutcome` to identify which of the four trees a job targets.
/// `batch_id = 0` is reserved as a sentinel for the legacy deposit-only prove path.
pub const TREE_NOTES_COMMITMENT: u8 = 0;
pub const TREE_NOTES_NULLIFIER: u8 = 1;
pub const TREE_ACCOUNTS_COMMITMENT: u8 = 2;
pub const TREE_ACCOUNTS_NULLIFIER: u8 = 3;

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveRequest {
	Commitment {
		/// On-chain batch ID from `registerTransactionBatchUpdate`; 0 for deposit-only path.
		batch_id: u64,
		/// Which of the four trees this job targets (TREE_NOTES_COMMITMENT or
		/// TREE_ACCOUNTS_COMMITMENT).
		tree_index: u8,
		/// The append-only commitment batch insertion proof (native witness).
		batch_proof: BatchCommitmentProof<Hash>,
		/// One note-validity proof per leaf in `batch_proof.leaves` order.
		associated_input_proofs: Vec<Vec<u8>>,
	},
	Nullifier {
		/// On-chain batch ID from `registerTransactionBatchUpdate`; 0 for deposit-only path.
		batch_id: u64,
		/// Which of the four trees this job targets (TREE_NOTES_NULLIFIER or
		/// TREE_ACCOUNTS_NULLIFIER).
		tree_index: u8,
		/// The chained nullifier insertion proof (native witness).
		batch_proof: NullifierChainedInsertProof<Hash>,
		/// One associated input proof per leaf order for this batch.
		associated_input_proofs: Vec<Vec<u8>>,
	},
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveOutcome {
	Success {
		/// Echoed from the originating `ProveRequest`; 0 for deposit-only path.
		batch_id: u64,
		/// Echoed from the originating `ProveRequest`.
		tree_index: u8,
		/// The new consumed root after insertion.
		new_root: Hash,
		/// Groth16 proof formatted for the Solidity contract.
		solidity_proof: Box<SolidityProof>,
		/// Aggregated validity proof for the public inputs in the batch.
		aggregated_input_solidity_proof: Box<SolidityProof>,
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
