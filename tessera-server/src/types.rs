use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof, BatchInsertProof};

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
///
/// Carries all four tree witnesses + sorted leaf data for TX proof construction.
/// The prover proves all five inner circuits and wraps them into a single
/// SuperAggregator Groth16 proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
	/// On-chain batch ID from `registerTransactionBatchUpdate`.
	pub batch_id: u64,
	/// Notes commitment tree batch-insertion witness.
	pub notes_commitment_proof: BatchCommitmentProof<Hash>,
	/// Notes nullifier tree batch-insertion witness.
	pub notes_nullifier_proof: BatchInsertProof<Hash>,
	/// Accounts commitment tree batch-insertion witness.
	pub accounts_commitment_proof: BatchCommitmentProof<Hash>,
	/// Accounts nullifier tree batch-insertion witness.
	pub accounts_nullifier_proof: BatchInsertProof<Hash>,
	/// Sorted leaf bytes for all 4 trees (after padding and sorting).
	/// Used by the prover to build TX leaf proofs with correct tree data.
	pub nc_sorted_leaves: Vec<[u8; 32]>,
	pub nn_sorted_leaves: Vec<[u8; 32]>,
	pub ac_sorted_leaves: Vec<[u8; 32]>,
	pub an_sorted_leaves: Vec<[u8; 32]>,
	/// Indices (in the sorted account-level batch) of slots that are real
	/// private transactions (is_real=1). Empty for deposit-only batches.
	pub real_account_slots: Vec<usize>,
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveOutcome {
	Success {
		/// Echoed from the originating `ProveRequest`.
		batch_id: u64,
		/// New notes commitment root after insertion.
		notes_new_root: Hash,
		/// New notes nullifier root after insertion.
		nullifier_notes_new_root: Hash,
		/// New accounts commitment root after insertion.
		accounts_new_root: Hash,
		/// New accounts nullifier root after insertion.
		nullifier_accounts_new_root: Hash,
		/// Single SuperAggregator Groth16 proof, ready for `confirmBatch()`.
		solidity_proof: Box<SolidityProof>,
		/// `keccak256` commitment over all 5 inner proofs' public inputs,
		/// encoded as 8 × uint32 big-endian words.  Passed as `publicInputs`
		/// to `confirmBatch()` on-chain.
		super_pi_commitment: [u8; 32],
	},
	Failure {
		/// Echoed from the originating `ProveRequest`.
		batch_id: u64,
		error: String,
	},
}

/// Parsed proof ready for the contract's `confirmBatch` call.
///
/// Corresponds to `DepositsRollupBridge.Proof` in Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityProof {
	pub proof: [U256; 8],
	pub commitments: [U256; 2],
	pub commitment_pok: [U256; 2],
}
