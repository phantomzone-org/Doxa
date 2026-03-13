use std::collections::HashMap;

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::{hasher::HashOutput, BatchCommitmentProof, BatchInsertProof};

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
	pub notes_commitment_proof: BatchCommitmentProof<HashOutput>,
	/// Notes nullifier tree batch-insertion witness.
	pub notes_nullifier_proof: BatchInsertProof<HashOutput>,
	/// Accounts commitment tree batch-insertion witness.
	pub accounts_commitment_proof: BatchCommitmentProof<HashOutput>,
	/// Accounts nullifier tree batch-insertion witness.
	pub accounts_nullifier_proof: BatchInsertProof<HashOutput>,
	/// Leaf bytes for all 4 trees (after padding).
	/// Sorted variants are used for nullifier tree proofs and off-circuit checks.
	/// Unsorted variants (arrival order) are used for dummy TX override values.
	pub nc_sorted_leaves: Vec<[u8; 32]>,
	pub nn_sorted_leaves: Vec<[u8; 32]>,
	pub ac_sorted_leaves: Vec<[u8; 32]>,
	pub an_sorted_leaves: Vec<[u8; 32]>,
	/// Sorting permutation for AN: `an_sort_perm[slot] = sorted_position`.
	/// Allows the prover to recover the original slot→value mapping:
	/// `override_an = an_sorted_leaves[an_sort_perm[s]]`.
	pub an_sort_perm: Vec<usize>,
	/// Sorting permutation for NN: `nn_sort_perm[slot] = sorted_position`.
	pub nn_sort_perm: Vec<usize>,
	/// Client-submitted TX proof bytes keyed by account slot index.
	/// Slots present in this map are real private TXs (is_real=1);
	/// absent slots use dummy proofs.
	pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

/// Sent from Prover back to Sequencer via `tokio::mpsc` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveOutcome {
	Success {
		/// Echoed from the originating `ProveRequest`.
		batch_id: u64,
		/// New notes commitment root after insertion.
		notes_new_root: HashOutput,
		/// New notes nullifier root after insertion.
		nullifier_notes_new_root: HashOutput,
		/// New accounts commitment root after insertion.
		accounts_new_root: HashOutput,
		/// New accounts nullifier root after insertion.
		nullifier_accounts_new_root: HashOutput,
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
