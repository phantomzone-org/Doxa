use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof, BatchInsertProof};

/// Sent from Sequencer to Prover via `tokio::mpsc` channel.
///
/// Carries all four tree witnesses + the 16 TX leaf proofs for a single batch.
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
	/// Serialised TX leaf proofs (exactly 16 slots; unused slots = DUMMY_ASSOCIATED_INPUT_PROOF).
	pub associated_tx_proofs: Vec<Vec<u8>>,
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
