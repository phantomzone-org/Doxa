use std::collections::HashMap;

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::HashOutput;

/// Sent from Sequencer V2 to ProverRuntimeV2 for TX batches.
///
/// Carries NC leaf array + private witnesses for the SuperAggregatorV2 circuit.
/// No tree proofs — the on-chain Poseidon IMT replaces them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequestV2 {
	/// On-chain batch identifier.
	pub batch_id: u64,
	/// Note-commitment leaves in arrival (slot) order.
	/// Length = `account_batch_size × notes_per_slot`.
	pub nc_leaves: Vec<[u8; 32]>,
	/// On-chain Poseidon IMT root before this batch (used for both acRoot and ncRoot).
	pub root: HashOutput,
	/// Contract `poolConfigRoot` (bytes32, big-endian).
	pub main_pool_cfg_root: [u8; 32],
	/// Client-supplied PrivTx proof bytes keyed by account slot index.
	/// Absent slots use the pre-loaded dummy proof.
	pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

/// Sent from ProverRuntimeV2 back to Sequencer V2 for TX batches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProveOutcomeV2 {
	Success {
		/// Echoed from the originating request.
		batch_id: u64,
		/// Poseidon Merkle root of the note-commitment batch (= SubtreeRoot).
		batch_poseidon_root: HashOutput,
		/// Groth16 proof ready for `proveTransactionBatch()`.
		solidity_proof: Box<SolidityProof>,
		/// `keccak256(piCommitment preimage)` encoded as 8 × u32 big-endian.
		super_pi_commitment: [u8; 32],
	},
	Failure {
		batch_id: u64,
		error: String,
	},
}

/// Sent from Sequencer V2 to ProverRuntimeV2 for deposit/consume batches.
///
/// Mirrors `ProveRequestV2` but targets the consume (deposit validation) pipeline:
/// the prover uses the `depositVerifier` address and marks deposit notes `Validated`
/// post-proof instead of nullifying them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeProveRequest {
	/// On-chain batch identifier.
	pub batch_id: u64,
	/// Deposit note-commitment leaves in arrival (slot) order.
	/// Length = `account_batch_size × notes_per_slot`.
	pub nc_leaves: Vec<[u8; 32]>,
	/// On-chain Poseidon IMT root before this batch (used for both acRoot and ncRoot).
	pub root: HashOutput,
	/// Contract `poolConfigRoot` (bytes32, big-endian).
	pub main_pool_cfg_root: [u8; 32],
	/// Client-supplied consume proof bytes keyed by account slot index.
	/// Absent slots use the pre-loaded dummy proof.
	pub consume_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

/// Sent from ProverRuntimeV2 back to Sequencer V2 for deposit/consume batches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsumeOutcome {
	Success {
		/// Echoed from the originating request.
		batch_id: u64,
		/// Poseidon Merkle root of the deposit-note batch (= SubtreeRoot).
		batch_poseidon_root: HashOutput,
		/// Groth16 proof ready for `proveDepositBatch()`.
		solidity_proof: Box<SolidityProof>,
		/// `keccak256(piCommitment preimage)` encoded as 8 × u32 big-endian.
		super_pi_commitment: [u8; 32],
	},
	Failure {
		batch_id: u64,
		error: String,
	},
}

// ---------------------------------------------------------------------------
// Shared proof type
// ---------------------------------------------------------------------------

/// Parsed proof ready for the contract's `proveTransactionBatch` / `proveDepositBatch` call.
///
/// Corresponds to `TesseraRollupV2.Proof` in Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityProof {
	pub proof: [U256; 8],
	pub commitments: [U256; 2],
	pub commitment_pok: [U256; 2],
}
