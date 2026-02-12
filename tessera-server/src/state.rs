use anyhow::Result;
use tessera_trees::tree::{hasher::Hash, BatchCommitmentProof};

use crate::pending_deposits::PendingDepositTree;

const BATCH_SIZE: usize = 128;

/// Sequencer in-memory state: Merkle tree + commitment accumulator.
pub struct SequencerState {
	/// The current Merkle tree (depth 32), mirrors on-chain `merkleRoot`.
	pub tree: PendingDepositTree<sha2::Sha256>,
	/// Currently accumulating commitments (grows from 0 to `BATCH_SIZE`).
	pub commitments: Vec<Hash>,
	/// Number of finalized batches.
	pub batch_count: u64,
	/// Deposit ID for the start of the next batch.
	pub next_batch_start_id: u64,
}

impl SequencerState {
	pub fn new() -> Self {
		Self {
			tree: PendingDepositTree::<sha2::Sha256>::new(),
			commitments: Vec::with_capacity(BATCH_SIZE),
			batch_count: 0,
			next_batch_start_id: 0,
		}
	}

	/// Return the genesis root (empty tree root) as a `Hash`.
	///
	/// This is the root of a depth-32 Merkle tree with all-zero leaves,
	/// computed via the Poseidon hash chain. The on-chain contract must be
	/// deployed with this value as `_genesisRoot`.
	pub fn genesis_root() -> Hash {
		let tree = PendingDepositTree::<sha2::Sha256>::new();
		tree.tree.get_root()
	}

	/// Add a commitment (from an on-chain DepositPending event) to the
	/// current batch.
	///
	/// Returns `true` if the batch is now full (`BATCH_SIZE` commitments).
	pub fn add_commitment(&mut self, commitment: Hash) -> bool {
		self.commitments.push(commitment);
		self.commitments.len() >= BATCH_SIZE
	}

	/// Returns `true` if the accumulator has enough commitments to seal a batch.
	pub fn batch_is_ready(&self) -> bool {
		self.commitments.len() >= BATCH_SIZE
	}

	/// Seal the current batch: drain exactly `BATCH_SIZE` commitments from
	/// the accumulator, insert them into the Merkle tree, and return the
	/// start index + commitment proof. Remaining commitments stay in the
	/// accumulator for the next batch.
	pub fn seal_batch(&mut self) -> Result<(u64, BatchCommitmentProof<Hash>)> {
		anyhow::ensure!(
			self.commitments.len() >= BATCH_SIZE,
			"seal_batch called with only {} commitments (need {})",
			self.commitments.len(),
			BATCH_SIZE,
		);
		let batch: Vec<Hash> = self.commitments.drain(..BATCH_SIZE).collect();
		let start_id = self.next_batch_start_id;
		self.next_batch_start_id += batch.len() as u64;
		let proof = self.tree.insert_commitments(batch)?;
		anyhow::ensure!(proof.verify(), "merkle batch proof verification failed after seal");
		Ok((start_id, proof))
	}
}
