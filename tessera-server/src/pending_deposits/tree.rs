use anyhow::Result;
use sha2::Digest;
use tessera_trees::tree::{
	hasher::Hash, BatchCommitmentProof, CommitmentInsertProof, CommitmentTree,
};

use crate::pending_deposits::{PendingDeposit, PendingDepositsBatch};

const DEPTH: usize = 32;

pub struct PendingDepositTree<H: Digest> {
	pub(crate) tree: CommitmentTree<Hash>,
	_phantom: core::marker::PhantomData<H>,
}

impl<H: Digest> PendingDepositTree<H> {
	pub fn new() -> Self {
		Self {
			tree: CommitmentTree::new(DEPTH),
			_phantom: core::marker::PhantomData,
		}
	}

	pub fn insert(
		&mut self,
		pending_deposit: &PendingDeposit,
	) -> Result<CommitmentInsertProof<Hash>> {
		self.tree.insert(pending_deposit.as_field_hash::<H>())
	}

	pub fn insert_batch(
		&mut self,
		pending_deposits: &PendingDepositsBatch,
	) -> Result<BatchCommitmentProof<Hash>> {
		self.tree
			.insert_batch(pending_deposits.leaves_as_field_hashes::<H>())
	}

	/// Insert a batch of pre-computed commitment hashes directly.
	///
	/// Used by the sequencer when commitments are read from on-chain events
	/// (already in Goldilocks field format).
	pub fn insert_commitments(
		&mut self,
		commitments: Vec<Hash>,
	) -> Result<BatchCommitmentProof<Hash>> {
		self.tree.insert_batch(commitments)
	}
}
