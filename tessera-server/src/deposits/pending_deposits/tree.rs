use anyhow::Result;
use sha2::Digest;
use tessera_trees::tree::{
	hasher::Hash, BatchCommitmentProof, CommitmentInsertProof, CommitmentTree,
};

use crate::{deposits::pending_deposits::PENDING_DEPOSIT_TREE_DEPTH, Deposit, DepositsBatch};

pub struct PendingDepositTree<H: Digest> {
	pub(crate) tree: CommitmentTree<Hash>,
	_phantom: core::marker::PhantomData<H>,
}

impl<H: Digest> PendingDepositTree<H> {
	pub fn new() -> Self {
		Self {
			tree: CommitmentTree::new(PENDING_DEPOSIT_TREE_DEPTH),
			_phantom: core::marker::PhantomData,
		}
	}

	pub fn insert(&mut self, deposit: &Deposit) -> Result<CommitmentInsertProof<Hash>> {
		self.tree.insert(deposit.as_field_hash::<H>())
	}

	pub fn insert_batch(&mut self, deposit: &DepositsBatch) -> Result<BatchCommitmentProof<Hash>> {
		self.tree
			.insert_batch(deposit.leaves_as_field_hashes::<H>())
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
