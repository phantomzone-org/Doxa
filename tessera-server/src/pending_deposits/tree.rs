use anyhow::Result;
use tessera_trees::tree::{
	hasher::Hash, BatchCommitmentProof, CommitmentInsertProof, CommitmentTree,
};

use crate::pending_deposits::{PendingDeposit, PendingDepositsBatch};

const DEPTH: usize = 32;

pub struct PendingDepositTree {
	pub(crate) tree: CommitmentTree<Hash>,
}

impl PendingDepositTree {
	pub fn new() -> Self {
		Self {
			tree: CommitmentTree::new(DEPTH),
		}
	}

	pub fn insert(
		&mut self,
		pending_deposit: &PendingDeposit,
	) -> Result<CommitmentInsertProof<Hash>> {
		self.tree.insert(pending_deposit.hash())
	}

	pub fn insert_batch(
		&mut self,
		pending_deposits: &PendingDepositsBatch,
	) -> Result<BatchCommitmentProof<Hash>> {
		self.tree.insert_batch(pending_deposits.leaves())
	}
}
