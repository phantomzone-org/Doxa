use anyhow::{ensure, Result};
use sha2::Digest;
use tessera_trees::tree::{
	NullifierChainedInsertProof, NullifierInsertProof, NullifierTree, hasher::Hash
};

use crate::{deposits::used_deposits::USED_DEPOSIT_TREE_DEPTH, Deposit, DepositsBatch};

pub struct UsedDepositTree<H: Digest> {
	pub(crate) tree: NullifierTree<Hash>,
	_phantom: core::marker::PhantomData<H>,
}

impl<H: Digest> UsedDepositTree<H> {
	pub fn new() -> Self {
		Self {
			tree: NullifierTree::new(USED_DEPOSIT_TREE_DEPTH),
			_phantom: core::marker::PhantomData,
		}
	}

	pub fn insert(&mut self, deposit: &Deposit) -> Result<NullifierInsertProof<Hash>> {
		self.tree.insert(deposit.as_field_hash::<H>())
	}

	pub fn insert_batch(
		&mut self,
		deposit: &DepositsBatch,
	) -> Result<NullifierChainedInsertProof<Hash>> {
		ensure!(
			!deposit.deposits.is_empty(),
			"used deposit insertion requires at least one deposit"
		);

		let mut proofs = Vec::with_capacity(deposit.deposits.len());

		for deposit in &deposit.deposits {
			let proof: NullifierInsertProof<Hash> = self.tree.insert(deposit.as_field_hash::<H>())?;
			proofs.push(proof);
		}

		Ok(NullifierChainedInsertProof::new(proofs))
	}

	/// Insert a batch of pre-computed commitment hashes directly.
	///
	/// Used by the sequencer when commitments are read from on-chain events
	/// (already in Goldilocks field format).
	pub fn insert_commitments(
		&mut self,
		commitments: Vec<Hash>,
	) -> Result<NullifierChainedInsertProof<Hash>> {
		ensure!(
			!commitments.is_empty(),
			"used deposit insertion requires at least one commitment"
		);

		let mut proofs = Vec::with_capacity(commitments.len());

		for commitment in commitments {
			let proof: NullifierInsertProof<Hash> = self.tree.insert(commitment)?;
			proofs.push(proof);
		}

		Ok(NullifierChainedInsertProof::new(proofs))
	}
}
