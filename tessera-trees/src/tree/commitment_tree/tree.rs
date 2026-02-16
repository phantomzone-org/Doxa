use crate::tree::{
	BatchCommitmentProof, CommitmentInsertProof, MerkleTree, error::MerkleTreeResult,
	hasher::MerkleHash,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(
	bound(
		serialize = "H::Digest: Serialize",
		deserialize = "H::Digest: Deserialize<'de>"
	)
)]
pub struct CommitmentTree<H: MerkleHash> {
	pub(crate) tree: MerkleTree<H>,
}

impl<H: MerkleHash> CommitmentTree<H> {
	pub fn new(depth: usize) -> Self {
		Self {
			tree: MerkleTree::new(depth),
		}
	}

	pub fn depth(&self) -> usize {
		self.tree.depth()
	}

	pub fn get_root(&self) -> H::Digest {
		self.tree.get_root()
	}

	pub fn num_leaves(&self) -> usize {
		self.tree.num_leaves()
	}

	/// Returns the leaf digests currently stored in the append tree.
	pub fn leaves(&self) -> &[H::Digest] {
		self.tree.leaves()
	}

	pub fn insert(&mut self, leaf: H::Digest) -> MerkleTreeResult<CommitmentInsertProof<H>> {
		let index: usize = self.num_leaves();

		let root_old: H::Digest = self.get_root();

		let siblings_old: Vec<H::Digest> =
			self.tree.generate_siblings_array(index, 0, self.depth())?;

		self.tree.insert(leaf)?;

		let siblings_new: Vec<H::Digest> =
			self.tree.generate_siblings_array(index, 0, self.depth())?;

		let root_new: H::Digest = self.get_root();

		Ok(CommitmentInsertProof {
			leaf,
			root_new,
			root_old,
			siblings_old,
			siblings_new,
			path: index,
		})
	}

	pub fn insert_batch(
		&mut self,
		leaves: Vec<H::Digest>,
	) -> MerkleTreeResult<BatchCommitmentProof<H>> {
		let start_index: usize = self.num_leaves();
		let batch_size: usize = leaves.len();

		let root_old: H::Digest = self.get_root();

		let upper_siblings_old: Vec<H::Digest> = self.tree.generate_siblings_array(
			start_index,
			batch_size.trailing_zeros() as usize,
			self.depth(),
		)?;

		self.tree.insert_batch(leaves.clone())?;

		let upper_siblings_new: Vec<H::Digest> = self.tree.generate_siblings_array(
			start_index,
			batch_size.trailing_zeros() as usize,
			self.depth(),
		)?;

		let root_new: H::Digest = self.get_root();

		Ok(BatchCommitmentProof {
			leaves,
			root_old,
			root_new,
			upper_siblings_new,
			upper_siblings_old,
			start_index,
		})
	}
}

#[cfg(test)]
mod tests {

	use anyhow::Result;
	use rand::{SeedableRng, rngs::StdRng};

	use crate::tree::{
		BatchCommitmentProof, CommitmentInsertProof, CommitmentTree,
		hasher::{Hash, NewRandom},
	};

	const DEPTH: usize = 10;
	const NUM_INSERTS: usize = 256;

	#[test]
	fn test_new() {
		let tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);
		assert_eq!(tree.num_leaves(), 0);
	}

	#[test]
	fn test_insert() -> Result<()> {
		let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		// Insert & verify many leaves

		let mut batch = Vec::with_capacity(NUM_INSERTS);
		for _ in 0..NUM_INSERTS as u64 {
			let leaf: Hash = Hash::new_random(&mut rng);
			let proof: CommitmentInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
			batch.push(Hash::new_random(&mut rng));
		}

		let proof: BatchCommitmentProof<Hash> = tree.insert_batch(batch)?;
		assert!(proof.verify());

		Ok(())
	}
}
