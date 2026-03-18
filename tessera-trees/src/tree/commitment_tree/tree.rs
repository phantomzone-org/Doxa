use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::tree::{
	BatchCommitmentProof, CommitmentInsertProof, MerkleTree, error::MerkleTreeResult,
	hasher::MerkleHash,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct CommitmentTree<H: MerkleHash> {
	pub(crate) tree: MerkleTree<H>,
	#[serde(default)]
	pub(crate) leaf_counts: BTreeMap<H::Digest, u64>,
}

impl<H: MerkleHash> CommitmentTree<H> {
	pub fn new(depth: usize) -> Self {
		Self {
			tree: MerkleTree::new(depth),
			leaf_counts: BTreeMap::new(),
		}
	}

	pub fn depth(&self) -> usize {
		self.tree.depth()
	}

	pub fn get_root(&self) -> H::Digest {
		self.tree.compute_root()
	}

	pub fn num_leaves(&self) -> usize {
		self.tree.num_leaves()
	}

	/// Returns the leaf digests currently stored in the append tree.
	pub fn leaves(&self) -> &[H::Digest] {
		self.tree.leaves()
	}

	/// Returns how many times `leaf` appears in this append tree.
	///
	/// Duplicates are allowed in commitment trees, so callers should use
	/// multiplicity checks rather than simple set-membership assumptions.
	pub fn leaf_count(&self, leaf: &H::Digest) -> u64 {
		*self.leaf_counts.get(leaf).unwrap_or(&0)
	}

	/// Returns whether `leaf` is present at least once.
	pub fn contains_leaf(&self, leaf: &H::Digest) -> bool {
		self.leaf_count(leaf) > 0
	}

	/// Rebuilds the multiplicity index from `tree.leaves()`.
	///
	/// Needed when loading snapshots produced before `leaf_counts` existed.
	pub fn rebuild_leaf_counts(&mut self) {
		self.leaf_counts.clear();
		for leaf in self.tree.leaves() {
			*self.leaf_counts.entry(*leaf).or_insert(0) += 1;
		}
	}

	pub fn merkle_path(
		&self,
		index: usize,
		start_depth: usize,
		end_depth: usize,
	) -> MerkleTreeResult<Vec<H::Digest>> {
		self.tree.merkle_path(index, start_depth, end_depth)
	}

	pub fn insert(&mut self, leaf: H::Digest) -> MerkleTreeResult<CommitmentInsertProof<H>> {
		let index: usize = self.num_leaves();

		let root_old: H::Digest = self.get_root();

		let siblings_old: Vec<H::Digest> = self.tree.merkle_path(index, 0, self.depth())?;

		self.tree.insert(leaf)?;
		*self.leaf_counts.entry(leaf).or_insert(0) += 1;

		let siblings_new: Vec<H::Digest> = self.tree.merkle_path(index, 0, self.depth())?;

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

		let upper_siblings_old: Vec<H::Digest> = self.tree.merkle_path(
			start_index,
			batch_size.trailing_zeros() as usize,
			self.depth(),
		)?;

		self.tree.insert_batch(leaves.clone())?;
		for leaf in &leaves {
			*self.leaf_counts.entry(*leaf).or_insert(0) += 1;
		}

		let upper_siblings_new: Vec<H::Digest> = self.tree.merkle_path(
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
		hasher::{HashOutput, NewRandom},
	};

	const DEPTH: usize = 10;
	const NUM_INSERTS: usize = 256;

	#[test]
	fn test_new() {
		let tree: CommitmentTree<HashOutput> = CommitmentTree::<HashOutput>::new(DEPTH);
		assert_eq!(tree.num_leaves(), 0);
	}

	#[test]
	fn test_insert() -> Result<()> {
		let mut tree: CommitmentTree<HashOutput> = CommitmentTree::<HashOutput>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		// Insert & verify many leaves

		let mut batch = Vec::with_capacity(NUM_INSERTS);
		for _ in 0..NUM_INSERTS as u64 {
			let leaf: HashOutput = HashOutput::new_random(&mut rng);
			let proof: CommitmentInsertProof<HashOutput> = tree.insert(leaf)?;
			assert!(proof.verify());
			batch.push(HashOutput::new_random(&mut rng));
		}

		let proof: BatchCommitmentProof<HashOutput> = tree.insert_batch(batch)?;
		assert!(proof.verify());

		Ok(())
	}

	#[test]
	fn test_duplicate_leaf_counts() -> Result<()> {
		let mut tree: CommitmentTree<HashOutput> = CommitmentTree::<HashOutput>::new(DEPTH);
		let mut rng: StdRng = StdRng::from_seed([1u8; 32]);

		let a = HashOutput::new_random(&mut rng);
		let b = HashOutput::new_random(&mut rng);

		let p1 = tree.insert_batch(vec![a, b, a, a])?;
		assert!(p1.verify());
		assert_eq!(tree.leaf_count(&a), 3);
		assert_eq!(tree.leaf_count(&b), 1);
		assert!(tree.contains_leaf(&a));
		assert!(tree.contains_leaf(&b));

		let p2 = tree.insert(a)?;
		assert!(p2.verify());
		assert_eq!(tree.leaf_count(&a), 4);

		Ok(())
	}

	#[test]
	fn test_rebuild_leaf_counts_from_leaves() -> Result<()> {
		let mut tree: CommitmentTree<HashOutput> = CommitmentTree::<HashOutput>::new(DEPTH);
		let mut rng: StdRng = StdRng::from_seed([2u8; 32]);

		let a = HashOutput::new_random(&mut rng);
		let b = HashOutput::new_random(&mut rng);

		let p = tree.insert_batch(vec![a, b, a, b])?;
		assert!(p.verify());
		assert_eq!(tree.leaf_count(&a), 2);
		assert_eq!(tree.leaf_count(&b), 2);

		// Simulate loading legacy state where no multiplicity index was persisted.
		tree.leaf_counts.clear();
		assert_eq!(tree.leaf_count(&a), 0);
		assert_eq!(tree.leaf_count(&b), 0);

		tree.rebuild_leaf_counts();
		assert_eq!(tree.leaf_count(&a), 2);
		assert_eq!(tree.leaf_count(&b), 2);
		assert!(tree.contains_leaf(&a));
		assert!(tree.contains_leaf(&b));

		Ok(())
	}
}
