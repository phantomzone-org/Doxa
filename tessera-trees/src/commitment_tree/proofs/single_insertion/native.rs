use tessera_utils::hasher::MerkleHash;

/// A Merkle membership proof for single leaf insertion.
///
/// This proof shows that:
/// 1. The leaf at `path` was empty in the old tree (with root_old)
/// 2. The leaf at `path` contains `leaf` in the new tree (with root_new)
///
/// The root commits to the number of leaves: root = H(num_leaves | left | right)
#[derive(Debug, Clone)]
pub struct CommitmentInsertProof<H: MerkleHash> {
	pub leaf: H::Digest,
	pub root_old: H::Digest,
	pub root_new: H::Digest,
	pub siblings_old: Vec<H::Digest>,
	pub siblings_new: Vec<H::Digest>,
	pub path: usize,
}

impl<H: MerkleHash> CommitmentInsertProof<H> {
	pub fn depth(&self) -> usize {
		self.siblings_old.len()
	}

	pub fn verify(&self) -> bool {
		assert_eq!(self.siblings_old.len(), self.siblings_new.len());

		if self.path + 1 > 1 << self.depth() {
			return false;
		}

		// Verify old root: empty leaf at path with siblings_old
		if Self::compute_root(&H::HEAD, &self.siblings_old, self.path, self.path) != self.root_old {
			return false;
		}

		// Verify new root: actual leaf at path with siblings_new
		if Self::compute_root(&self.leaf, &self.siblings_new, self.path, self.path + 1)
			!= self.root_new
		{
			return false;
		}

		true
	}

	#[inline]
	fn compute_root(
		leaf_hash: &H::Digest,
		siblings: &[H::Digest],
		path: usize,
		num_leaves: usize,
	) -> H::Digest {
		let depth = siblings.len();
		let mut current: H::Digest = *leaf_hash;

		for (level, sibling) in siblings.iter().enumerate() {
			let is_right = ((path >> level) & 1) == 1;

			// At the final level, use hash_root to commit num_leaves
			if level == depth - 1 {
				let (left, right) = if is_right {
					(sibling, &current)
				} else {
					(&current, sibling)
				};
				current = H::hash_root(num_leaves, left, right);
			} else {
				current = H::hash_2_to_1(&current, sibling, is_right);
			}
		}

		current
	}
}
