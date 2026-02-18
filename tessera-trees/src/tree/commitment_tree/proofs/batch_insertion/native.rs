use plonky2::{
	field::{extension::Extendable, types::Field},
	hash::hash_types::RichField,
};
use serde::{Deserialize, Serialize};

use crate::tree::hasher::{CommitmentPreimage, DataCommitment, MerkleHash, ToHashOut};

/// A Merkle proof for batch leaf insertion.
///
/// This proof shows that:
/// 1. The leaves at [start_index..start_index+batch_size] were empty in the old tree
/// 2. The leaves at [start_index..start_index+batch_size] contain the provided values in the new
///    tree
///
/// The root commits to the number of leaves: root = H(num_leaves | left | right)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct BatchCommitmentProof<H: MerkleHash> {
	pub leaves: Vec<H::Digest>,
	pub root_old: H::Digest,
	pub root_new: H::Digest,
	pub start_index: usize,
	pub upper_siblings_old: Vec<H::Digest>,
	pub upper_siblings_new: Vec<H::Digest>,
}

impl<H: MerkleHash> BatchCommitmentProof<H> {
	/// Returns the batch size (number of leaves in this proof).
	pub fn batch_size(&self) -> usize {
		self.leaves.len()
	}

	/// Returns the subtree height k where batch_size = 2^k.
	pub fn subtree_height(&self) -> usize {
		self.leaves.len().trailing_zeros() as usize
	}

	/// Returns the tree depth.
	pub fn depth(&self) -> usize {
		self.upper_siblings_old.len() + self.subtree_height()
	}

	/// Computes the commitment digest from this proof using the given
	/// [`DataCommitment`] implementation.
	///
	/// Returns the field elements that should match the STARK proof's
	/// `public_inputs` when the circuit was built with the same commitment.
	///
	/// ```ignore
	/// let expected_pi = native_proof.compute_commitment::<F, D>(&PoseidonCommitment);
	/// // or equivalently:
	/// let expected_pi = PoseidonCommitment.commit_native(&native_proof);
	/// assert_eq!(expected_pi, stark_proof.public_inputs);
	/// ```
	pub fn compute_commitment<F, const D: usize>(
		&self,
		commitment: &dyn DataCommitment<F, D>,
	) -> Vec<F>
	where
		F: RichField + Extendable<D>,
		H::Digest: ToHashOut<F>,
	{
		commitment.commit_native(self)
	}

	/// Verify the batch commitment proof:
	/// 1. Assert that leaves at [start_index..start_index+batch_size] were empty against root_old
	/// 2. Assert that the inserted leaves hash correctly against root_new
	pub fn verify(&self) -> bool {
		let batch_size: usize = self.batch_size();
		assert!(batch_size.is_power_of_two());
		assert!(self.start_index.is_multiple_of(batch_size));
		assert!(self.upper_siblings_old.len() == self.upper_siblings_new.len());

		let k: usize = self.subtree_height();

		// ---- 1) Compute empty subtree root of height k ----
		let empty_subtree_root: H::Digest = Self::compute_empty_subtree_root(k);

		// ---- 2) Verify empty subtree attaches to root_old ----
		let computed_old_root: H::Digest = Self::attach_subtree_root(
			empty_subtree_root,
			&self.upper_siblings_old,
			self.start_index,
			k,
			self.start_index,
		);

		if computed_old_root != self.root_old {
			return false;
		}

		// ---- 3) Compute batch subtree root from leaves ----
		let batch_subtree_root: H::Digest = Self::compute_subtree_root(&self.leaves);

		// ---- 4) Verify batch subtree attaches to root_new ----
		let computed_new_root: H::Digest = Self::attach_subtree_root(
			batch_subtree_root,
			&self.upper_siblings_new,
			self.start_index,
			k,
			self.start_index + batch_size,
		);

		computed_new_root == self.root_new
	}

	/// Compute the root of an empty subtree of height k.
	/// An empty subtree has all leaves equal to H::HEAD.
	fn compute_empty_subtree_root(height: usize) -> H::Digest {
		let mut hash: H::Digest = H::HEAD;
		for _ in 0..height {
			hash = H::hash_2_to_1(&hash, &hash, false);
		}
		hash
	}

	/// Compute the subtree root from a vector of leaves.
	/// The number of leaves must be a power of two.
	fn compute_subtree_root(leaves: &[H::Digest]) -> H::Digest {
		debug_assert!(leaves.len().is_power_of_two());

		if leaves.len() == 1 {
			return leaves[0];
		}

		// In-place computation to avoid extra allocations
		let mut cur: Vec<H::Digest> = leaves.to_vec();

		while cur.len() > 1 {
			let parent_len = cur.len() >> 1;
			for i in 0..parent_len {
				let left: &H::Digest = &cur[2 * i];
				let right: &H::Digest = &cur[2 * i + 1];
				cur[i] = H::hash_2_to_1(left, right, false);
			}
			cur.truncate(parent_len);
		}

		cur[0]
	}

	/// Attach a subtree root to the global tree using upper siblings.
	/// At the final level, uses hash_root to commit num_leaves.
	fn attach_subtree_root(
		subtree_root: H::Digest,
		upper_siblings: &[H::Digest],
		start_index: usize,
		subtree_height: usize,
		num_leaves: usize,
	) -> H::Digest {
		let num_upper_siblings = upper_siblings.len();
		let mut current_hash: H::Digest = subtree_root;
		let mut pos = start_index >> subtree_height;

		for (level, sibling) in upper_siblings.iter().enumerate() {
			let is_right = (pos & 1) == 1;

			// At the final level (root), use hash_root to commit num_leaves
			if level == num_upper_siblings - 1 {
				let (left, right) = if is_right {
					(sibling, &current_hash)
				} else {
					(&current_hash, sibling)
				};
				current_hash = H::hash_root(num_leaves, left, right);
			} else {
				current_hash = H::hash_2_to_1(&current_hash, sibling, is_right);
			}
			pos >>= 1;
		}

		current_hash
	}
}

/// Preimage layout: `root_old || root_new || leaves[0] || ... || leaves[n-1]`
///
/// Matches the circuit's
/// [`BatchCommitmentProofTargets::new`](crate::tree::BatchCommitmentProofTargets::new).
impl<F: Field, H: MerkleHash> CommitmentPreimage<F> for BatchCommitmentProof<H>
where
	H::Digest: ToHashOut<F>,
{
	fn write_preimage(&self, buf: &mut Vec<F>) {
		buf.reserve((self.leaves.len() + 2) * 4);
		buf.extend_from_slice(&self.root_old.to_hash_out().elements);
		buf.extend_from_slice(&self.root_new.to_hash_out().elements);
		for leaf in &self.leaves {
			buf.extend_from_slice(&leaf.to_hash_out().elements);
		}
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;
	use rand::{SeedableRng, rngs::StdRng};

	use crate::tree::{
		BatchCommitmentProof, CommitmentTree,
		hasher::{Hash, NewRandom},
	};

	#[test]
	fn test_batch_merkle_proof() -> Result<()> {
		const DEPTH: usize = 16;
		const BATCH: usize = 16;

		let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		// Create batch of random leaves
		let mut leaves: Vec<Hash> = Vec::new();
		for _ in 0..BATCH {
			leaves.push(Hash::new_random(&mut rng));
		}

		// Insert batch and get proof
		let proof: BatchCommitmentProof<Hash> = tree.insert_batch(leaves)?;

		// Verify the proof
		assert!(proof.verify());

		Ok(())
	}

	#[test]
	fn test_batch_merkle_proof_after_inserts() -> Result<()> {
		const DEPTH: usize = 16;
		const INITIAL_LEAVES: usize = 32;
		const BATCH: usize = 16;

		let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);

		let mut rng = StdRng::from_seed([0u8; 32]);

		// Insert some initial leaves
		for _ in 0..INITIAL_LEAVES {
			let value = Hash::new_random(&mut rng);
			tree.insert(value).unwrap();
		}

		// Create batch of random leaves
		let mut leaves: Vec<Hash> = Vec::new();
		for _ in 0..BATCH {
			leaves.push(Hash::new_random(&mut rng));
		}

		// Insert batch and get proof
		let proof: BatchCommitmentProof<Hash> = tree.insert_batch(leaves)?;

		// Verify the proof
		assert!(proof.verify());

		Ok(())
	}

	#[test]
	fn test_batch_merkle_proof_various_sizes() -> Result<()> {
		const DEPTH: usize = 16;

		let mut rng = StdRng::from_seed([42u8; 32]);

		// Test various batch sizes (all powers of 2)
		for batch_size in [1, 2, 4, 8, 16, 32, 64] {
			let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);

			// Create batch of random leaves
			let mut leaves: Vec<Hash> = Vec::new();
			for _ in 0..batch_size {
				leaves.push(Hash::new_random(&mut rng));
			}

			// Insert batch and get proof
			let proof: BatchCommitmentProof<Hash> = tree.insert_batch(leaves)?;

			// Verify the proof
			assert!(proof.verify(), "Failed for batch_size={}", batch_size);
		}

		Ok(())
	}
}
