use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::tree::{
	Node, NullifierTree,
	error::{MerkleTreeError, MerkleTreeResult},
	hasher::MerkleHash,
};

/// One row of the batch insertion trace.
///
/// Each link captures the full state of a single leaf insertion
/// within the batch: its value, next-pointer, predecessor, and
/// Merkle authentication path. The STARK circuit processes one
/// link per trace row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct BatchInsertionLink<H: MerkleHash> {
	/// Whether this predecessor is a chain lead (true) or chained (false).
	pub mask: bool,

	/// New leaf being inserted.
	pub leaf_index: usize,
	pub leaf_value: H::Digest,
	pub leaf_next_index: usize,
	pub leaf_next_value: H::Digest,

	/// Predecessor node in the existing tree.
	pub pred_path: usize,
	pub pred_value: H::Digest,
	pub pred_old_next_index: usize,
	pub pred_old_next_value: H::Digest,
	pub pred_new_next_index: usize,
	pub pred_new_next_value: H::Digest,
	pub pred_old_siblings: Vec<H::Digest>,
	pub pred_new_siblings: Vec<H::Digest>,
}

impl<H: MerkleHash> BatchInsertionLink<H> {
	/// Computes the leaf node hash: H(leaf_value, leaf_next_index, leaf_next_value).
	pub fn leaf_hash(&self) -> H::Digest {
		H::commit_node(
			&self.leaf_value,
			self.leaf_next_index,
			&self.leaf_next_value,
		)
	}

	/// Computes the old predecessor hash (before update).
	pub fn pred_old_hash(&self) -> H::Digest {
		H::commit_node(
			&self.pred_value,
			self.pred_old_next_index,
			&self.pred_old_next_value,
		)
	}

	/// Computes the new predecessor hash (after update).
	pub fn pred_new_hash(&self) -> H::Digest {
		H::commit_node(
			&self.pred_value,
			self.pred_new_next_index,
			&self.pred_new_next_value,
		)
	}

	/// Verifies constraints for the first link [0] and its transition to [1].
	///
	/// Checks:
	/// - Constraint 18: mask[0] == true
	/// - Per-leaf constraints (1–5)
	/// - Transition constraints to `next` (6–17)
	pub fn verify_first(&self, next: &Self) -> bool {
		if !self.mask {
			return false;
		}
		self.verify_per_leaf() && self.verify_transition(next)
	}

	/// Verifies constraints for a mid link [i] and its transition to [i+1].
	///
	/// Checks:
	/// - Per-leaf constraints (1–5)
	/// - Transition constraints to `next` (6–17)
	pub fn verify_mid(&self, next: &Self) -> bool {
		self.verify_per_leaf() && self.verify_transition(next)
	}

	/// Verifies constraints for the last link [n-1].
	///
	/// Checks:
	/// - Per-leaf constraints (1–5)
	/// - Constraint 19: leaf_next_index == pred_old_next_index
	/// - Constraint 20: leaf_next_value == pred_old_next_value
	pub fn verify_last(&self) -> bool {
		if !self.verify_per_leaf() {
			return false;
		}
		self.leaf_next_index == self.pred_old_next_index
			&& self.leaf_next_value == self.pred_old_next_value
	}

	/// Per-leaf constraints (checked for every link).
	///
	///  1. mask[i] => pred_new_next_index[i] == leaf_index[i]
	///  2. mask[i] => pred_new_next_value[i] == leaf_value[i]
	///  3. leaf_next_value[i] > leaf_value[i]
	///  4. pred_old_next_value[i] > leaf_value[i]
	///  5. pred_value[i] < leaf_value[i]
	fn verify_per_leaf(&self) -> bool {
		// Constraint 5
		if !(self.pred_value < self.leaf_value) {
			return false;
		}
		// Constraint 4
		if !(self.pred_old_next_value > self.leaf_value) {
			return false;
		}
		// Constraint 3
		if !(self.leaf_next_value > self.leaf_value) {
			return false;
		}
		// Constraints 1–2
		if self.mask
			&& (self.pred_new_next_index != self.leaf_index
				|| self.pred_new_next_value != self.leaf_value)
		{
			return false;
		}
		true
	}

	/// Transition constraints between self (link[i]) and next (link[i+1]).
	///
	/// --- When next.mask (distinct predecessor) ---
	///  6. leaf_next_index[i] == pred_old_next_index[i]
	///  7. leaf_next_value[i] == pred_old_next_value[i]
	///  8. pred_value[i+1] > leaf_value[i]
	///
	/// --- When !next.mask (chained) ---
	///  9. pred_path[i] == pred_path[i+1]
	/// 10. pred_value[i] == pred_value[i+1]
	/// 11. pred_new_next_value[i] == pred_new_next_value[i+1]
	/// 12. pred_new_next_index[i] == pred_new_next_index[i+1]
	/// 13. pred_old_next_value[i] == pred_old_next_value[i+1]
	/// 14. pred_old_next_index[i] == pred_old_next_index[i+1]
	/// 15. leaf_next_index[i] == leaf_index[i+1]
	/// 16. leaf_next_value[i] == leaf_value[i+1]
	///
	/// --- Always ---
	/// 17. leaf_index[i] + 1 == leaf_index[i+1] (sorted order: leaf_value[i] < leaf_value[i+1])
	fn verify_transition(&self, next: &Self) -> bool {
		// Sorted order
		if !(self.leaf_value < next.leaf_value) {
			return false;
		}

		if next.mask {
			// Constraint 8: distinct predecessor gap doesn't overlap
			if !(next.pred_value > self.leaf_value) {
				return false;
			}
			// Constraints 6–7
			if self.leaf_next_index != self.pred_old_next_index
				|| self.leaf_next_value != self.pred_old_next_value
			{
				return false;
			}
		} else {
			// Constraints 9–14: chained predecessor fields must match
			if self.pred_path != next.pred_path
				|| self.pred_value != next.pred_value
				|| self.pred_old_next_index != next.pred_old_next_index
				|| self.pred_old_next_value != next.pred_old_next_value
				|| self.pred_new_next_index != next.pred_new_next_index
				|| self.pred_new_next_value != next.pred_new_next_value
			{
				return false;
			}
			// Constraints 15–16
			if self.leaf_next_index != next.leaf_index || self.leaf_next_value != next.leaf_value {
				return false;
			}
		}

		// Constraint 17
		if self.leaf_index + 1 != next.leaf_index {
			return false;
		}

		true
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct BatchInsertProof<H: MerkleHash> {
	// ============ PUBLIC INPUTS ============
	/// Initial tree root (before insertion)
	pub old_root: H::Digest,
	/// Final tree root (after insertion)
	pub new_root: H::Digest,

	/// Batch insertion index
	pub start_index: usize,

	/// Per-leaf insertion links (one per batch entry, in sorted order).
	pub links: Vec<BatchInsertionLink<H>>,

	/// Upper siblings for the batch subtree → new_root walk (after predecessor updates).
	pub new_node_upper_siblings_after_pred_update: Vec<H::Digest>,
}

impl<H: MerkleHash> NullifierTree<H> {
	pub fn insert_batch(
		&mut self,
		mut leaves: Vec<H::Digest>,
	) -> MerkleTreeResult<BatchInsertProof<H>> {
		let start_index: usize = self.nodes.len();

		let batch_size: usize = leaves.len();

		if !batch_size.is_power_of_two() {
			return Err(anyhow!(MerkleTreeError::InvalidBatch(
				"batch_size must be a power of two".to_string()
			)));
		}

		if !start_index.is_multiple_of(batch_size) {
			return Err(anyhow!(MerkleTreeError::InvalidBatch(
				"start_index must be aligned to batch_size".to_string()
			)));
		}

		let log_batch_size: usize = (batch_size - 1).trailing_ones() as usize;

		let old_root: H::Digest = self.get_root();

		// Sort leaves and populate predecessors
		let (pred_paths, pred_values, pred_old_next_indexes, pred_old_next_values, mask) =
			self.sort_leaves(&mut leaves)?;

		// 1. Updates predecessors (batch): old_root -> mid_root All siblings are captured against
		//    old_root (tree is not mutated until after the loop). Non-masked predecessors copy the
		//    chain lead's siblings.
		let mut pred_in_tree_paths = Vec::new();
		let mut pred_old_siblings: Vec<Vec<H::Digest>> = Vec::with_capacity(batch_size);
		let mut pred_new_next_indexes: Vec<usize> = Vec::with_capacity(batch_size);
		let mut pred_new_next_values: Vec<H::Digest> = Vec::with_capacity(batch_size);
		for i in 0..batch_size {
			if mask[i] {
				pred_new_next_indexes.push(start_index + i);
				pred_new_next_values.push(leaves[i]);

				// Capture siblings against old_root (tree not yet mutated)
				let siblings: Vec<H::Digest> =
					self.tree.merkle_path(pred_paths[i], 0, self.depth())?;
				pred_old_siblings.push(siblings);

				self.nodes[pred_paths[i]] = Node::new(
					pred_values[i],
					pred_new_next_indexes[i],
					pred_new_next_values[i],
				);
				pred_in_tree_paths.push(pred_paths[i]);
			} else {
				pred_new_next_indexes.push(*pred_new_next_indexes.last().unwrap());
				pred_new_next_values.push(*pred_new_next_values.last().unwrap());

				// Copy chain lead's siblings
				pred_old_siblings.push(pred_old_siblings.last().unwrap().clone());
			}
		}

		// Batch-apply all predecessor updates to the tree
		for &path in &pred_in_tree_paths {
			self.tree.leaves[path] = self.nodes[path].compute_hash();
		}
		self.tree.update_sparse_paths(&pred_in_tree_paths);

		// 1b. Capture pred_new_siblings against mid_root (after all predecessor updates).
		//     Non-masked entries copy the chain lead's siblings.
		let mut pred_new_siblings: Vec<Vec<H::Digest>> = Vec::with_capacity(batch_size);
		for i in 0..batch_size {
			if mask[i] {
				pred_new_siblings.push(self.tree.merkle_path(pred_paths[i], 0, self.depth())?);
			} else {
				pred_new_siblings.push(pred_new_siblings.last().unwrap().clone());
			}
		}

		// 2. Capture upper siblings after pred update (for batch subtree → new_root walk)
		let new_node_upper_siblings_after_pred_update: Vec<H::Digest> =
			self.tree
				.merkle_path(start_index, log_batch_size, self.depth())?;

		// 3. Updates tree nodes and builds links
		let mut links: Vec<BatchInsertionLink<H>> = Vec::with_capacity(batch_size);
		for i in 0..batch_size {
			// Derive this leaf's next pointer
			let (leaf_next_index, leaf_next_value) = if i == batch_size - 1 || mask[i + 1] {
				(pred_old_next_indexes[i], pred_old_next_values[i])
			} else {
				(start_index + i + 1, leaves[i + 1])
			};

			self.nodes
				.push(Node::new(leaves[i], leaf_next_index, leaf_next_value));

			self.tree
				.leaves
				.push(self.nodes.last().unwrap().compute_hash());
			self.actives.insert(leaves[i], start_index + i);

			links.push(BatchInsertionLink {
				mask: mask[i],
				leaf_index: start_index + i,
				leaf_value: leaves[i],
				leaf_next_index,
				leaf_next_value,
				pred_path: pred_paths[i],
				pred_value: pred_values[i],
				pred_old_next_index: pred_old_next_indexes[i],
				pred_old_next_value: pred_old_next_values[i],
				pred_new_next_index: pred_new_next_indexes[i],
				pred_new_next_value: pred_new_next_values[i],
				pred_old_siblings: pred_old_siblings[i].clone(),
				pred_new_siblings: pred_new_siblings[i].clone(),
			});
		}

		// 4. Commits the entire batch A + B -> new_root
		self.tree
			.update_consecutive_paths(start_index, batch_size)?;

		let new_root: H::Digest = self.get_root();

		Ok(BatchInsertProof {
			old_root,
			new_root,
			start_index,
			links,
			new_node_upper_siblings_after_pred_update,
		})
	}

	/// Sorts the leaves in ascending order and return a mask
	/// indicating if the leaf true predecessor is already committed or not.
	fn sort_leaves(
		&self,
		leaves: &mut Vec<H::Digest>,
	) -> MerkleTreeResult<(
		Vec<usize>,
		Vec<H::Digest>,
		Vec<usize>,
		Vec<H::Digest>,
		Vec<bool>,
	)> {
		let batch_size = leaves.len();

		// 1. Sort leaves
		leaves.sort();

		// 2. Checks all leaves are unique
		for i in 1..batch_size {
			if leaves[i - 1] >= leaves[i] {
				return Err(anyhow!(MerkleTreeError::InvalidBatch(
					"duplicated leaves".to_string()
				)));
			}
		}

		let mut mask: Vec<bool> = vec![false; batch_size];
		let mut pred_paths: Vec<usize> = Vec::with_capacity(batch_size);
		let mut pred_values: Vec<H::Digest> = Vec::with_capacity(batch_size);
		let mut pred_next_indexes: Vec<usize> = Vec::with_capacity(batch_size);
		let mut pred_next_values: Vec<H::Digest> = Vec::with_capacity(batch_size);

		for i in 0..batch_size {
			let leaf = leaves[i];

			let pred_index: usize = self.find_predecessor_index_from_value(leaf).ok_or(anyhow!(
				MerkleTreeError::NonMembershipProofError(
					"failed to find predecessor index".to_string()
				)
			))?;

			let pred_node: Node<H> = self.nodes[pred_index];

			if !(pred_node.value < leaf && leaf < pred_node.next_value) {
				return Err(anyhow!(MerkleTreeError::NonMembershipProofError(
					"range check failed".to_string()
				)));
			}

			let chained = i > 0 && leaves[i - 1] > pred_node.value;
			mask[i] = !chained;
			pred_paths.push(pred_index);
			pred_values.push(pred_node.value);
			pred_next_indexes.push(pred_node.next_index);
			pred_next_values.push(pred_node.next_value);
		}

		Ok((
			pred_paths,
			pred_values,
			pred_next_indexes,
			pred_next_values,
			mask,
		))
	}
}

impl<H: MerkleHash> BatchInsertProof<H> {
	pub fn verify(&self) -> bool {
		let old_root = self.old_root;
		let batch_size = self.links.len();

		if batch_size == 0 || !batch_size.is_power_of_two() {
			return false;
		}

		let log_batch_size = batch_size.trailing_zeros() as usize;

		if !self.start_index.is_multiple_of(batch_size) {
			return false;
		}

		// ============================================================
		// Phase A: old_root -> mid_root (predecessor updates)
		//
		// Authenticate every predecessor against old_root (pred_old)
		// and against mid_root (pred_new). Non-masked entries
		// redundantly verify the same node as their chain lead.
		// ============================================================
		let mid_root = {
			// Derive mid_root from the first link's pred_new authentication
			let first_new_hash = self.links[0].pred_new_hash();
			Self::compute_root(
				&first_new_hash,
				&self.links[0].pred_new_siblings,
				self.links[0].pred_path,
				self.start_index,
			)
		};

		for link in &self.links {
			// Authenticate pred_old against old_root
			if Self::compute_root(
				&link.pred_old_hash(),
				&link.pred_old_siblings,
				link.pred_path,
				self.start_index,
			) != old_root
			{
				return false;
			}

			// Authenticate pred_new against mid_root
			if Self::compute_root(
				&link.pred_new_hash(),
				&link.pred_new_siblings,
				link.pred_path,
				self.start_index,
			) != mid_root
			{
				return false;
			}
		}

		// ============================================================
		// Linked-list constraints via BatchInsertionLink API
		// ============================================================
		let n = batch_size;

		if n == 1 {
			// Single-element batch: first + last on the same link
			if !self.links[0].mask {
				return false;
			}
			if !self.links[0].verify_last() {
				return false;
			}
		} else {
			// First [0, 1]
			if !self.links[0].verify_first(&self.links[1]) {
				return false;
			}
			// Mid [i, i+1] for i in 1..n-2
			for i in 1..n - 1 {
				if !self.links[i].verify_mid(&self.links[i + 1]) {
					return false;
				}
			}
			// Last [n-1]
			if !self.links[n - 1].verify_last() {
				return false;
			}
		}

		// Emptiness checks omitted: all predecessors have indices < start_index,
		// so the batch subtree [start_index, start_index + batch_size) is
		// structurally guaranteed empty in both old_root and mid_root.

		// ============================================================
		// Phase B: mid_root -> new_root (batch subtree insertion)
		// ============================================================

		// Build batch subtree bottom-up from link leaf hashes
		let mut level: Vec<H::Digest> = self.links.iter().map(|l| l.leaf_hash()).collect();
		for _ in 0..log_batch_size {
			let mut next_level = Vec::with_capacity(level.len() / 2);
			for j in (0..level.len()).step_by(2) {
				next_level.push(H::hash_2_to_1(&level[j], &level[j + 1], false));
			}
			level = next_level;
		}
		let batch_subtree_root = level[0];

		match Self::compute_upper_root(
			&batch_subtree_root,
			&self.new_node_upper_siblings_after_pred_update,
			self.start_index,
			log_batch_size,
			self.start_index + batch_size,
		) {
			Some(computed_new_root) => computed_new_root == self.new_root,
			None => false,
		}
	}

	/// Computes a Merkle root from a leaf hash, its authentication path,
	/// and a fixed-depth sibling array.
	///
	/// `path` is interpreted as a little-endian bitmask:
	/// - bit i == 0 → current node is left child at level i
	/// - bit i == 1 → current node is right child at level i
	///
	/// At the final level, uses `hash_root` to commit `num_leaves`.
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

	/// Walks a subtree root through upper siblings to the tree root.
	fn compute_upper_root(
		subtree_root: &H::Digest,
		upper_siblings: &[H::Digest],
		start_index: usize,
		log_batch_size: usize,
		num_leaves: usize,
	) -> Option<H::Digest> {
		if upper_siblings.is_empty() {
			return None;
		}
		let last_idx = upper_siblings.len() - 1;
		let mut cur: H::Digest = *subtree_root;

		for (i, sibling) in upper_siblings.iter().enumerate() {
			let dir = (start_index >> (log_batch_size + i)) & 1 == 1;

			if i == last_idx {
				let (left, right) = if dir {
					(sibling, &cur)
				} else {
					(&cur, sibling)
				};
				cur = H::hash_root(num_leaves, left, right);
			} else {
				cur = H::hash_2_to_1(&cur, sibling, dir);
			}
		}

		Some(cur)
	}
}

#[cfg(test)]
pub mod test {

	use anyhow::Result;

	use crate::tree::{
		NullifierInsertProof, NullifierTree,
		hasher::{HashOutput, NewFromU64},
	};

	const DEPTH: usize = 4;

	use super::BatchInsertProof;

	/// Helper: builds a tree with 7 leaves then batch-inserts 4 more.
	/// Returns the valid proof.
	fn make_valid_proof() -> Result<BatchInsertProof<HashOutput>> {
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);

		let input_leaves = [5, 15, 12, 30, 7, 13, 25];
		for i in 0..7 {
			let leaf: HashOutput = HashOutput::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<HashOutput> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let new_leaves = [6, 14, 26, 27];
		let mut leaves = Vec::with_capacity(4);
		for i in 0..new_leaves.len() {
			leaves.push(HashOutput::new_from_u64(new_leaves[i]));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		Ok(batch_proof)
	}

	#[test]
	fn batch_insert_native() -> Result<()> {
		let proof = make_valid_proof()?;
		assert!(proof.verify());
		Ok(())
	}

	#[test]
	fn test_tampered_new_root() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.new_root = HashOutput::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_tampered_old_root() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.old_root = HashOutput::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_swapped_leaves() -> Result<()> {
		let mut proof = make_valid_proof()?;
		let tmp = proof.links[0].leaf_value;
		proof.links[0].leaf_value = proof.links[1].leaf_value;
		proof.links[1].leaf_value = tmp;
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_fake_predecessor_value() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.links[0].pred_value = HashOutput::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_mask_first_false() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.links[0].mask = false;
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_mask_chain_to_true() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// mask[3] is false (chained); flipping to true breaks predecessor binding
		assert!(!proof.links[3].mask);
		proof.links[3].mask = true;
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_empty_proof_returns_false() {
		let proof: BatchInsertProof<HashOutput> = BatchInsertProof {
			old_root: HashOutput::new_from_u64(0),
			new_root: HashOutput::new_from_u64(0),
			start_index: 0,
			links: vec![],
			new_node_upper_siblings_after_pred_update: vec![],
		};
		assert!(!proof.verify());
	}

	#[test]
	fn test_non_power_of_two_batch_size() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// Extend to batch_size=5 (not power of two)
		proof.links.push(proof.links.last().unwrap().clone());
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_duplicate_pred_paths() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// Tamper with a masked predecessor's siblings to break mid_root authentication
		let masked_indices: Vec<usize> = proof
			.links
			.iter()
			.enumerate()
			.filter(|(_, l)| l.mask)
			.map(|(i, _)| i)
			.collect();
		if masked_indices.len() >= 2 {
			let second = masked_indices[1];
			proof.links[second].pred_new_siblings[0] = HashOutput::new_from_u64(999);
			assert!(!proof.verify());
		}
		Ok(())
	}

	/// Test with predecessors that are siblings in the Merkle tree,
	/// exercising the path-overlap merge in compute_sparse_root_update.
	#[test]
	fn test_sibling_predecessors() -> Result<()> {
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);

		let input_leaves = [10, 20, 30, 40, 50, 60, 70];
		for i in 0..7 {
			let leaf: HashOutput = HashOutput::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<HashOutput> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let new_leaves = [15, 25, 35, 45];
		let mut leaves = Vec::with_capacity(4);
		for &v in &new_leaves {
			leaves.push(HashOutput::new_from_u64(v));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		let num_masked: usize = batch_proof.links.iter().filter(|l| l.mask).count();
		assert_eq!(
			num_masked, 4,
			"all 4 should be masked (distinct predecessors)"
		);

		Ok(())
	}

	/// Test with maximum chaining: all batch leaves share the same predecessor.
	#[test]
	fn test_max_chaining() -> Result<()> {
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);

		let input_leaves = [10, 100, 200, 300, 400, 500, 600];
		for i in 0..7 {
			let leaf: HashOutput = HashOutput::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<HashOutput> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let new_leaves = [20, 30, 40, 50];
		let mut leaves = Vec::with_capacity(4);
		for &v in &new_leaves {
			leaves.push(HashOutput::new_from_u64(v));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		let num_masked: usize = batch_proof.links.iter().filter(|l| l.mask).count();
		assert_eq!(num_masked, 1, "only first should be masked (max chaining)");

		Ok(())
	}

	/// Large test: 1024 initial leaves then batch-insert 128 more.
	#[test]
	fn test_large_batch_128_initial_1024() -> Result<()> {
		const LARGE_DEPTH: usize = 12;
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(LARGE_DEPTH);

		for v in 1..=1023u64 {
			let leaf: HashOutput = HashOutput::new_from_u64(v * 3);
			let proof = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let mut leaves = Vec::with_capacity(128);
		for i in 0..128u64 {
			leaves.push(HashOutput::new_from_u64(i * 3 + 1));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		assert_eq!(batch_proof.links.len(), 128);

		Ok(())
	}
}
