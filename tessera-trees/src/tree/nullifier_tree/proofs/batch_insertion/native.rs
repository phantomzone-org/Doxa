use anyhow::anyhow;

use crate::tree::{
	Node, NullifierTree,
	error::{MerkleTreeError, MerkleTreeResult},
	hasher::MerkleHash,
};

#[derive(Debug, Clone)]
pub struct BatchInsertProof<H: MerkleHash> {
	// ============ PUBLIC INPUTS ============
	/// Initial tree root (before insertion)
	pub old_root: H::Digest,
	/// Final tree root (after insertion)
	pub new_root: H::Digest,

	/// Masking values used during verification to
	/// distinguish between predecessors that where
	/// already committed in the tree and predecessors
	/// that where in the batch.
	pub mask: Vec<bool>,

	/// Batch insertion index, required to
	/// properly update next_index field of predecessors
	pub start_index: usize,

	/// Contains all predecessors infos, including the ones
	/// that where not previously committed in the tree
	/// (i.e present in the batch).
	pub pred_paths: Vec<usize>,
	pub pred_values: Vec<H::Digest>,
	pub pred_old_next_indexes: Vec<usize>,
	pub pred_old_next_values: Vec<H::Digest>,
	pub pred_old_siblings: Vec<Vec<H::Digest>>,
	pub pred_new_next_indexes: Vec<usize>,
	pub pred_new_next_values: Vec<H::Digest>,

	/// Batch new values
	pub new_node_values: Vec<H::Digest>,

	/// Emptiness commit of the batch in the tree, before and after
	/// the update of the predecessors that were already in the tree
	pub new_node_upper_siblings_before_pred_update: Vec<H::Digest>,
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

		// Sort leaves and populates predecessors:
		// mask: if the predecessor is already committed in the tree
		// pred_paths: path of the predecessor
		// Node:
		// - pred_values: value
		// - pred_next_indexes: next index
		// - pred_next_values: next value
		let (pred_paths, pred_values, pred_old_next_indexes, pred_old_next_values, mask) =
			self.sort_leaves(&mut leaves)?;

		// 1. Anchors the emptiness of the batch to old_root
		let new_node_upper_siblings_before_pred_update: Vec<H::Digest> =
			self.tree
				.merkle_path(start_index, log_batch_size, self.depth())?;

		// 2. Updates predecessors (batch): old_root -> mid_root All siblings are captured against
		//    old_root (tree is not mutated until after the loop). Only masked predecessors get
		//    siblings.
		let mut pred_in_tree_paths = Vec::new();
		let mut pred_old_siblings: Vec<Vec<<H as MerkleHash>::Digest>> = Vec::new();
		let mut pred_new_next_indexes: Vec<usize> = Vec::with_capacity(batch_size);
		let mut pred_new_next_values = Vec::with_capacity(batch_size);
		for i in 0..batch_size {
			if mask[i] {
				pred_new_next_indexes.push(start_index + i);
				pred_new_next_values.push(leaves[i]);
			} else {
				pred_new_next_indexes.push(*pred_new_next_indexes.last().unwrap());
				pred_new_next_values.push(*pred_new_next_values.last().unwrap());
			}

			if mask[i] {
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
			}
		}

		// Batch-apply all predecessor updates to the tree
		for &path in &pred_in_tree_paths {
			self.tree.leaves[path] = self.nodes[path].compute_hash();
		}
		self.tree.update_sparse_paths(&pred_in_tree_paths);

		// 3. Anchors the emptiness of batch to mid_root
		let new_node_upper_siblings_after_pred_update: Vec<H::Digest> =
			self.tree
				.merkle_path(start_index, log_batch_size, self.depth())?;

		// 4. Updates tree nodes
		for i in 0..batch_size {
			if i < batch_size - 1 {
				match (mask[i], mask[i + 1]) {
					(true, true) | (false, true) => {
						self.nodes.push(Node::new(
							leaves[i],
							pred_old_next_indexes[i],
							pred_old_next_values[i],
						));
					},
					(true, false) | (false, false) => {
						self.nodes
							.push(Node::new(leaves[i], start_index + i + 1, leaves[i + 1]));
					},
				}
			} else {
				self.nodes.push(Node::new(
					leaves[i],
					pred_old_next_indexes[i],
					pred_old_next_values[i],
				));
			}

			self.tree
				.leaves
				.push(self.nodes.last().unwrap().compute_hash());
			self.actives.insert(leaves[i], start_index + i);
		}

		// 5. Commits the entire batch A + B -> new_root
		self.tree
			.update_consecutive_paths(start_index, batch_size)?;

		// ============================================================
		// Phase 3: Emit STARK-friendly proof
		// ============================================================

		// pred[i].value < leaf < pred[i].next_value <= pred[i+1].value
		let new_root: H::Digest = self.get_root();

		Ok(BatchInsertProof {
			old_root,
			new_root,
			mask,
			pred_paths,
			pred_values,
			pred_old_next_indexes,
			pred_old_next_values,
			pred_old_siblings,
			pred_new_next_indexes,
			pred_new_next_values,
			start_index,
			new_node_values: leaves,
			new_node_upper_siblings_before_pred_update,
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

			// 1.a. Find the tree predecessor of `value`
			//
			// This is the unique node such that:
			//     pred.value < value < pred.next_value
			let pred_index: usize = self.find_predecessor_index_from_value(leaf).ok_or(anyhow!(
				MerkleTreeError::NonMembershipProofError(
					"failed to find predecessor index".to_string()
				)
			))?;

			let pred_node: Node<H> = self.nodes[pred_index];

			// 1.b. Validate non-membership in native code
			if !(pred_node.value < leaf && leaf < pred_node.next_value) {
				return Err(anyhow!(MerkleTreeError::NonMembershipProofError(
					"range check failed".to_string()
				)));
			}

			// 1.c. Records all predecessors.
			// mask[i] = false when the predecessor is the same as the previous
			// leaf's predecessor (i.e. chained — the previous batch leaf falls
			// in the same predecessor's gap).
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
	#[allow(clippy::needless_range_loop)]
	pub fn verify(&self) -> bool {
		let old_root = self.old_root;
		let batch_size = self.pred_paths.len();

		if batch_size == 0 || !batch_size.is_power_of_two() {
			return false;
		}

		let log_batch_size = batch_size.trailing_zeros() as usize;

		if self.mask.len() != batch_size
			|| self.pred_old_next_indexes.len() != batch_size
			|| self.pred_old_next_values.len() != batch_size
			|| self.pred_new_next_indexes.len() != batch_size
			|| self.pred_new_next_values.len() != batch_size
			|| self.new_node_values.len() != batch_size
			|| self.pred_values.len() != batch_size
		{
			return false;
		}

		let num_masked: usize = self.mask.iter().filter(|&&m| m).count();
		if self.pred_old_siblings.len() != num_masked {
			return false;
		}

		let mask: &Vec<bool> = &self.mask;

		// First mask value MUST be true
		if !mask[0] {
			return false;
		}

		// ============================================================
		// Phase A: old_root -> mid_root (predecessor updates)
		//
		// 1. Authenticate each masked predecessor against old_root
		// 2. Compute mid_root via sparse bottom-up merge of all updates
		// ============================================================
		let mut sibling_cursor = 0;
		let mut masked_paths: Vec<usize> = Vec::new();
		let mut old_leaf_hashes: Vec<H::Digest> = Vec::new();
		let mut new_leaf_hashes: Vec<H::Digest> = Vec::new();
		let mut all_siblings: Vec<&Vec<H::Digest>> = Vec::new();

		for i in 0..batch_size {
			if !mask[i] {
				continue;
			}

			let siblings = &self.pred_old_siblings[sibling_cursor];
			sibling_cursor += 1;

			let old_pred_hash: H::Digest = H::commit_node(
				&self.pred_values[i],
				self.pred_old_next_indexes[i],
				&self.pred_old_next_values[i],
			);

			if Self::compute_root(
				&old_pred_hash,
				siblings,
				self.pred_paths[i],
				self.start_index,
			) != old_root
			{
				return false;
			}

			let new_pred_hash: H::Digest = H::commit_node(
				&self.pred_values[i],
				self.pred_new_next_indexes[i],
				&self.pred_new_next_values[i],
			);

			masked_paths.push(self.pred_paths[i]);
			old_leaf_hashes.push(old_pred_hash);
			new_leaf_hashes.push(new_pred_hash);
			all_siblings.push(siblings);
		}

		let mid_root = if masked_paths.is_empty() {
			old_root
		} else {
			match Self::compute_sparse_root_update(
				&masked_paths,
				&old_leaf_hashes,
				&new_leaf_hashes,
				&all_siblings,
				self.start_index,
				&old_root,
			) {
				Some(root) => root,
				None => return false,
			}
		};

		// ============================================================
		// Linked-list constraints + Phase B leaf hashes (single pass)
		//
		// 12 essential constraints enforced per iteration (for STARK trace reference).
		// 5 additional constraints (marked T) are tautological in the native verifier
		// because leaf_next is derived, not a witness. They become real constraints
		// in the STARK circuit where leaf_next is a witness column.
		//
		// --- Per-leaf (all i) ---
		//  1. mask[i] => pred_new_next_index[i] == start_index + i
		//  2. mask[i] => pred_new_next_value[i] == leaf[i]
		//  3. leaf_next_value[i] > leaf[i]                              (¹)
		//  4. pred_old_next_value[i] > leaf[i]
		//  5. pred_value[i] < leaf[i]
		//
		// --- Inter-leaf (i < batch_size - 1, looking at i+1) ---
		//  6. T  mask[i+1] => leaf_next_index[i] == pred_old_next_index[i]
		//  7. T  mask[i+1] => leaf_next_value[i] == pred_old_next_value[i]
		//  8.    mask[i+1] => pred_value[i+1] > leaf[i]
		//  9.   !mask[i+1] => pred_path[i] == pred_path[i+1]
		// 10.   !mask[i+1] => pred_value[i] == pred_value[i+1]
		// 11.   !mask[i+1] => pred_new_next_value[i] == pred_new_next_value[i+1]
		// 12.   !mask[i+1] => pred_new_next_index[i] == pred_new_next_index[i+1]
		// 13.   !mask[i+1] => pred_old_next_value[i] == pred_old_next_value[i+1]
		// 14.   !mask[i+1] => pred_old_next_index[i] == pred_old_next_index[i+1]
		// 15. T !mask[i+1] => leaf_next_index[i] == leaf_index[i+1]
		// 16. T !mask[i+1] => leaf_next_value[i] == leaf_value[i+1]
		// 17. T  leaf_index[i] + 1 == leaf_index[i+1]
		//
		// --- First / last ---
		// 18.  mask[0] == true                         (checked above as early return)
		// 19. T leaf_next_index[last] == pred_old_next_index[last]  (by construction)
		// 20. T leaf_next_value[last] == pred_old_next_value[last]  (by construction)
		//
		// (¹) Constraint 3 is implied: when mask[i+1], it reduces to #4;
		//     when !mask[i+1], it reduces to sorted order (leaf[i] < leaf[i+1]).
		// ============================================================
		let mut leaf_hashes: Vec<H::Digest> = Vec::with_capacity(batch_size);

		for i in 0..batch_size {
			let leaf = self.new_node_values[i];

			// Derive this leaf's next pointer
			let (next_index, next_value) = if i == batch_size - 1 || mask[i + 1] {
				(self.pred_old_next_indexes[i], self.pred_old_next_values[i])
			} else {
				(self.start_index + i + 1, self.new_node_values[i + 1])
			};

			// Non-membership: pred.value < leaf < pred.next_value
			if !(self.pred_values[i] < leaf && leaf < self.pred_old_next_values[i]) {
				return false;
			}

			// Predecessor update binding (masked only)
			if mask[i]
				&& (self.pred_new_next_indexes[i] != self.start_index + i
					|| self.pred_new_next_values[i] != leaf)
			{
				return false;
			}

			// Inter-leaf constraints
			if i < batch_size - 1 {
				// Sorted order
				if leaf >= self.new_node_values[i + 1] {
					return false;
				}

				if mask[i + 1] {
					// Distinct predecessor: gap must not overlap current leaf
					if self.pred_values[i + 1] <= leaf {
						return false;
					}
				} else {
					// Chained: all predecessor fields must match
					if self.pred_paths[i] != self.pred_paths[i + 1]
						|| self.pred_values[i] != self.pred_values[i + 1]
						|| self.pred_old_next_indexes[i] != self.pred_old_next_indexes[i + 1]
						|| self.pred_old_next_values[i] != self.pred_old_next_values[i + 1]
						|| self.pred_new_next_indexes[i] != self.pred_new_next_indexes[i + 1]
						|| self.pred_new_next_values[i] != self.pred_new_next_values[i + 1]
					{
						return false;
					}
				}
			}

			leaf_hashes.push(H::commit_node(&leaf, next_index, &next_value));
		}

		// ============================================================
		// Emptiness checks: batch slots empty in old_root and mid_root
		// ============================================================
		if !Self::authenticate_empty_batch(
			self.start_index,
			log_batch_size,
			&self.new_node_upper_siblings_before_pred_update,
			&old_root,
			self.start_index,
		) {
			return false;
		}

		if !Self::authenticate_empty_batch(
			self.start_index,
			log_batch_size,
			&self.new_node_upper_siblings_after_pred_update,
			&mid_root,
			self.start_index,
		) {
			return false;
		}

		// ============================================================
		// Phase B: mid_root -> new_root (batch subtree insertion)
		// ============================================================

		// Build batch subtree bottom-up
		let mut level = leaf_hashes;
		for _ in 0..log_batch_size {
			let mut next_level = Vec::with_capacity(level.len() / 2);
			for j in (0..level.len()).step_by(2) {
				next_level.push(H::hash_2_to_1(&level[j], &level[j + 1], false));
			}
			level = next_level;
		}
		let batch_subtree_root = level[0];

		// 3. Walk upper siblings from subtree root to tree root
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

	/// Checks that leaves [start_index..start_index + batch_size] are empty.
	fn authenticate_empty_batch(
		start_index: usize,
		log_batch_size: usize,
		upper_siblings: &[H::Digest],
		root: &H::Digest,
		num_leaves: usize,
	) -> bool {
		// Recompute the empty subtree root
		let mut empty_subtree: H::Digest = H::HEAD;
		for _ in 0..log_batch_size {
			empty_subtree = H::hash_2_to_1(&empty_subtree, &empty_subtree, false);
		}

		match Self::compute_upper_root(
			&empty_subtree,
			upper_siblings,
			start_index,
			log_batch_size,
			num_leaves,
		) {
			Some(computed) => &computed == root,
			None => false,
		}
	}

	/// Walks a subtree root through upper siblings to the tree root.
	/// Used by both Phase B (batch insertion) and emptiness checks.
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

	/// Computes the new root after updating K leaves simultaneously.
	///
	/// All siblings are against the old root. When two updated leaves
	/// share a Merkle path node, the stale sibling is replaced with
	/// the freshly computed hash from the other leaf's subtree.
	///
	/// Processes levels bottom-up: at each level, computes the new parent
	/// hash for each updated position, merging when siblings are also updated.
	///
	/// Cross-checks that the old hashes converge to `expected_old_root`.
	/// Returns `None` if paths contain duplicates or the old root doesn't match.
	fn compute_sparse_root_update(
		paths: &[usize],
		old_leaf_hashes: &[H::Digest],
		new_leaf_hashes: &[H::Digest],
		siblings: &[&Vec<H::Digest>],
		num_leaves: usize,
		expected_old_root: &H::Digest,
	) -> Option<H::Digest> {
		use std::collections::BTreeMap;

		let k = paths.len();
		if k == 0 {
			return None;
		}
		let depth = siblings[0].len();

		// Map: position_at_current_level -> (old_hash, new_hash, sibling_index)
		// sibling_index tells us which sibling array to use for this position
		let mut updates: BTreeMap<usize, (H::Digest, H::Digest, usize)> = BTreeMap::new();
		for i in 0..k {
			// Duplicate paths would silently drop an update
			if updates.contains_key(&paths[i]) {
				return None;
			}
			updates.insert(paths[i], (old_leaf_hashes[i], new_leaf_hashes[i], i));
		}

		for level in 0..depth {
			let mut next_updates: BTreeMap<usize, (H::Digest, H::Digest, usize)> = BTreeMap::new();

			for (&pos, &(old_hash, new_hash, sib_idx)) in &updates {
				let parent = pos / 2;
				let is_right = pos & 1 == 1;
				let sibling_pos = pos ^ 1;

				// Determine the old and new sibling values
				let (old_sibling, new_sibling) =
					if let Some(&(old_s, new_s, _)) = updates.get(&sibling_pos) {
						// Sibling is also being updated — use its new hash
						(old_s, new_s)
					} else {
						// Sibling unchanged — use from proof
						let s = siblings[sib_idx][level];
						(s, s)
					};

				// Skip if parent already processed (from sibling's iteration)
				if next_updates.contains_key(&parent) {
					continue;
				}

				let (old_left, old_right) = if is_right {
					(old_sibling, old_hash)
				} else {
					(old_hash, old_sibling)
				};

				let (new_left, new_right) = if is_right {
					(new_sibling, new_hash)
				} else {
					(new_hash, new_sibling)
				};

				let old_parent = if level == depth - 1 {
					H::hash_root(num_leaves, &old_left, &old_right)
				} else {
					H::hash_2_to_1(&old_left, &old_right, false)
				};

				let new_parent = if level == depth - 1 {
					H::hash_root(num_leaves, &new_left, &new_right)
				} else {
					H::hash_2_to_1(&new_left, &new_right, false)
				};

				next_updates.insert(parent, (old_parent, new_parent, sib_idx));
			}

			updates = next_updates;
		}

		if updates.len() != 1 {
			return None;
		}

		let (_, (old_root_computed, new_root, _)) = updates.into_iter().next().unwrap();

		// Cross-check: old hashes must converge to the expected old root
		if &old_root_computed != expected_old_root {
			return None;
		}

		Some(new_root)
	}
}

#[cfg(test)]
pub mod test {

	use anyhow::Result;

	use crate::tree::{
		NullifierInsertProof, NullifierTree,
		hasher::{Hash, NewFromU64},
	};

	const DEPTH: usize = 4;

	use super::BatchInsertProof;

	/// Helper: builds a tree with 7 leaves then batch-inserts 4 more.
	/// Returns the valid proof.
	fn make_valid_proof() -> Result<BatchInsertProof<Hash>> {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let input_leaves = [5, 15, 12, 30, 7, 13, 25];
		for i in 0..7 {
			let leaf: Hash = Hash::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let new_leaves = [6, 14, 26, 27];
		let mut leaves = Vec::with_capacity(4);
		for i in 0..new_leaves.len() {
			leaves.push(Hash::new_from_u64(new_leaves[i]));
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
		proof.new_root = Hash::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_tampered_old_root() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.old_root = Hash::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_swapped_leaves() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.new_node_values.swap(0, 1);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_fake_predecessor_value() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.pred_values[0] = Hash::new_from_u64(999);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_mask_first_false() -> Result<()> {
		let mut proof = make_valid_proof()?;
		proof.mask[0] = false;
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_mask_chain_to_true() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// mask[3] is false (chained); flipping to true breaks sibling count
		assert!(!proof.mask[3]);
		proof.mask[3] = true;
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_empty_proof_returns_false() {
		let proof: BatchInsertProof<Hash> = BatchInsertProof {
			old_root: Hash::new_from_u64(0),
			new_root: Hash::new_from_u64(0),
			mask: vec![],
			start_index: 0,
			pred_paths: vec![],
			pred_values: vec![],
			pred_old_next_indexes: vec![],
			pred_old_next_values: vec![],
			pred_old_siblings: vec![],
			pred_new_next_indexes: vec![],
			pred_new_next_values: vec![],
			new_node_values: vec![],
			new_node_upper_siblings_before_pred_update: vec![],
			new_node_upper_siblings_after_pred_update: vec![],
		};
		assert!(!proof.verify());
	}

	#[test]
	fn test_non_power_of_two_batch_size() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// Extend to batch_size=5 (not power of two)
		proof.pred_paths.push(0);
		assert!(!proof.verify());
		Ok(())
	}

	#[test]
	fn test_duplicate_pred_paths() -> Result<()> {
		let mut proof = make_valid_proof()?;
		// Force two masked predecessors to share the same path
		if proof.mask.iter().filter(|&&m| m).count() >= 2 {
			let masked_indices: Vec<usize> = proof
				.mask
				.iter()
				.enumerate()
				.filter(|(_, m)| **m)
				.map(|(i, _)| i)
				.collect();
			let first = masked_indices[0];
			let second = masked_indices[1];
			proof.pred_paths[second] = proof.pred_paths[first];
			assert!(!proof.verify());
		}
		Ok(())
	}

	/// Test with predecessors that are siblings in the Merkle tree,
	/// exercising the path-overlap merge in compute_sparse_root_update.
	#[test]
	fn test_sibling_predecessors() -> Result<()> {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		// Insert leaves whose predecessors will land at adjacent tree positions.
		// Positions are assigned sequentially: sentinel=0, then 1,2,3,...
		// We want at least two batch predecessors at sibling positions (e.g. 2 and 3).
		// Insert 7 values so positions 0-7 are filled, then batch-insert 4 more.
		// Values are chosen so batch leaves have predecessors at positions that
		// are Merkle siblings (differ only in the lowest bit).
		let input_leaves = [10, 20, 30, 40, 50, 60, 70];
		for i in 0..7 {
			let leaf: Hash = Hash::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		// Batch: 4 leaves that fall into gaps of different predecessors
		let new_leaves = [15, 25, 35, 45];
		let mut leaves = Vec::with_capacity(4);
		for &v in &new_leaves {
			leaves.push(Hash::new_from_u64(v));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		// Verify that we have multiple masked predecessors (no chaining)
		let num_masked: usize = batch_proof.mask.iter().filter(|&&m| m).count();
		assert_eq!(
			num_masked, 4,
			"all 4 should be masked (distinct predecessors)"
		);

		Ok(())
	}

	/// Test with maximum chaining: all batch leaves share the same predecessor.
	#[test]
	fn test_max_chaining() -> Result<()> {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		// Insert 7 leaves with a large gap for chaining
		let input_leaves = [10, 100, 200, 300, 400, 500, 600];
		for i in 0..7 {
			let leaf: Hash = Hash::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		// All 4 batch leaves fall in the same gap (10..100)
		let new_leaves = [20, 30, 40, 50];
		let mut leaves = Vec::with_capacity(4);
		for &v in &new_leaves {
			leaves.push(Hash::new_from_u64(v));
		}

		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		// Only the first should be masked, rest are chained
		let num_masked: usize = batch_proof.mask.iter().filter(|&&m| m).count();
		assert_eq!(num_masked, 1, "only first should be masked (max chaining)");

		Ok(())
	}
}
