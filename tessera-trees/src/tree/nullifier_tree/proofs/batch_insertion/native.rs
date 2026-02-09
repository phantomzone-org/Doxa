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
	///
	/// Each array is of size batch_size and groups two sets:
	/// [0..split]: predecessors previously in the tree
	/// [split..] : predecessors in the batch.
	pub pred_paths: Vec<usize>,
	pub pred_values: Vec<H::Digest>,
	pub pred_old_next_indexes: Vec<usize>,
	pub pred_old_next_values: Vec<H::Digest>,
	pub pred_old_siblings: Vec<Vec<H::Digest>>,

	/// Batch new values
	pub new_node_values: Vec<H::Digest>,

	/// Emptiness commit of the batch in the tree, before and after
	/// the update of the predecessors that were already in the tree
	/// i.e. [0..split].
	pub new_node_upper_siblings_before_pred_update: Vec<H::Digest>,
	pub new_node_upper_siblings_after_pred_update: Vec<H::Digest>,
}

impl<H: MerkleHash> NullifierTree<H> {
	pub fn insert_leaves(
		&mut self,
		mut leaves: Vec<H::Digest>,
	) -> MerkleTreeResult<BatchInsertProof<H>> {
		let start_index: usize = self.nodes.len();

		let batch_size: usize = leaves.len();

		assert!(batch_size.is_power_of_two());
		assert!(start_index.is_multiple_of(batch_size));

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
			self.sort_leaves(start_index, &mut leaves)?;

		// 1. Anchors the emptiness of the batch to old_root
		let new_node_upper_siblings_before_pred_update: Vec<H::Digest> = self
			.tree
			.generate_siblings_array(start_index, log_batch_size, self.depth())?;

		// 2. Updates predecessors & commits old_root -> mid_root
		let mut pred_in_tree_paths = Vec::new();
		let mut pred_old_siblings: Vec<Vec<<H as MerkleHash>::Digest>> =
			Vec::with_capacity(batch_size);
		for i in 0..batch_size {
			if mask[i] {
				self.nodes[pred_paths[i]] = Node::new(pred_values[i], start_index + i, leaves[i]);
				pred_in_tree_paths.push(pred_paths[i]);
				let siblings: Vec<H::Digest> =
					self.tree
						.generate_siblings_array(pred_paths[i], 0, self.depth())?;
				pred_old_siblings.push(siblings);
			} else {
				let siblings: Vec<H::Digest> =
					self.tree.generate_siblings_array(0, 0, self.depth())?;
				pred_old_siblings.push(siblings);
			}
		}

		self.tree.update_sparse_paths(&pred_in_tree_paths);

		// 3. Anchors the emptiness of batch to mid_root
		let new_node_upper_siblings_after_pred_update: Vec<H::Digest> = self
			.tree
			.generate_siblings_array(start_index, log_batch_size, self.depth())?;

		for i in 0..batch_size {
			self.nodes.push(Node::new(
				leaves[i],
				pred_old_next_indexes[i],
				pred_old_next_values[i],
			));

			self.actives.insert(leaves[i], start_index + i);
		}

		// 4. Commits the entire batch A + B -> new_root
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
		start_index: usize,
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
				return Err(anyhow!(MerkleTreeError::InvalidBatch(format!(
					"duplicated leaves"
				))));
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

			let candidate_com: Node<H> = self.find_node_by_index(pred_index).ok_or(anyhow!(
				MerkleTreeError::NonMembershipProofError(
					"failed to find predecessor from index".to_string()
				)
			))?;

			// 1.b. Read predecessor node
			let pred_node: Node<H> = self.nodes[pred_index];

			// 1.c. Validate non-membership in native code
			if !(&pred_node.value < &leaf && &leaf < &pred_node.next_value) {
				return Err(anyhow!(MerkleTreeError::NonMembershipProofError(
					"range check failed".to_string()
				)));
			}

			//                               T  T  T  F  F  T   F   F
			//  0  1  2  3  4   5   6   7]   8   9   10 11 12   13  14  15
			// [0, 1, 3, 5, 9, 10, 11, 12]  [2] [4] [ 6  7  8] [13, 14, 15]
			//                              [2] [3] [11 12  4] [14  15   0]
			//                              [3] [5] [ 7  8  9] [14  15   0]
			// pred_path                    [1] [2] [ 3 10 11] [ 7  13  14]
			// pred_value                   [1] [3] [ 5  6  7] [12  13  14]
			if i > 0 {
				let candidate_batch: H::Digest = leaves[i - 1];

				// Since `leaves` is strictly sorted, candidate_batch < leaf always holds.
				// So candidate_batch > candidate_com.value ⇔ batch predecessor is better.
				if candidate_batch > candidate_com.value {
					pred_paths.push(start_index + i - 1);
					pred_values.push(candidate_batch);
					pred_next_indexes.push(pred_next_indexes[i - 1]);
					pred_next_indexes[i - 1] = start_index + i;
					pred_next_values.push(pred_next_values[i - 1]);
					pred_next_values[i - 1] = leaves[i];
				} else {
					// 1.d. Snapshot old root and predecessor metadata
					//
					// These values are required to:
					// - authenticate the predecessor
					// - rewire its successor pointer
					mask[i] = true;
					pred_paths.push(pred_index);
					pred_values.push(pred_node.value);
					pred_next_indexes.push(pred_node.next_index);
					pred_next_values.push(pred_node.next_value);
				}
			} else {
				// 1.d. Snapshot old root and predecessor metadata
				//
				// These values are required to:
				// - authenticate the predecessor
				// - rewire its successor pointer
				mask[i] = true;
				pred_paths.push(pred_index);
				pred_values.push(pred_node.value);
				pred_next_indexes.push(pred_node.next_index);
				pred_next_values.push(pred_node.next_value);
			}
		}

		for i in 0..pred_values.len() {
			println!(
				"{:2}: {} {:2} {:2} {} {}",
				start_index + i,
				leaves[i],
				pred_paths[i],
				pred_next_indexes[i],
				pred_values[i],
				pred_next_values[i]
			);
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
		let batch_size = self.pred_paths.len();
		let log_batch_size = batch_size.trailing_zeros() as usize;

		assert_eq!(self.pred_old_next_indexes.len(), batch_size);
		assert_eq!(self.pred_old_next_values.len(), batch_size);
		assert_eq!(self.new_node_values.len(), batch_size);
		assert_eq!(self.pred_old_siblings.len(), batch_size);
		assert_eq!(self.pred_values.len(), batch_size);

		let mask: &Vec<bool> = &self.mask;

		// First mask value MUST be one
		if !mask[0] {
			return false;
		}

		let mut pred_value: H::Digest = self.pred_values[0];
		let mut pred_path: usize = self.pred_paths[0];
		let mut pred_siblings: &Vec<H::Digest> = &self.pred_old_siblings[0];

		// Authenticates true predecessors against old_root
		for i in 0..batch_size {
			// If mask == true, the current value is the true
			// predecessor and must be propagated until the next
			// mask == true (i.e. these values do not change if
			// mask == false).
			if mask[i] {
				pred_value = self.pred_values[i];
				pred_path = self.pred_paths[i];
				pred_siblings = &self.pred_old_siblings[i];
			}

			// If the next mask is true, this means that we either
			// arrived at the end of a chain of false predecessors
			// (current mask is false) or that there was not chain
			// (current mask is true).
			//
			// As such it's time to authenticate the predecessor against the old root.
			if i == batch_size - 1 || mask[i + 1] {
				let old_pred_hash: H::Digest = H::commit_node(
					&pred_value,
					self.pred_old_next_indexes[i],
					&self.pred_old_next_values[i],
				);

				if Self::compute_root(&old_pred_hash, pred_siblings, pred_path, self.start_index)
					!= old_root
				{
					return false;
				}
			}
		}

		if !Self::authenticate_empty_batch(
			self.start_index,
			log_batch_size,
			&self.new_node_upper_siblings_before_pred_update,
			&old_root,
			self.start_index,
		) {
			return false;
		}

		// Computes mid_root
		let mut _mid_root: H::Digest = H::HEAD;

		println!("mask: {:?}", self.mask);

		for i in 0..batch_size {
			if mask[i] {
				let new_pred_hash: H::Digest = H::commit_node(
					&self.pred_values[i],
					self.start_index + i,
					&self.new_node_values[i],
				);

				println!("pred_hash: {} {}", self.pred_paths[i], new_pred_hash);

				let root: H::Digest = Self::compute_root(
					&new_pred_hash,
					&self.pred_old_siblings[i],
					self.pred_paths[i],
					self.start_index,
				);

				println!("root: {}", root);

				// if mid_root == H::HEAD{
				// mid_root = root
				// }else{
				// if mid_root != root{
				// return false
				// }
				// }
			}
		}

		true
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

	/// Checks that leaves [starting_index..starting_index + batch_size] are empty.
	fn authenticate_empty_batch(
		start_index: usize,
		log_batch_size: usize,
		upper_siblings: &[H::Digest],
		root: &H::Digest,
		num_leaves: usize,
	) -> bool {
		let num_upper_siblings = upper_siblings.len();

		// Recomputes batch root (empty subtree)
		let mut cur: H::Digest = H::HEAD;
		for _ in 0..log_batch_size {
			cur = H::hash_2_to_1(&cur, &cur, false);
		}

		// Continue with sibling until top of tree
		for i in 0..num_upper_siblings {
			let dir = (start_index >> (log_batch_size + i)) & 1 == 1;

			// At the final level, use hash_root to commit num_leaves
			if i == num_upper_siblings - 1 {
				let (left, right) = if dir {
					(&upper_siblings[i], &cur)
				} else {
					(&cur, &upper_siblings[i])
				};
				cur = H::hash_root(num_leaves, left, right);
			} else {
				cur = H::hash_2_to_1(&cur, &upper_siblings[i], dir);
			}
		}

		&cur == root
	}
}

#[cfg(test)]
pub mod test {

	use anyhow::Result;

	// use rand::{SeedableRng, rngs::StdRng};
	use crate::tree::{
		NullifierInsertProof, NullifierTree,
		hasher::{Hash, NewFromU64},
	};
	#[allow(dead_code)]
	const DEPTH: usize = 10;
	// const STARTING_LEAVES: usize = 1 << (DEPTH - 1);
	// const BATCH_SIZE: usize = 1 << (DEPTH - 2);

	//#[test]
	#[allow(dead_code)]
	fn batch_insert_native() -> Result<()> {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		// let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		let input_leaves = [1, 3, 5, 9, 10, 11, 12];

		for i in 0..7 {
			let leaf: Hash = Hash::new_from_u64(input_leaves[i]);
			let proof: NullifierInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		println!();

		// for i in 0..tree.nodes.len(){
		//  print!("node[{i}]:\n {}\n", tree.nodes[i]);
		//}

		tree.verify()?;

		let new_leaves = [2, 4, 6, 7, 8, 13, 14, 15];

		let mut leaves = Vec::with_capacity(8);
		for i in 0..8 {
			let leaf = Hash::new_from_u64(new_leaves[i]);
			leaves.push(leaf);
		}

		let batch_proof = tree.insert_leaves(leaves)?;

		// for i in 0..tree.nodes.len() {
		//  print!("node[{i}]:\n {}\n", tree.nodes[i]);
		//}

		tree.verify()?;

		assert!(batch_proof.verify());

		Ok(())
	}
}
