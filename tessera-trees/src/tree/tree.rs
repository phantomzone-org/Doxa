extern crate alloc;

use alloc::{vec, vec::Vec};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::tree::{
	error::{MerkleTreeError, MerkleTreeResult},
	hasher::MerkleHash,
};

/// Represents an indexed nullifier merkle tree.
///
/// The tree is left->right append only and has a
/// sparse representation (only active [Node] and
/// siblings are stored).
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct MerkleTree<H: MerkleHash> {
	/// Leaves
	pub(crate) leaves: Vec<H::Digest>,

	/// A vector of hashes by levels, from depth-1 up to 0 (the root)
	pub(crate) layers: Vec<Vec<H::Digest>>,

	/// A helper vector of default hashes
	pub(crate) default_siblings: Vec<H::Digest>,
}

impl<H: MerkleHash> MerkleTree<H> {
	/// Allocates a new [NullifierTree] of the provided depth.
	/// The depth is fixed and cannot be changed afterward.
	pub fn new(depth: usize) -> Self {
		let mut default_siblings: Vec<H::Digest> = Vec::with_capacity(depth);

		default_siblings.push(H::HEAD);
		for i in 1..depth {
			default_siblings.push(H::hash_2_to_1(
				&default_siblings[i - 1],
				&default_siblings[i - 1],
				false,
			));
		}

		Self {
			leaves: Vec::new(),
			layers: vec![Vec::new(); depth],
			default_siblings,
		}
	}

	#[allow(dead_code)]
	pub(crate) fn get_default_siblings(&self) -> &[H::Digest] {
		&self.default_siblings
	}

	/// Generates a fixed-size sibling array for a given index.
	/// Any index is supported, even for empty nodes.
	pub fn merkle_path(
		&self,
		index: usize,
		start_depth: usize,
		end_depth: usize,
	) -> MerkleTreeResult<Vec<H::Digest>> {
		assert!(end_depth <= self.depth());
		assert!(end_depth > start_depth);

		let mut siblings: Vec<H::Digest> = vec![H::HEAD; end_depth - start_depth];
		let mut pos: usize = index >> start_depth;

		for level in start_depth..end_depth {
			let is_right: bool = (pos & 1) == 1;
			let sibling_pos: usize = if is_right { pos - 1 } else { pos + 1 };

			siblings[level - start_depth] = if level == 0 {
				if sibling_pos < self.leaves.len() {
					self.leaves[sibling_pos]
				} else {
					self.default_siblings[0]
				}
			} else {
				let prev_layer = &self.layers[level - 1];
				if sibling_pos < prev_layer.len() {
					prev_layer[sibling_pos]
				} else {
					self.default_siblings[level]
				}
			};

			pos >>= 1;
		}

		Ok(siblings)
	}

	pub fn depth(&self) -> usize {
		self.layers.len()
	}

	/// Returns the number of leaf slots currently allocated (including inactive ones).
	pub fn num_leaves(&self) -> usize {
		self.leaves.len()
	}

	/// Returns the leaf hashes currently stored (append order).
	pub fn leaves(&self) -> &[H::Digest] {
		&self.leaves
	}

	pub fn get_root(&self) -> H::Digest {
		let last_layer: &Vec<H::Digest> = self.layers.last().unwrap();
		if last_layer.is_empty() {
			// Empty tree: return the root of a tree with all empty leaves
			// default_siblings[depth-1] is the root of a subtree with 2^(depth-1) empty leaves
			// The empty root is hash_root(0, default_siblings[depth-1], default_siblings[depth-1])
			let last_default = self.default_siblings.last().unwrap();
			H::hash_root(0, last_default, last_default)
		} else {
			assert_eq!(last_layer.len(), 1);
			last_layer[0]
		}
	}

	pub(crate) fn update_merkle_path(&mut self, index: usize) {
		// `pos` tracks the node position at the current level.
		// At level 0 this is a leaf index; afterwards it becomes the parent index.
		let mut pos: usize = index;

		// The hash we propagate upward.
		// Starts as the updated leaf's hash.
		let mut current_hash: H::Digest = self.leaves[index];

		// Iterate through each Merkle level, bottom → top
		for level in 0..self.depth() {
			// Compute the parent index at this level
			let parent: usize = pos >> 1;

			// Determine whether the current hash is a right child
			// (needed for ordering the hash inputs)
			let is_right: bool = (pos & 1) == 1;

			// --------------------------------------------------
			// Step 1: Fetch the sibling hash
			// --------------------------------------------------
			//
			// IMPORTANT INVARIANT:
			//   - At level 0, siblings come from `nodes`
			//   - At level ≥1, siblings come from `layers[level - 1]`
			//   - If the sibling does not exist, use the default hash
			//
			let sibling_hash: H::Digest = if level == 0 {
				// Level 0: siblings are leaves
				if is_right {
					// Right child → left sibling must exist
					self.leaves[pos - 1]
				} else if pos + 1 < self.leaves.len() {
					// Left child → right sibling exists
					self.leaves[pos + 1]
				} else {
					// Left child → right sibling missing → default
					self.default_siblings[0]
				}
			} else {
				// Level ≥1: siblings are from the previous layer
				let prev_layer: &Vec<H::Digest> = &self.layers[level - 1];

				if is_right {
					// Right child → left sibling must exist
					prev_layer[pos - 1]
				} else if pos + 1 < prev_layer.len() {
					// Left child → right sibling exists
					prev_layer[pos + 1]
				} else {
					// Left child → right sibling missing → default
					self.default_siblings[level]
				}
			};

			// --------------------------------------------------
			// Step 2: Compute parent hash
			// --------------------------------------------------
			// At the final level (root), use hash_root to commit num_leaves
			current_hash = if level == self.depth() - 1 {
				let (left, right) = if is_right {
					(&sibling_hash, &current_hash)
				} else {
					(&current_hash, &sibling_hash)
				};
				H::hash_root(self.leaves.len(), left, right)
			} else {
				H::hash_2_to_1(&current_hash, &sibling_hash, is_right)
			};

			// --------------------------------------------------
			// Step 3: Write the parent hash
			// --------------------------------------------------
			//
			// In a left-to-right append-only tree:
			//   - Either the parent already exists → overwrite
			//   - Or this is the next parent → append
			//
			let layer: &mut Vec<H::Digest> = &mut self.layers[level];

			if parent < layer.len() {
				// Parent already exists → overwrite
				layer[parent] = current_hash;
			} else {
				// Parent does not exist yet → append
				//
				// This assertion guarantees we are filling layers sequentially
				debug_assert_eq!(parent, layer.len());
				layer.push(current_hash);
			}

			// Move up the tree
			pos = parent;
		}
	}

	#[allow(dead_code)]
	pub(crate) fn rebuild_tree(&mut self) {
		// Clear all layers
		for layer in self.layers.iter_mut() {
			layer.clear();
		}

		// Rebuild from leaves upward
		for i in 0..self.leaves.len() {
			self.update_merkle_path(i);
		}
	}

	pub(crate) fn update_leaf(
		&mut self,
		index: usize,
		new_leaf: H::Digest,
	) -> MerkleTreeResult<()> {
		if index >= self.leaves.len() {
			return Err(anyhow!(MerkleTreeError::IndexError(format!(
				"index: {} >= {}",
				index,
				self.leaves.len()
			))));
		}

		self.leaves[index] = new_leaf;
		self.update_merkle_path(index);

		Ok(())
	}

	pub(crate) fn insert(&mut self, leaf: H::Digest) -> MerkleTreeResult<()> {
		if self.num_leaves() >= 1 << self.depth() {
			return Err(anyhow!(MerkleTreeError::FullTree()));
		}

		self.leaves.push(leaf);
		self.update_merkle_path(self.leaves.len() - 1);

		Ok(())
	}

	pub(crate) fn insert_batch(&mut self, leaves: Vec<H::Digest>) -> MerkleTreeResult<()> {
		let batch_size: usize = leaves.len();

		if !self.num_leaves().is_multiple_of(batch_size) {
			return Err(anyhow!(MerkleTreeError::InvalidBatch(format!(
				"batch_size: {batch_size} does not divide leaves: {}",
				self.num_leaves()
			))));
		}

		if self.num_leaves() >= 1 << self.depth() {
			return Err(anyhow!(MerkleTreeError::FullTree()));
		}

		self.leaves.extend(leaves);
		self.update_consecutive_paths(self.num_leaves() - batch_size, batch_size)?;

		Ok(())
	}

	#[allow(dead_code)]
	/// Update Merkle paths for a consecutive range of leaf indices.
	///
	/// This method updates all ancestors of leaves in `[start, start + batch_size)`
	/// in a lazy, append-only Merkle tree.
	///
	/// Semantics:
	/// - If a leaf exists, its stored hash is used.
	/// - If a leaf does not exist, `H::HEAD` is used.
	/// - If a node in an upper layer does not yet exist, it is appended.
	/// - Missing siblings are filled using `self.default_siblings[level]`.
	pub(crate) fn update_consecutive_paths(
		&mut self,
		start: usize,
		batch_size: usize,
	) -> MerkleTreeResult<()> {
		let depth = self.depth();
		let num_leaves = self.leaves.len();

		if start + batch_size > 1 << depth {
			return Err(anyhow!(MerkleTreeError::IndexError(
				"IndexError: start+batch_size > 1<<depth".to_string()
			)));
		}

		let mut cur_start = start;
		let mut cur_end = start + batch_size;

		for level in 0..depth {
			// Split layers so prev_layer and layer are disjoint
			let (lower, rest) = self.layers.split_at_mut(level);
			let layer = &mut rest[0];

			let prev_layer: Option<&Vec<H::Digest>> = if level == 0 {
				None
			} else {
				Some(&lower[level - 1])
			};

			for pos in cur_start..cur_end {
				let parent = pos >> 1;
				let is_right = (pos & 1) == 1;

				// -----------------------------
				// Current hash
				// -----------------------------
				let current_hash: H::Digest = match prev_layer {
					None => {
						if pos < self.leaves.len() {
							self.leaves[pos]
						} else {
							H::HEAD
						}
					},
					Some(prev) => {
						if pos < prev.len() {
							prev[pos]
						} else {
							H::HEAD
						}
					},
				};

				// -----------------------------
				// Sibling hash
				// -----------------------------
				let sibling_pos = if is_right { pos - 1 } else { pos + 1 };

				let sibling_hash: H::Digest = match prev_layer {
					None => {
						if sibling_pos < self.leaves.len() {
							self.leaves[sibling_pos]
						} else {
							self.default_siblings[level]
						}
					},
					Some(prev) => {
						if sibling_pos < prev.len() {
							prev[sibling_pos]
						} else {
							self.default_siblings[level]
						}
					},
				};

				// -----------------------------
				// Parent hash
				// -----------------------------
				// At the final level (root), use hash_root to commit num_leaves
				let parent_hash = if level == depth - 1 {
					let (left, right) = if is_right {
						(&sibling_hash, &current_hash)
					} else {
						(&current_hash, &sibling_hash)
					};
					H::hash_root(num_leaves, left, right)
				} else {
					H::hash_2_to_1(&current_hash, &sibling_hash, is_right)
				};

				// -----------------------------
				// Write or append
				// -----------------------------
				if parent < layer.len() {
					layer[parent] = parent_hash;
				} else {
					debug_assert_eq!(parent, layer.len());
					layer.push(parent_hash);
				}
			}

			// Move to parent range
			cur_start >>= 1;
			cur_end = (cur_end + 1) >> 1;
		}

		Ok(())
	}

	#[allow(dead_code)]
	/// Update Merkle paths for multiple indices efficiently.
	/// This ensures consistency when indices share common ancestors.
	pub(crate) fn update_sparse_paths(&mut self, indices: &[usize]) {
		use std::collections::BTreeSet;

		if indices.is_empty() {
			return;
		}

		// Track active positions at each level
		let mut active: BTreeSet<usize> = indices.iter().copied().collect();

		for level in 0..self.depth() {
			// Update hashes for all active positions at this level
			for &pos in active.iter() {
				let parent: usize = pos >> 1;
				let is_right: bool = (pos & 1) == 1;

				// Get current hash at this position
				let current_hash: H::Digest = if level == 0 {
					self.leaves[pos]
				} else {
					self.layers[level - 1][pos]
				};

				// Get sibling hash
				let sibling_hash: H::Digest = if level == 0 {
					if is_right {
						self.leaves[pos - 1]
					} else if pos + 1 < self.leaves.len() {
						self.leaves[pos + 1]
					} else {
						self.default_siblings[0]
					}
				} else {
					let prev_layer: &Vec<H::Digest> = &self.layers[level - 1];
					if is_right {
						prev_layer[pos - 1]
					} else if pos + 1 < prev_layer.len() {
						prev_layer[pos + 1]
					} else {
						self.default_siblings[level]
					}
				};

				// Compute parent hash
				// At the final level (root), use hash_root to commit num_leaves
				let parent_hash = if level == self.depth() - 1 {
					let (left, right) = if is_right {
						(&sibling_hash, &current_hash)
					} else {
						(&current_hash, &sibling_hash)
					};
					H::hash_root(self.leaves.len(), left, right)
				} else {
					H::hash_2_to_1(&current_hash, &sibling_hash, is_right)
				};

				// Write parent hash
				let layer: &mut Vec<H::Digest> = &mut self.layers[level];
				if parent < layer.len() {
					layer[parent] = parent_hash;
				} else {
					debug_assert_eq!(parent, layer.len());
					layer.push(parent_hash);
				}
			}

			// Move to parent level
			if level + 1 < self.depth() {
				let mut parents: BTreeSet<usize> = BTreeSet::new();
				for &pos in active.iter() {
					parents.insert(pos >> 1);
				}
				active = parents;
			}
		}
	}
}
