use crate::tree::hasher::MerkleHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
	bound(
		serialize = "H::Digest: Serialize",
		deserialize = "H::Digest: Deserialize<'de>"
	)
)]
pub struct NullifierInsertProof<H: MerkleHash> {
	// ============ PUBLIC INPUTS ============
	/// Initial tree root (before insertion)
	pub old_root: H::Digest,
	/// Final tree root (after insertion)
	pub new_root: H::Digest,

	// ============ PRIVATE WITNESSES ============

	// --- Predecessor node data ---
	/// Old predecessor path direction bits (true = right child)
	pub pred_path: usize,
	/// Old predecessor value
	pub pred_value: H::Digest,
	/// Old predecessor next index
	pub pred_old_next_index: usize,
	/// Old predecessor next pointer (points to successor before insertion)
	pub pred_old_next_value: H::Digest,
	/// Merkle path siblings for predecessor position
	pub pred_old_siblings: Vec<H::Digest>,

	// --- New node data ---
	/// New node path direction bits for insertion position (true = right child)
	pub new_node_path: usize,
	/// New node value (the key being inserted)
	pub new_node_value: H::Digest,
	/// Merkle path siblings for insertion position
	pub new_node_siblings_before_pred_update: Vec<H::Digest>,
	pub new_node_siblings_after_pred_update: Vec<H::Digest>,
}

impl<H: MerkleHash> NullifierInsertProof<H> {
	/// Verifies a single-leaf insertion proof for an indexed Merkle tree.
	///
	/// This verifier checks a *two-step root transition*:
	///
	/// ```text
	///                   ┌────────────────────────────┐
	///                   │          old_root          │
	///                   └────────────────────────────┘
	///                       ▲                    ▲
	///                       │                    │
	///  pred_path + siblings │                    │ new_node_path + siblings (before)
	///                       │                    │
	///             ┌─────────┴─────────┐  ┌───────┴─────────┐
	///             │  old_pred_hash    │  │   EMPTY LEAF    │
	///             │  = commit(pred)   │  │   (HEAD)        │
	///             └───────────────────┘  └─────────────────┘
	///                       │
	///                       │  (single-leaf update:
	///                       │   change pred leaf only)
	///                       ▼
	///                   ┌────────────────────────────┐
	///                   │          mid_root          │
	///                   └────────────────────────────┘
	///                       ▲                    ▲
	///                       │                    │
	///  pred_path + siblings │                    │ new_node_path + siblings (after)
	///                       │                    │
	///             ┌─────────┴─────────┐  ┌───────┴─────────┐
	///             │  new_pred_hash    │  │   EMPTY LEAF    │
	///             │ = commit(pred → x)│  │   (HEAD)        │
	///             └───────────────────┘  └─────────────────┘
	///                                            │
	///                                            │ (single-leaf update:
	///                                            │  insert new node)
	///                                            ▼
	///                  ┌────────────────────────────┐
	///                  │          new_root          │
	///                  └────────────────────────────┘
	///                                ▲
	///                                │
	///                  new_node_path + siblings (after)
	///                                │
	///                     ┌──────────┴────────────┐
	///                     │   new_node_hash       │
	///                     │ = commit(x → old_succ)│
	///                     └───────────────────────┘
	/// ```
	/// The proof is sound under the following guarantees:
	/// - the predecessor existed in `old_root`
	/// - the insertion slot was empty in `old_root`
	/// - only the predecessor leaf was modified to obtain `mid_root`
	/// - the insertion slot remained empty in `mid_root`
	/// - only the insertion slot was modified to obtain `new_root`
	/// - the ordering invariant `pred.value < new_value < pred.old_next_value` holds
	///
	/// No Merkle multiproofs are required; correctness follows from
	/// explicit root chaining and single-leaf updates.
	pub fn verify(&self) -> bool {
		assert_eq!(
			self.new_node_siblings_after_pred_update.len(),
			self.new_node_siblings_before_pred_update.len()
		);

		if self.new_node_path + 1 > 1 << self.depth() {
			return false;
		}

		if self.pred_path > 1 << self.depth() {
			return false;
		}

		// Canonical empty leaf hash used by the tree.
		// This must exactly match the empty leaf used natively and in-circuit.
		let empty_hash: H::Digest = H::HEAD;

		// ============================================================
		// Step 1: Authenticate predecessor in old_root
		//
		// Proves that the predecessor leaf existed in the committed
		// pre-state and had the claimed successor pointers.
		// ============================================================

		let old_pred_hash: H::Digest = H::commit_node(
			&self.pred_value,
			self.pred_old_next_index,
			&self.pred_old_next_value,
		);

		let computed_old_root_from_pred: H::Digest = Self::compute_root(
			&old_pred_hash,
			&self.pred_old_siblings,
			self.pred_path,
			self.new_node_path,
		);

		// ============================================================
		// Step 2: Authenticate emptiness of insertion slot in old_root
		//
		// Proves that the insertion index was empty *before* any update.
		// ============================================================

		let computed_old_root_from_empty: H::Digest = Self::compute_root(
			&empty_hash,
			&self.new_node_siblings_before_pred_update,
			self.new_node_path,
			self.new_node_path,
		);

		// Both facts must hold in the same committed pre-state.
		if computed_old_root_from_pred != self.old_root
			|| computed_old_root_from_empty != self.old_root
		{
			return false;
		}

		// ============================================================
		// Step 3: Update predecessor → mid_root
		//
		// Rewires:
		//   pred.next_index = new_node_index
		//   pred.next_value = new_node_value
		//
		// This is a *single-leaf update* from old_root → mid_root.
		// The tree size hasn't changed yet (just updating existing node).
		// ============================================================

		let new_pred_hash: H::Digest =
			H::commit_node(&self.pred_value, self.new_node_path, &self.new_node_value);

		let mid_root: H::Digest = Self::compute_root(
			&new_pred_hash,
			&self.pred_old_siblings,
			self.pred_path,
			self.new_node_path,
		);

		// ============================================================
		// Step 4: Re-authenticate emptiness in mid_root
		//
		// Ensures the predecessor update did not affect the insertion slot.
		// Still using new_node_path since no new node inserted yet.
		// ============================================================

		let computed_mid_root: H::Digest = Self::compute_root(
			&empty_hash,
			&self.new_node_siblings_after_pred_update,
			self.new_node_path,
			self.new_node_path,
		);

		if computed_mid_root != mid_root {
			return false;
		}

		// ============================================================
		// Step 5: Insert new node → new_root
		//
		// The new node inherits the predecessor's old successor pointers:
		//   new.next_index = pred.old_next_index
		//   new.next_value = pred.old_next_value
		// Now tree size increases to num_leaves_new.
		// ============================================================

		let new_node_hash: H::Digest = H::commit_node(
			&self.new_node_value,
			self.pred_old_next_index,
			&self.pred_old_next_value,
		);

		let computed_new_root: H::Digest = Self::compute_root(
			&new_node_hash,
			&self.new_node_siblings_after_pred_update,
			self.new_node_path,
			self.new_node_path + 1,
		);

		if computed_new_root != self.new_root {
			return false;
		}

		// ============================================================
		// Step 6: Ordering / non-membership check
		//
		// Enforces that the new value fits strictly between the
		// predecessor and its former successor.
		// ============================================================

		self.new_node_value > self.pred_value && self.new_node_value < self.pred_old_next_value
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

	/// Returns the initial root (public input).
	pub fn old_root(&self) -> H::Digest {
		self.old_root
	}

	/// Returns the final root (public input).
	pub fn new_root(&self) -> H::Digest {
		self.new_root
	}

	pub fn depth(&self) -> usize {
		self.pred_old_siblings.len()
	}
}
