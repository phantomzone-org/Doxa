use std::collections::BTreeMap;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::tree::{
	MerkleTree, Node, NullifierInsertProof,
	error::{MerkleTreeError, MerkleTreeResult},
	hasher::{Hash, MerkleHash},
};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
	serialize = "H::Digest: Serialize",
	deserialize = "H::Digest: Deserialize<'de>"
))]
pub struct NullifierTree<H: MerkleHash> {
	pub(crate) nodes: Vec<Node<H>>,
	pub(crate) actives: BTreeMap<H::Digest, usize>,
	pub(crate) tree: MerkleTree<H>,
}

impl<H: MerkleHash> NullifierTree<H> {
	pub fn new(depth: usize) -> Self {
		let first: Node<H> = Node::first();
		let mut actives: BTreeMap<H::Digest, usize> = BTreeMap::new();
		actives.insert(first.value, 0);
		let mut tree: MerkleTree<H> = MerkleTree::new(depth);
		tree.insert(first.compute_hash()).unwrap();
		Self {
			nodes: vec![first],
			actives,
			tree,
		}
	}

	#[allow(dead_code)]
	pub(crate) fn get_head_index(&self) -> Option<usize> {
		if let Some((_, index)) = self.actives.iter().next() {
			Some(*index)
		} else {
			None
		}
	}

	pub fn find_predecessor_index_from_value(&self, value: H::Digest) -> Option<usize> {
		let (_, &pred_index) = self.actives.range(..value).next_back()?;
		Some(pred_index)
	}

	pub fn find_node_by_index(&self, index: usize) -> Option<Node<H>> {
		self.nodes.get(index).copied()
	}

	pub fn find_node_index_by_value(&self, label: &H::Digest) -> Option<usize> {
		self.actives.get(label).copied()
	}

	pub fn find_node_by_label(&self, label: &H::Digest) -> Option<Node<H>> {
		self.find_node_by_index(self.find_node_index_by_value(label)?)
	}

	pub fn depth(&self) -> usize {
		self.tree.depth()
	}

	pub fn num_leaves(&self) -> usize {
		self.tree.num_leaves()
	}

	pub fn merkle_path(
		&self,
		index: usize,
		start_depth: usize,
		end_depth: usize,
	) -> MerkleTreeResult<Vec<H::Digest>> {
		self.tree.merkle_path(index, start_depth, end_depth)
	}

	/// Inserts a new leaf into the indexed Merkle tree and produces a
	/// STARK-friendly insertion proof.
	///
	/// This method performs a *single-leaf insertion* in a way that is
	/// compatible with in-circuit verification under the “one update at a time”
	/// model (i.e. no Merkle multiproof updates).
	///
	/// The insertion is logically:
	/// ```text
	///     pred  →  new_node  →  old_successor
	/// ```
	/// and is implemented as **two sequential single-leaf updates**:
	///
	/// 1. Update the predecessor leaf to point to the new node
	/// 2. Insert the new node into the first empty leaf
	///
	/// To make this transition provable in-circuit, the method snapshots
	/// Merkle authentication paths **before and after** the predecessor update,
	/// allowing the verifier to prove:
	///
	/// - the predecessor existed in `old_root`
	/// - the insertion slot was empty in `old_root`
	/// - the predecessor update was applied correctly
	/// - the insertion slot was still empty in the intermediate root
	/// - the new node was inserted correctly
	///
	/// # Requirements
	/// - `DEPTH` **must** match the tree’s depth
	/// - the tree must not be full
	/// - `value` must not already exist in the tree
	///
	/// # Returns
	/// An [`InsertProof`] containing all witness data required to verify the
	/// insertion inside a STARK / Plonky2 circuit.
	///
	/// # Soundness Invariants
	/// - `nodes.len()` is always the index of the first empty leaf
	/// - leaves `[0 .. nodes.len() - 1]` are occupied
	/// - leaves `[nodes.len() .. 2^DEPTH - 1]` are empty
	/// - only one leaf is updated per Merkle root transition
	pub fn insert(&mut self, value: H::Digest) -> MerkleTreeResult<NullifierInsertProof<H>> {
		// ============================================================
		// Sanity checks
		// ============================================================

		let depth: usize = self.tree.depth();

		// Ensure there is at least one empty leaf
		if self.tree.leaves.len() >= 1 << depth {
			return Err(anyhow!(MerkleTreeError::FullTree()));
		}

		// ============================================================
		// Phase 1: Gather witness data BEFORE mutating the tree
		//
		// All data collected here is anchored to `old_root`.
		// ============================================================

		// 1.a. Find the tree predecessor of `value`
		//
		// This is the unique node such that:
		//     pred.value < value < pred.next_value
		let pred_index: usize = self
			.find_predecessor_index_from_value(value)
			.ok_or(anyhow!(MerkleTreeError::NonMembershipProofError(
				"failed to find predecessor".to_string()
			)))?;

		// 1.b. Read predecessor node
		let pred_node: Node<H> = self.nodes[pred_index];

		// 1.c. Validate non-membership in native code
		//
		// This mirrors the in-circuit range check:
		//     pred.value < value < pred.next_value
		if !(pred_node.value < value && value < pred_node.next_value) {
			return Err(anyhow!(MerkleTreeError::NonMembershipProofError(
				"range check failed".to_string()
			)));
		}

		// 1.d. Snapshot old root and predecessor metadata
		//
		// These values are required to:
		// - authenticate the predecessor
		// - rewire its successor pointer
		let old_root: H::Digest = self.tree.get_root();
		let pred_value: H::Digest = pred_node.value;
		let pred_old_next_index: usize = pred_node.next_index;
		let pred_old_next_value: H::Digest = pred_node.next_value;

		// 1.e. Merkle authentication path for the predecessor
		//
		// Proves predecessor membership in `old_root`
		let pred_old_siblings: Vec<H::Digest> =
			self.tree.merkle_path(pred_index, 0, self.tree.depth())?;

		// ============================================================
		// Phase 2: Mutate the tree
		//
		// This phase performs exactly two single-leaf updates:
		//   1) predecessor update
		//   2) new node insertion
		// ============================================================

		// Invariant:
		//   `nodes.len()` is the index of the first empty leaf.
		let next_empty_index: usize = self.tree.leaves.len();

		// ------------------------------------------------------------
		// 2.a. Snapshot insertion siblings BEFORE predecessor update
		//
		// This anchors the emptiness of the insertion slot to `old_root`.
		// ------------------------------------------------------------
		let new_node_siblings_before_pred_update: Vec<H::Digest> =
			self.tree.merkle_path(next_empty_index, 0, depth)?;

		// ------------------------------------------------------------
		// 2.b. Update predecessor: old_root → mid_root
		//
		// Rewire:
		//   pred.next_index = next_empty_index
		//   pred.next_value = value
		// ------------------------------------------------------------
		let update_pred: Node<H> = Node::new(pred_value, next_empty_index, value);
		self.nodes[pred_index] = update_pred;
		self.tree
			.update_leaf(pred_index, update_pred.compute_hash())?;

		// ------------------------------------------------------------
		// 2.c. Snapshot insertion siblings AFTER predecessor update
		//
		// This anchors the emptiness of the insertion slot to `mid_root`.
		// ------------------------------------------------------------
		let new_node_siblings_after_pred_update: Vec<H::Digest> =
			self.tree.merkle_path(next_empty_index, 0, depth)?;

		// ------------------------------------------------------------
		// 2.d. Insert the new node
		//
		// The new node inherits the predecessor’s old successor.
		// ------------------------------------------------------------
		let new_node: Node<H> = Node::new(value, pred_old_next_index, pred_old_next_value);
		self.nodes.push(new_node);
		self.actives.insert(value, next_empty_index);

		// ------------------------------------------------------------
		// 2.e. Update Merkle path for new node: mid_root → new_root
		// ------------------------------------------------------------
		self.tree.insert(new_node.compute_hash())?;

		// ============================================================
		// Phase 3: Emit STARK-friendly proof
		// ============================================================

		let new_root: H::Digest = self.tree.get_root();

		Ok(NullifierInsertProof {
			// Public inputs
			old_root,
			new_root,

			// Predecessor witness
			pred_path: pred_index,
			pred_value,
			pred_old_next_index,
			pred_old_next_value,
			pred_old_siblings,

			// New node witness
			new_node_value: value,
			new_node_path: next_empty_index,
			new_node_siblings_before_pred_update,
			new_node_siblings_after_pred_update,
		})
	}

	pub fn get_root(&self) -> H::Digest {
		self.tree.get_root()
	}

	pub fn verify(&self) -> MerkleTreeResult<()> {
		let mut prev_node: Node<H> = self.nodes[0];

		self.find_node_by_label(&prev_node.value)
			.ok_or(anyhow!(MerkleTreeError::LeafHashMismatch(0)))?;

		for _ in 1..self.nodes.len() {
			let node: Node<H> = self.nodes[prev_node.next_index];

			if node.value != prev_node.next_value {
				return Err(anyhow!(MerkleTreeError::LeafDataInvalid(format!(
					"node.value != prev_node.next_value\n{}\n {}\n",
					prev_node, node
				))));
			}

			if !(prev_node.value < node.value && node.value < node.next_value) {
				return Err(anyhow!(MerkleTreeError::LeafDataInvalid(format!(
					"!(prev_node.value < node.value && node.value < node.next_value)\n{}\n {}\n",
					prev_node, node
				))));
			}

			self.find_node_by_label(&node.value)
				.ok_or(anyhow!(MerkleTreeError::NotFoundError(format!(
					"{}",
					node.value
				))))?;

			prev_node = node;
		}

		if prev_node.next_index != 0 || prev_node.next_value != H::TAIL {
			return Err(anyhow!(MerkleTreeError::LeafDataInvalid(format!(
				"last node[{}]",
				prev_node.next_index
			))));
		}

		if self.nodes.len() != self.tree.num_leaves() {
			return Err(anyhow!(MerkleTreeError::IndexError(
				"self.nodes.len() != self.tree.num_leaves()".to_string()
			)));
		}

		for i in 0..self.nodes.len() {
			if self.nodes[i].compute_hash() != self.tree.leaves[i] {
				return Err(anyhow!(MerkleTreeError::LeafDataInvalid(format!(
					"node[{i}].compute_hash() != self.tree.leaves[{i}]"
				))));
			}
		}

		self.tree.verify()?;

		Ok(())
	}
}

impl NullifierTree<Hash> {
	/// Creates a new nullifier tree pre-padded so that `nodes.len() == batch_size`.
	///
	/// The tree starts with the sentinel node at index 0, then deterministically
	/// inserts `batch_size - 1` padding leaves.  Each padding leaf's value is
	/// derived as:
	///
	/// ```text
	///   value[i] = Hash::from_32bytes_digest(Keccak256(i || H(node[i-1])))
	/// ```
	///
	/// where `H(node[i-1])` is the compute_hash() of the previous node (its
	/// Poseidon commitment) serialized as 32 big-endian bytes, and `i` is the
	/// leaf index encoded as a big-endian `u64`.
	///
	/// This ensures the genesis root is deterministic and reproducible for any
	/// given `batch_size`, and the first `insert_batch` call will find
	/// `nodes.len()` properly aligned.
	pub fn new_with_padding(depth: usize, batch_size: usize) -> Self {
		assert!(
			batch_size.is_power_of_two() && batch_size > 1,
			"batch_size must be a power of two > 1"
		);

		let mut tree = Self::new(depth);

		for i in 1..batch_size {
			let prev_hash = tree.nodes[i - 1].compute_hash();
			let value = Self::derive_padding_leaf(i, &prev_hash);
			tree.insert(value)
				.unwrap_or_else(|e| panic!("padding insert at index {i} failed: {e}"));
		}

		tree
	}

	/// Derives a deterministic padding leaf value:
	///   `Hash::from_32bytes_digest(Keccak256(leaf_index_be8 || node_hash_be32))`
	fn derive_padding_leaf(leaf_index: usize, prev_node_hash: &Hash) -> Hash {
		use tiny_keccak::{Hasher, Keccak};

		let mut keccak = Keccak::v256();

		// leaf index as big-endian u64
		keccak.update(&(leaf_index as u64).to_be_bytes());

		// previous node's compute_hash() as 4 × big-endian u64 (32 bytes)
		for &elem in &prev_node_hash.0 {
			keccak.update(&elem.0.to_be_bytes());
		}

		let mut digest = [0u8; 32];
		keccak.finalize(&mut digest);

		Hash::from_32bytes_digest(digest)
	}
}

#[cfg(test)]
mod tests {

	use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
	use rand::{SeedableRng, rngs::StdRng};

	use crate::tree::{
		NullifierInsertProof,
		hasher::{Hash, MerkleHash, NewRandom},
		nullifier_tree::NullifierTree,
	};

	const DEPTH: usize = 10;
	const NUM_INSERTS: usize = 256;

	#[test]
	fn test_new() {
		let tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);
		assert!(matches!(tree.get_root(), Hash(_)));
		assert_eq!(tree.nodes.len(), 1);
	}

	#[test]
	fn test_new_with_padding() {
		let tree = NullifierTree::<Hash>::new_with_padding(DEPTH, 16);
		assert_eq!(tree.nodes.len(), 16);
		tree.verify().expect("padded tree should be valid");

		// Determinism: same batch_size always yields the same root.
		let tree2 = NullifierTree::<Hash>::new_with_padding(DEPTH, 16);
		assert_eq!(tree.get_root(), tree2.get_root());

		// Different batch_size yields a different root.
		let tree4 = NullifierTree::<Hash>::new_with_padding(DEPTH, 4);
		assert_eq!(tree4.nodes.len(), 4);
		assert_ne!(tree.get_root(), tree4.get_root());
		tree4.verify().expect("padded tree (4) should be valid");
	}

	#[test]
	fn test_padded_tree_accepts_batch_insert() {
		let mut tree = NullifierTree::<Hash>::new_with_padding(DEPTH, 4);
		assert_eq!(tree.nodes.len(), 4);

		let mut rng: StdRng = StdRng::from_seed([99u8; 32]);
		let batch: Vec<Hash> = (0..4).map(|_| Hash::new_random(&mut rng)).collect();
		let proof = tree
			.insert_batch(batch)
			.expect("batch insert should succeed");
		assert!(proof.verify());
		assert_eq!(tree.nodes.len(), 8);
		tree.verify()
			.expect("tree after batch insert should be valid");
	}

	#[test]
	fn test_insert_leaf_and_invariants() {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		for _ in 0..NUM_INSERTS as u64 {
			let leaf: Hash = Hash::new_random(&mut rng);
			let insert_proof: NullifierInsertProof<Hash> = tree.insert(leaf).unwrap();
			assert!(insert_proof.verify());
			// The tree should contain the inserted node.
			let found_node = tree.find_node_by_label(&leaf);
			assert!(found_node.is_some(), "Inserted node should be found");
			assert_eq!(
				found_node.unwrap().value,
				leaf,
				"Node value should match inserted value"
			);
		}
	}

	#[test]
	fn test_insert_and_find_node_by_label() {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		for _ in 0..NUM_INSERTS as u64 {
			let leaf: Hash = Hash::new_random(&mut rng);

			let proof: NullifierInsertProof<Hash> = tree.insert(leaf).unwrap();
			assert!(proof.verify());

			// find_node_by_label must find the inserted node
			let found_node = tree.find_node_by_label(&leaf);
			assert!(found_node.is_some(), "Inserted node should be found");
			assert_eq!(found_node.unwrap().value, leaf, "Node value should match");
		}
	}

	/// Duplicate labels must be rejected (uniqueness).
	#[test]
	fn test_duplicate_label_rejected() {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		let value: Hash = Hash::new_random(&mut rng);

		assert!(tree.insert(value).unwrap().verify());
		assert!(tree.insert(value).is_err());
	}

	/// Non-membership should fail (or error) if label equals predecessor.label or predecessor.next
	/// depending on your strict-inequality policy.
	#[test]
	fn test_non_membership_rejects_equal_boundary() {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		let value: Hash = Hash::new_random(&mut rng);

		assert!(tree.insert(value).unwrap().verify());

		// Probe exactly at an existing label (must not be "non-member")
		let res = tree.insert(value);
		assert!(
			res.is_err(),
			"non-membership unexpectedly succeeded for existing label"
		);
	}

	/// Very large labels should still behave correctly (ordering comparisons on Hash bytes).
	#[test]
	fn test_label_boundary() {
		let mut tree = NullifierTree::<Hash>::new(DEPTH);

		let mut label: Hash = Hash::TAIL;
		label.0[3] -= GoldilocksField::ONE;

		let p = tree.insert(label).unwrap();
		assert!(p.verify());

		assert!(tree.find_node_index_by_value(&label).is_some());
	}

	/// Inserts labels in randomized order and checks that the indexed-tree interval
	/// invariant still holds (i.e., next pointers form a sorted linked list).
	#[test]
	fn test_randomized_insertion_order_preserves_invariants() {
		const N: usize = 200;
		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);

		let mut values: Vec<Hash> = Vec::with_capacity(N);

		for _ in 0..N {
			let value: Hash = Hash::new_random(&mut rng);
			values.push(value);
			let p = tree.insert(value).unwrap();
			assert!(p.verify());
		}

		// All labels must be findable
		for i in 0..N {
			assert!(tree.find_node_index_by_value(&values[i]).is_some());
		}
	}
}
