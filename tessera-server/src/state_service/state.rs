use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Context;
use tessera_trees::{MerkleProof, MerkleTree};
use tessera_utils::hasher::HashOutput;

use crate::contract;

/// In-memory mirror of the on-chain IMT (Incremental Merkle Tree).
///
/// Holds the full tree, a commitment→index lookup map, the set of spent
/// nullifiers, and the set of confirmed roots. All mutation goes through
/// the typed methods below; none of them perform I/O.
pub struct StateSnapshot {
	/// The full Poseidon Merkle tree, mirroring the on-chain structure.
	tree: MerkleTree<HashOutput>,
	/// Maps every known leaf commitment (raw `[u8; 32]`) to its position in
	/// the tree. Populated in lock-step with `tree`.
	leaf_index: HashMap<[u8; 32], usize>,
	/// Set of all nullifiers that have been spent on-chain.
	nullifiers: HashSet<[u8; 32]>,
	/// Set of all roots that have been confirmed on-chain (i.e. returned by
	/// a `*BatchProven` event's `newTreeRoot` field).
	///
	/// Uses [`BTreeSet`] because [`HashOutput`] implements [`Ord`] but not
	/// [`std::hash::Hash`], consistent with how the sequencer stores roots.
	confirmed_roots: BTreeSet<HashOutput>,
}

impl StateSnapshot {
	/// Allocate an empty [`StateSnapshot`] for a tree of the given `depth`.
	///
	/// `depth` must equal the on-chain `treeDepth()` value (typically 32).
	pub fn new(depth: usize) -> Self {
		Self {
			tree: MerkleTree::new(depth),
			leaf_index: HashMap::new(),
			nullifiers: HashSet::new(),
			confirmed_roots: BTreeSet::new(),
		}
	}

	// -----------------------------------------------------------------------
	// Mutation
	// -----------------------------------------------------------------------

	/// Append `commitment` to the tree as the next leaf and record its index.
	///
	/// Returns the zero-based leaf index assigned to this commitment.
	///
	/// # Errors
	/// Propagates any error from [`MerkleTree::insert`] (e.g. tree full).
	pub fn insert_leaf(&mut self, commitment: [u8; 32]) -> anyhow::Result<usize> {
		let leaf = contract::bytes32_to_hash(&alloy::primitives::B256::from(commitment))
			.context("commitment is not a valid Goldilocks hash")?;
		let index = self
			.tree
			.insert(leaf)
			.map_err(|e| anyhow::anyhow!("failed to insert leaf: {e}"))?;
		self.leaf_index.insert(commitment, index);
		Ok(index)
	}

	/// Record `nullifier` as spent.
	///
	/// Idempotent: inserting the same nullifier twice is a no-op.
	pub fn insert_nullifier(&mut self, nullifier: [u8; 32]) {
		self.nullifiers.insert(nullifier);
	}

	/// Mark `root` as confirmed on-chain.
	///
	/// Idempotent: confirming the same root twice is a no-op.
	pub fn confirm_root(&mut self, root: HashOutput) {
		self.confirmed_roots.insert(root);
	}

	// -----------------------------------------------------------------------
	// Queries
	// -----------------------------------------------------------------------

	/// Return the zero-based tree index for `commitment`, or `None` if
	/// `commitment` has never been inserted.
	pub fn leaf_index(&self, commitment: &[u8; 32]) -> Option<usize> {
		self.leaf_index.get(commitment).copied()
	}

	/// Return the full [`MerkleProof`] for the leaf at `index`.
	///
	/// The proof contains the leaf value, all siblings from depth 0 to the
	/// root, the direction bits, and the current root.
	///
	/// # Errors
	/// Returns `Err` if `index` is out of range.
	pub fn siblings(&self, index: usize) -> anyhow::Result<MerkleProof<HashOutput>> {
		self.tree
			.merkle_proof(index)
			.map_err(|e| anyhow::anyhow!("merkle_proof({index}): {e}"))
	}

	/// Return `true` if `nullifier` has been recorded as spent.
	pub fn contains_nullifier(&self, nullifier: &[u8; 32]) -> bool {
		self.nullifiers.contains(nullifier)
	}

	/// Return `true` if `root` is in the confirmed-root set.
	pub fn is_confirmed_root(&self, root: &HashOutput) -> bool {
		self.confirmed_roots.contains(root)
	}

	/// Return the current Poseidon root of the local tree.
	pub fn root(&self) -> HashOutput {
		self.tree.root()
	}

	/// Return the number of leaves currently in the tree.
	pub fn leaf_count(&self) -> usize {
		self.tree.num_leaves()
	}
}
