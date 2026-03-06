use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use tessera_trees::tree::{hasher::Hash, CommitmentTree, NullifierTree};

use crate::TREE_DEPTH;

/// Canonical sort key for sequencing on-chain events in arrival order.
///
/// Three-level sort (block → tx → log) matches the EVM log ordering guarantee:
/// events within a block are ordered by transaction position, and within a
/// transaction by log emission order.
///
/// On the API path (no on-chain event), `block_number` and `transaction_index`
/// are set to 0 and `log_index` is filled from a monotonically-increasing
/// counter (`api_order_counter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventOrderKey {
	pub block_number: u64,
	pub transaction_index: u64,
	pub log_index: u64,
}

/// A leaf that has been accepted but not yet included in a proving batch.
///
/// Stored in `pending_requests` (keyed by [`EventOrderKey`]) and mirrored in
/// `pending_commitments` for O(1) duplicate detection.
#[derive(Debug, Clone)]
pub struct PendingRequest {
	pub order_key: EventOrderKey,
	pub commitment: [u8; 32],
}

/// Trait abstracting over commitment and nullifier tree insertion behavior.
///
/// The sequencer manages four trees that differ only in their insertion
/// method (`insert_batch` vs `insert_chained`) and proof-verification
/// pattern.  This trait captures the common surface needed by
/// [`TreeState`], WAL replay, and chain recovery.
pub trait SequencerTree: Sized {
	fn new(depth: usize) -> Self;
	fn get_root(&self) -> Hash;
	fn num_leaves(&self) -> usize;
	/// Insert leaves, verify the resulting proof, and return the new root.
	fn insert_verified(&mut self, leaves: Vec<Hash>) -> Result<Hash>;
	/// Apply fixups needed after loading a legacy snapshot. Default: no-op.
	fn fixup_legacy_snapshot(&mut self, _snapshot_version: u32) {}
}

impl SequencerTree for CommitmentTree<Hash> {
	fn new(depth: usize) -> Self {
		CommitmentTree::new(depth)
	}

	fn get_root(&self) -> Hash {
		self.get_root()
	}

	fn num_leaves(&self) -> usize {
		self.num_leaves()
	}

	fn insert_verified(&mut self, leaves: Vec<Hash>) -> Result<Hash> {
		let proof = self.insert_batch(leaves)?;
		anyhow::ensure!(proof.verify(), "commitment tree proof verification failed");
		Ok(proof.root_new)
	}

	fn fixup_legacy_snapshot(&mut self, snapshot_version: u32) {
		if snapshot_version < 2 {
			self.rebuild_leaf_counts();
		}
	}
}

impl SequencerTree for NullifierTree<Hash> {
	fn new(depth: usize) -> Self {
		NullifierTree::new(depth)
	}

	fn get_root(&self) -> Hash {
		self.get_root()
	}

	fn num_leaves(&self) -> usize {
		self.num_leaves()
	}

	fn insert_verified(&mut self, leaves: Vec<Hash>) -> Result<Hash> {
		let proof = self.insert_chained(leaves)?;
		anyhow::ensure!(proof.verify(), "nullifier tree proof verification failed");
		proof
			.proofs
			.last()
			.map(|p| p.new_root)
			.ok_or_else(|| anyhow::anyhow!("nullifier proof contains no insertions"))
	}
}

/// Sequencer in-memory state for one tree's pending-request queue.
///
/// Generic over the tree type (`CommitmentTree<Hash>` or
/// `NullifierTree<Hash>`) via [`SequencerTree`].  All queue-management
/// logic is tree-type-agnostic.
pub struct TreeState<T: SequencerTree> {
	/// Local tree mirror.
	pub tree: T,
	/// Pending consume requests keyed by canonical chain order.
	pub pending_requests: BTreeMap<EventOrderKey, PendingRequest>,
	/// Fast duplicate guard for pending requests.
	pub pending_commitments: HashSet<[u8; 32]>,
}

impl<T: SequencerTree> Default for TreeState<T> {
	fn default() -> Self {
		Self::new()
	}
}

impl<T: SequencerTree> TreeState<T> {
	/// Create a new, empty tree state.
	pub fn new() -> Self {
		Self {
			tree: T::new(TREE_DEPTH),
			pending_requests: BTreeMap::new(),
			pending_commitments: HashSet::new(),
		}
	}

	/// Return the tree's genesis root (empty tree root).
	pub fn genesis_root() -> Hash {
		T::new(TREE_DEPTH).get_root()
	}

	/// Return current local root.
	pub fn current_root(&self) -> Hash {
		self.tree.get_root()
	}

	/// Replay one commitment into the local tree.
	pub fn replay_consumed_commitment(&mut self, commitment: Hash) -> Result<()> {
		self.tree.insert_verified(vec![commitment])?;
		Ok(())
	}

	/// Add a pending consume request by canonical chain order.
	///
	/// Silently deduplicates: if `commitment` is already in `pending_commitments`
	/// the request is dropped.
	///
	/// Returns `true` when the pending queue has reached `batch_size` items.
	pub fn add_consume_request(
		&mut self,
		order_key: EventOrderKey,
		commitment: [u8; 32],
		batch_size: usize,
	) -> bool {
		if self.pending_commitments.contains(&commitment) {
			return self.pending_requests.len() >= batch_size;
		}

		self.pending_commitments.insert(commitment);
		self.pending_requests.insert(
			order_key,
			PendingRequest {
				order_key,
				commitment,
			},
		);
		self.pending_requests.len() >= batch_size
	}

	/// Remove the pending request whose commitment matches `commitment`.
	///
	/// No-op if `commitment` is not currently pending.
	pub fn remove_pending_by_commitment(&mut self, commitment: &[u8; 32]) {
		if !self.pending_commitments.remove(commitment) {
			return;
		}
		if let Some(key) = self
			.pending_requests
			.iter()
			.find_map(|(k, v)| (v.commitment == *commitment).then_some(*k))
		{
			self.pending_requests.remove(&key);
		}
	}

	/// Pop exactly `batch_size` requests in canonical order.
	///
	/// Returns `None` if fewer than `batch_size` requests are pending.
	/// Also removes the popped entries from `pending_commitments`.
	pub fn pop_next_batch(&mut self, batch_size: usize) -> Option<Vec<PendingRequest>> {
		if self.pending_requests.len() < batch_size {
			return None;
		}
		self.pop_next_up_to(batch_size)
	}

	/// Pop up to `batch_size` requests in canonical order (partial-batch flush).
	///
	/// Unlike [`pop_next_batch`], this succeeds even when fewer than `batch_size`
	/// items are pending — useful for timeout-driven partial flushes.
	/// Returns `None` only when the queue is empty.
	pub fn pop_next_up_to(&mut self, batch_size: usize) -> Option<Vec<PendingRequest>> {
		if self.pending_requests.is_empty() {
			return None;
		}
		let take_n = batch_size.min(self.pending_requests.len());
		let keys: Vec<EventOrderKey> = self.pending_requests.keys().take(take_n).copied().collect();
		let mut out = Vec::with_capacity(take_n);
		for key in keys {
			if let Some(req) = self.pending_requests.remove(&key) {
				self.pending_commitments.remove(&req.commitment);
				out.push(req);
			}
		}
		Some(out)
	}

	/// Re-enqueue a previously popped batch (used after a prover failure).
	///
	/// Restores each request to both `pending_requests` and `pending_commitments`.
	pub fn reinsert_batch(&mut self, batch: Vec<PendingRequest>) {
		for req in batch {
			self.pending_commitments.insert(req.commitment);
			self.pending_requests.insert(req.order_key, req);
		}
	}
}

/// Convenience aliases preserving the original type names.
pub type CommitmentTreeState = TreeState<CommitmentTree<Hash>>;
pub type NullifierTreeState = TreeState<NullifierTree<Hash>>;
