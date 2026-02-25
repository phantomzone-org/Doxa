use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use tessera_trees::tree::{hasher::Hash, CommitmentTree};

use crate::{
	states::{EventOrderKey, PendingRequest},
	TREE_DEPTH,
};

/// Sequencer in-memory state for commitment-request processing.
pub struct CommitmentTreeState {
	/// Local consumed-note append-only tree mirror.
	pub tree: CommitmentTree<Hash>,
	/// Pending consume requests keyed by canonical chain order.
	pub pending_requests: BTreeMap<EventOrderKey, PendingRequest>,
	/// Fast duplicate guard for pending requests.
	pub pending_commitments: HashSet<[u8; 32]>,
}

impl Default for CommitmentTreeState {
	fn default() -> Self {
		Self::new()
	}
}

impl CommitmentTreeState {
	/// Create a new, empty commitment tree state.
	pub fn new() -> Self {
		Self {
			tree: CommitmentTree::new(TREE_DEPTH),
			pending_requests: BTreeMap::new(),
			pending_commitments: HashSet::new(),
		}
	}

	/// Return the consumed-tree genesis root (empty append tree root).
	pub fn genesis_root() -> Hash {
		let tree: CommitmentTree<Hash> = CommitmentTree::new(TREE_DEPTH);
		tree.get_root()
	}

	/// Return current local consumed root.
	pub fn current_root(&self) -> Hash {
		self.tree.get_root()
	}

	/// Replay one consumed commitment into the local consumed append tree.
	pub fn replay_consumed_commitment(&mut self, commitment: Hash) -> Result<()> {
		let proof = self.tree.insert_batch(vec![commitment])?;
		anyhow::ensure!(
			proof.verify(),
			"consumed-tree proof verification failed during replay"
		);
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
