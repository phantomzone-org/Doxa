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

impl CommitmentTreeState {
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
	/// Returns true when we have at least `batch_size` pending requests.
	pub fn add_consume_request(
		&mut self,
		order_key: EventOrderKey,
		commitment: [u8; 32],
		associated_input_proof: Vec<u8>,
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
				associated_input_proof: Some(associated_input_proof),
			},
		);
		self.pending_requests.len() >= batch_size
	}

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

	pub fn pop_next_batch(&mut self, batch_size: usize) -> Option<Vec<PendingRequest>> {
		if self.pending_requests.len() < batch_size {
			return None;
		}

		let keys: Vec<EventOrderKey> = self
			.pending_requests
			.keys()
			.take(batch_size)
			.copied()
			.collect();
		let mut out = Vec::with_capacity(batch_size);
		for key in keys {
			if let Some(req) = self.pending_requests.remove(&key) {
				self.pending_commitments.remove(&req.commitment);
				out.push(req);
			}
		}
		Some(out)
	}

	pub fn reinsert_batch(&mut self, batch: Vec<PendingRequest>) {
		for req in batch {
			self.pending_commitments.insert(req.commitment);
			self.pending_requests.insert(req.order_key, req);
		}
	}
}
