use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use tessera_trees::tree::hasher::Hash;

use crate::deposits::PendingDepositTree;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventOrderKey {
	pub block_number: u64,
	pub transaction_index: u64,
	pub log_index: u64,
}

#[derive(Debug, Clone)]
pub struct PendingConsumeRequest {
	pub order_key: EventOrderKey,
	pub commitment: [u8; 32],
}

/// Sequencer in-memory state for consume-request processing.
pub struct SequencerState {
	/// Local consumed-note append-only tree mirror.
	pub consumed_tree: PendingDepositTree<sha2::Sha256>,
	/// Pending consume requests keyed by canonical chain order.
	pub pending_requests: BTreeMap<EventOrderKey, PendingConsumeRequest>,
	/// Fast duplicate guard for pending requests.
	pub pending_commitments: HashSet<[u8; 32]>,
}

impl SequencerState {
	pub fn new() -> Self {
		Self {
			consumed_tree: PendingDepositTree::<sha2::Sha256>::new(),
			pending_requests: BTreeMap::new(),
			pending_commitments: HashSet::new(),
		}
	}

	/// Return the consumed-tree genesis root (empty append tree root).
	pub fn genesis_consumed_root() -> Hash {
		let tree = PendingDepositTree::<sha2::Sha256>::new();
		tree.tree.get_root()
	}

	/// Return current local consumed root.
	pub fn current_consumed_root(&self) -> Hash {
		self.consumed_tree.tree.get_root()
	}

	/// Replay one consumed commitment into the local consumed append tree.
	pub fn replay_consumed_commitment(&mut self, commitment: Hash) -> Result<()> {
		let proof = self.consumed_tree.insert_commitments(vec![commitment])?;
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
		batch_size: usize,
	) -> bool {
		if self.pending_commitments.contains(&commitment) {
			return self.pending_requests.len() >= batch_size;
		}

		self.pending_commitments.insert(commitment);
		self.pending_requests.insert(
			order_key,
			PendingConsumeRequest {
				order_key,
				commitment,
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

	pub fn pop_next_batch(&mut self, batch_size: usize) -> Option<Vec<PendingConsumeRequest>> {
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

	pub fn reinsert_batch(&mut self, batch: Vec<PendingConsumeRequest>) {
		for req in batch {
			self.pending_commitments.insert(req.commitment);
			self.pending_requests.insert(req.order_key, req);
		}
	}
}
