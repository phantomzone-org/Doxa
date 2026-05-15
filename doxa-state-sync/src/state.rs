use std::{
	collections::{BTreeMap, BTreeSet, HashMap, HashSet},
	sync::{Arc, RwLock},
};

use alloy::primitives::{Address, U256};
use doxa_client::pool_config::MainPoolConfigTree;
use doxa_trees::{MerkleProof, MerkleTree};
use doxa_utils::hasher::HashOutput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositStatus {
	Pending,
	Validated,
	Withdrawn,
}

#[derive(Debug, Clone)]
pub struct DepositRecord {
	pub note_commitment: [u8; 32],
	pub value: U256,
	pub recipient: Address,
	pub status: DepositStatus,
	pub deposit_block: u64,
	pub asset_id: U256,
}

#[derive(Debug, Clone)]
pub struct CommitmentLocation {
	pub pi_commitment: [u8; 32],
	pub subtree_leaf_index: usize,
	pub confirmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchKind {
	Transaction,
	BridgeTx,
}

#[derive(Clone)]
pub struct StateSyncState {
	// StateTree mirror
	pub state_tree: MerkleTree<HashOutput>,
	pub batch_root_to_leaf_index: HashMap<[u8; 32], usize>,
	pub commitment_to_batch: HashMap<HashOutput, CommitmentLocation>,
	pub confirmed_roots: BTreeSet<HashOutput>,

	// Batch subtree storage
	pub pending_batch_leaves: HashMap<[u8; 32], Vec<doxa_utils::hasher::HashOutput>>,
	pub confirmed_batch_subtrees:
		HashMap<[u8; 32], doxa_trees::MerkleTree<doxa_utils::hasher::HashOutput>>,
	pub pi_to_batch_root: HashMap<[u8; 32], HashOutput>,

	// Pending batch tracking
	pub pending_tx_batches: HashMap<[u8; 32], alloy::primitives::Bytes>,
	pub pending_bridge_tx_batches: HashMap<[u8; 32], alloy::primitives::Bytes>,
	pub confirmed_tx_batches: HashSet<[u8; 32]>,
	pub confirmed_bridge_tx_batches: HashSet<[u8; 32]>,

	// Nullifier index
	pub confirmed_nullifiers: HashSet<HashOutput>,
	pub pending_nullifiers: HashMap<HashOutput, [u8; 32]>,

	// MainPoolConfigTree mirror
	pub config_tree: MainPoolConfigTree<HashOutput>,
	pub subpool_roots: HashMap<u64, HashOutput>,
	pub pending_subpool_assignments: BTreeMap<u64, SubpoolAssignedEvent>,
	pub next_expected_subpool_id: u64,

	// Deposit index
	pub deposits: HashMap<[u8; 32], DepositRecord>,

	// Sync state
	pub last_synced_block: u64,
}

#[derive(Debug, Clone)]
pub struct SubpoolAssignedEvent {
	pub subpool_id: u64,
	pub owner: Address,
	pub block_number: u64,
	pub log_index: u64,
}

impl StateSyncState {
	pub fn new(tree_depth: usize) -> Self {
		let mut state = Self {
			state_tree: MerkleTree::new(tree_depth),
			batch_root_to_leaf_index: HashMap::new(),
			commitment_to_batch: HashMap::new(),
			confirmed_roots: BTreeSet::new(),
			pending_batch_leaves: HashMap::new(),
			confirmed_batch_subtrees: HashMap::new(),
			pi_to_batch_root: HashMap::new(),
			pending_tx_batches: HashMap::new(),
			pending_bridge_tx_batches: HashMap::new(),
			confirmed_tx_batches: HashSet::new(),
			confirmed_bridge_tx_batches: HashSet::new(),
			confirmed_nullifiers: HashSet::new(),
			pending_nullifiers: HashMap::new(),
			config_tree: MainPoolConfigTree::new(),
			subpool_roots: HashMap::new(),
			pending_subpool_assignments: BTreeMap::new(),
			next_expected_subpool_id: 1,
			deposits: HashMap::new(),
			last_synced_block: 0,
		};

		let genesis_root = state.state_tree.root();
		state.confirmed_roots.insert(genesis_root);
		state
	}

	pub fn insert_state_tree_leaf(&mut self, batch_root: HashOutput) -> anyhow::Result<usize> {
		let index = self
			.state_tree
			.insert(batch_root)
			.map_err(|e| anyhow::anyhow!("failed to insert state tree leaf: {e}"))?;
		let key = *crate::contract::hash_to_bytes32(&batch_root);
		self.batch_root_to_leaf_index.insert(key, index);
		Ok(index)
	}

	pub fn confirm_batch(
		&mut self,
		pi_commitment: [u8; 32],
		batch_root: HashOutput,
		new_tree_root: HashOutput,
	) -> anyhow::Result<()> {
		// Insert batch root into state tree FIRST — if this fails, state remains consistent
		self.insert_state_tree_leaf(batch_root)?;

		// Verify the new_tree_root matches local state_tree root after insertion
		let local_root = self.state_tree.root();
		if local_root != new_tree_root {
			tracing::warn!(
				?pi_commitment,
				"local state tree root does not match on-chain new_tree_root after batch confirmation"
			);
		}

		// Build subtree from pending_batch_leaves for this pi_commitment
		if let Some(leaves) = self.pending_batch_leaves.remove(&pi_commitment) {
			use doxa_trees::MerkleTree;
			let mut subtree = MerkleTree::new(crate::constants::BATCH_SUBTREE_DEPTH);
			for leaf in &leaves {
				subtree
					.insert(*leaf)
					.map_err(|e| anyhow::anyhow!("subtree insert failed: {e}"))?;
			}
			// Verify subtree root matches batch_root
			if subtree.root() != batch_root {
				tracing::warn!(?pi_commitment, "local subtree root does not match batch_root");
			}
			self.confirmed_batch_subtrees.insert(pi_commitment, subtree);
		}

		self.pi_to_batch_root.insert(pi_commitment, batch_root);

		// Mark commitments confirmed
		let commitments_to_update: Vec<HashOutput> = self
			.commitment_to_batch
			.iter()
			.filter_map(|(c, loc)| {
				if loc.pi_commitment == pi_commitment { Some(*c) } else { None }
			})
			.collect();
		for c in commitments_to_update {
			if let Some(loc) = self.commitment_to_batch.get_mut(&c) {
				loc.confirmed = true;
			}
		}

		// Move pending → confirmed
		if self.pending_tx_batches.remove(&pi_commitment).is_some() {
			self.confirmed_tx_batches.insert(pi_commitment);
		} else if self.pending_bridge_tx_batches.remove(&pi_commitment).is_some() {
			self.confirmed_bridge_tx_batches.insert(pi_commitment);
		}

		// Confirm nullifiers
		let nullifiers_to_confirm: Vec<HashOutput> = self
			.pending_nullifiers
			.iter()
			.filter_map(|(n, pic)| {
				if *pic == pi_commitment { Some(*n) } else { None }
			})
			.collect();
		for n in nullifiers_to_confirm {
			self.pending_nullifiers.remove(&n);
			self.confirmed_nullifiers.insert(n);
		}

		self.confirmed_roots.insert(new_tree_root);
		Ok(())
	}

	pub fn add_pending_commitment(
		&mut self,
		commitment: doxa_utils::hasher::HashOutput,
		pi_commitment: [u8; 32],
		subtree_leaf_index: usize,
	) {
		self.commitment_to_batch.insert(
			commitment,
			CommitmentLocation { pi_commitment, subtree_leaf_index, confirmed: false },
		);
		let leaves = self
			.pending_batch_leaves
			.entry(pi_commitment)
			.or_insert_with(|| vec![doxa_utils::hasher::HashOutput::default(); 512]);
		if subtree_leaf_index < 512 {
			leaves[subtree_leaf_index] = commitment;
		}
	}

	pub fn add_pending_nullifier(&mut self, nullifier: HashOutput, pi_commitment: [u8; 32]) {
		self.pending_nullifiers.insert(nullifier, pi_commitment);
	}

	pub fn get_commitment_status(&self, commitment: &HashOutput) -> CommitmentStatus {
		match self.commitment_to_batch.get(commitment) {
			Some(location) if location.confirmed => {
				let batch_root = self.get_batch_root_for_commitment(commitment);
				let batch_root_key =
					batch_root.map(|r| *crate::contract::hash_to_bytes32(&r));
				if let (Some(batch_root_key), Ok(batch_subtree_path)) = (
					batch_root_key,
					self.get_batch_subtree_proof(commitment),
				) {
					if let Some(&batch_leaf_index) =
						self.batch_root_to_leaf_index.get(&batch_root_key)
					{
						if let Ok(state_tree_path) = self.state_tree.merkle_proof(batch_leaf_index) {
							return CommitmentStatus::Confirmed {
								batch_subtree_path,
								state_tree_path,
							};
						}
					}
				}
				tracing::error!(
					?commitment,
					"commitment is confirmed but proof construction failed"
				);
				CommitmentStatus::NotFound
			},
			Some(location) => CommitmentStatus::Pending { pi_commitment: location.pi_commitment },
			None => CommitmentStatus::NotFound,
		}
	}

	pub fn get_nullifier_status(&self, nullifier: &HashOutput) -> NullifierStatus {
		if self.confirmed_nullifiers.contains(nullifier) {
			NullifierStatus::Confirmed
		} else if let Some(pi_commitment) = self.pending_nullifiers.get(nullifier) {
			NullifierStatus::Pending { pi_commitment: *pi_commitment }
		} else {
			NullifierStatus::NotFound
		}
	}

	pub fn get_batch_status(&self, pi_commitment: &[u8; 32], kind: BatchKind) -> BatchStatus {
		match kind {
			BatchKind::Transaction => {
				if self.confirmed_tx_batches.contains(pi_commitment) {
					BatchStatus::Confirmed
				} else if self.pending_tx_batches.contains_key(pi_commitment) {
					BatchStatus::Pending
				} else {
					BatchStatus::NotFound
				}
			},
			BatchKind::BridgeTx => {
				if self.confirmed_bridge_tx_batches.contains(pi_commitment) {
					BatchStatus::Confirmed
				} else if self.pending_bridge_tx_batches.contains_key(pi_commitment) {
					BatchStatus::Pending
				} else {
					BatchStatus::NotFound
				}
			},
		}
	}

	pub fn get_deposits_from_block(&self, from_block: u64) -> Vec<DepositRecord> {
		self.deposits
			.values()
			.filter(|deposit| deposit.deposit_block >= from_block)
			.cloned()
			.collect()
	}

	fn get_batch_root_for_commitment(&self, commitment: &HashOutput) -> Option<HashOutput> {
		let loc = self.commitment_to_batch.get(commitment)?;
		self.pi_to_batch_root.get(&loc.pi_commitment).copied()
	}

	fn get_batch_subtree_proof(
		&self,
		commitment: &HashOutput,
	) -> anyhow::Result<doxa_trees::MerkleProof<doxa_utils::hasher::HashOutput>> {
		let loc = self
			.commitment_to_batch
			.get(commitment)
			.ok_or_else(|| anyhow::anyhow!("commitment not found"))?;
		let subtree = self
			.confirmed_batch_subtrees
			.get(&loc.pi_commitment)
			.ok_or_else(|| anyhow::anyhow!("no confirmed subtree for pi_commitment"))?;
		subtree
			.merkle_proof(loc.subtree_leaf_index)
			.map_err(|e| anyhow::anyhow!("subtree proof failed: {e}"))
	}
}

// Thread-safe wrapper
#[derive(Clone)]
pub struct StateSyncService {
	state: Arc<RwLock<StateSyncState>>,
}

impl StateSyncService {
	pub fn new(tree_depth: usize) -> Self {
		Self { state: Arc::new(RwLock::new(StateSyncState::new(tree_depth))) }
	}

	pub fn with_state<F, R>(&self, f: F) -> R where F: FnOnce(&StateSyncState) -> R {
		let state = self.state.read().unwrap();
		f(&*state)
	}

	pub fn with_state_mut<F, R>(&self, f: F) -> R where F: FnOnce(&mut StateSyncState) -> R {
		let mut state = self.state.write().unwrap();
		f(&mut *state)
	}
}

// Response types for API
pub enum CommitmentStatus {
	Confirmed {
		batch_subtree_path: MerkleProof<HashOutput>,
		state_tree_path: MerkleProof<HashOutput>,
	},
	Pending { pi_commitment: [u8; 32] },
	NotFound,
}

pub enum NullifierStatus {
	Confirmed,
	Pending { pi_commitment: [u8; 32] },
	NotFound,
}

pub enum BatchStatus {
	Confirmed,
	Pending,
	NotFound,
}
