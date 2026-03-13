//! Slot-centric batch builder for the sequencer.
//!
//! Replaces the old four-independent-queue approach with a single array of
//! [`BatchSlot`]s.  Each slot is either a real private TX, a deposit
//! mini-batch (up to 8 NC notes packed), or an empty (all-dummy) slot.

use std::collections::{HashMap, HashSet};

use alloy::primitives::FixedBytes;
use tessera_trees::tree::{hasher::HashOutput, CommitmentTree, NullifierTree};

use crate::{contract, dummy::derive_dummy_leaf, types::ProveRequest};

/// Number of note-level leaves per account-level slot (NC and NN each have 8
/// per TX slot).
pub const NOTES_PER_SLOT: usize = 8;

/// Per-slot public inputs: the four tree leaves for one account-level slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotPI {
	pub ac: [u8; 32],
	pub an: [u8; 32],
	pub nc: [[u8; 32]; 8],
	pub nn: [[u8; 32]; 8],
}

/// One account-level slot in a batch.
pub enum BatchSlot {
	/// Real private TX: all four trees have real leaves extracted from the TX
	/// proof's public inputs.
	PrivateTx {
		/// Client-supplied PrivTx proof bytes (is_real = 1).
		tx_proof: Vec<u8>,
		/// AC leaf: extracted from tx_proof PIs.
		ac: [u8; 32],
		/// AN leaf: extracted from tx_proof PIs.
		an: [u8; 32],
		/// NC leaves (8): extracted from tx_proof PIs.
		nc: [[u8; 32]; 8],
		/// NN leaves (8): extracted from tx_proof PIs.
		nn: [[u8; 32]; 8],
	},
	/// Deposit mini-batch: up to 8 real NC notes packed into one slot.
	/// AC, AN, NN are fully dummy-padded at slot creation time.
	/// NC positions `0..nc_filled` are real deposit notes; the rest are
	/// filled with dummies at `finalize()` time.
	Deposit {
		/// AC leaf: dummy (materialized at slot creation).
		ac: [u8; 32],
		/// AN leaf: dummy (materialized at slot creation).
		an: [u8; 32],
		/// NC leaves (8): nc[0..nc_filled] = real deposit notes,
		/// nc[nc_filled..8] = filled with dummies at finalize().
		nc: [[u8; 32]; 8],
		/// How many NC positions are filled with real deposit notes.
		nc_filled: usize,
		/// NN leaves (8): all dummies (materialized at slot creation).
		nn: [[u8; 32]; 8],
	},
	/// Empty: all four trees padded with deterministic dummies.
	Empty {
		ac: [u8; 32],
		an: [u8; 32],
		nc: [[u8; 32]; 8],
		nn: [[u8; 32]; 8],
	},
}

/// Leaf arrays produced by [`BatchBuilder::finalize`].
#[allow(dead_code)]
pub struct FinalizedBatch {
	/// AC leaves in arrival order (len = `account_batch_size`).
	pub ac_leaves: Vec<[u8; 32]>,
	/// AN leaves sorted as `[u64; 4]` big-endian (len = `account_batch_size`).
	pub an_sorted: Vec<[u8; 32]>,
	/// Sorting permutation for AN: `an_sort_perm[slot] = sorted_position`.
	/// The prover recovers a slot's AN value via `an_sorted[an_sort_perm[slot]]`.
	pub an_sort_perm: Vec<usize>,
	/// NC leaves in arrival order (len = `note_batch_size`).
	pub nc_leaves: Vec<[u8; 32]>,
	/// NN leaves sorted as `[u64; 4]` big-endian (len = `note_batch_size`).
	pub nn_sorted: Vec<[u8; 32]>,
	/// Sorting permutation for NN: `nn_sort_perm[slot] = sorted_position`.
	/// The prover recovers a slot's NN value via `nn_sorted[nn_sort_perm[slot]]`.
	pub nn_sort_perm: Vec<usize>,
	/// Client TX proof bytes keyed by slot index (real private TX slots only).
	/// Slots present in this map are real (is_real=1); absent slots are dummy.
	pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

/// Incrementally builds a batch of `account_batch_size` slots.
///
/// Tree batch sizes:
///   - AC, AN: `account_batch_size` leaves (1 per slot).
///   - NC, NN: `note_batch_size = account_batch_size × NOTES_PER_SLOT` leaves (8 per slot).
pub struct BatchBuilder {
	slots: Vec<BatchSlot>,
	account_batch_size: usize,
	note_batch_size: usize,
	/// Index of the current open deposit mini-batch slot (`nc_filled < 8`).
	/// `None` when no open deposit slot exists.
	open_deposit: Option<usize>,
	/// Current tree roots at batch creation time (used for dummy derivation).
	ac_root: [u8; 32],
	an_root: [u8; 32],
	nc_root: [u8; 32],
	nn_root: [u8; 32],
	/// Absolute batch start indices for each tree.
	ac_start: usize,
	an_start: usize,
	nc_start: usize,
	nn_start: usize,
	/// AN leaves currently in this batch (for duplicate detection).
	an_in_batch: HashSet<[u8; 32]>,
	/// NN leaves currently in this batch (for duplicate detection).
	nn_in_batch: HashSet<[u8; 32]>,
}

impl BatchBuilder {
	/// Create a new batch builder.
	///
	/// # Parameters
	/// - `account_batch_size`: number of account-level slots in the batch.
	/// - `ac_tree` / `an_tree` / `nc_tree` / `nn_tree`: current tree states (used to read roots and
	///   leaf counts for dummy derivation).
	pub fn new(
		account_batch_size: usize,
		ac_tree: &CommitmentTree<HashOutput>,
		an_tree: &NullifierTree<HashOutput>,
		nc_tree: &CommitmentTree<HashOutput>,
		nn_tree: &NullifierTree<HashOutput>,
	) -> Self {
		let note_batch_size = account_batch_size * NOTES_PER_SLOT;
		Self {
			slots: Vec::with_capacity(account_batch_size),
			account_batch_size,
			note_batch_size,
			open_deposit: None,
			ac_root: contract::hash_to_bytes32(&ac_tree.get_root()).0,
			an_root: contract::hash_to_bytes32(&an_tree.get_root()).0,
			nc_root: contract::hash_to_bytes32(&nc_tree.get_root()).0,
			nn_root: contract::hash_to_bytes32(&nn_tree.get_root()).0,
			ac_start: ac_tree.num_leaves(),
			an_start: an_tree.num_leaves(),
			nc_start: nc_tree.num_leaves(),
			nn_start: nn_tree.num_leaves(),
			an_in_batch: HashSet::new(),
			nn_in_batch: HashSet::new(),
		}
	}

	/// Check if an AN leaf is already in this batch.
	pub fn contains_an(&self, leaf: &[u8; 32]) -> bool {
		self.an_in_batch.contains(leaf)
	}

	/// Check if an NN leaf is already in this batch.
	pub fn contains_nn(&self, leaf: &[u8; 32]) -> bool {
		self.nn_in_batch.contains(leaf)
	}

	/// Number of slots currently filled.
	pub fn len(&self) -> usize {
		self.slots.len()
	}

	/// Whether the batch is empty (no slots allocated).
	#[allow(dead_code)]
	pub fn is_empty(&self) -> bool {
		self.slots.is_empty()
	}

	/// Whether the batch is full (all account-level slots allocated).
	pub fn is_full(&self) -> bool {
		self.slots.len() >= self.account_batch_size
	}

	/// Add a real private TX to the batch.
	///
	/// All four tree leaves are extracted from the TX proof's public inputs
	/// (provided by the caller after validation).
	///
	/// Returns `true` if the batch is now full.
	///
	/// # Errors
	/// Returns `Err` if the batch is already full.
	pub fn add_private_tx(
		&mut self,
		tx_proof: Vec<u8>,
		ac: [u8; 32],
		an: [u8; 32],
		nc: [[u8; 32]; 8],
		nn: [[u8; 32]; 8],
	) -> anyhow::Result<bool> {
		anyhow::ensure!(!self.is_full(), "batch is full; cannot add private TX");
		self.an_in_batch.insert(an);
		for leaf in &nn {
			self.nn_in_batch.insert(*leaf);
		}
		self.slots.push(BatchSlot::PrivateTx {
			tx_proof,
			ac,
			an,
			nc,
			nn,
		});
		Ok(self.is_full())
	}

	/// Add a deposit note to the batch.
	///
	/// The note is packed into the current open deposit mini-batch slot. If no
	/// open slot exists (or the current one is full), a new `Deposit` slot is
	/// allocated with AC, AN, NN fully dummy-padded.
	///
	/// Returns `true` if the batch is now full.
	///
	/// # Errors
	/// Returns `Err` if the batch is already full and no open deposit slot has
	/// room.
	pub fn add_deposit(&mut self, nc_note: [u8; 32]) -> anyhow::Result<bool> {
		// Try to pack into existing open deposit slot.
		if let Some(idx) = self.open_deposit {
			if let BatchSlot::Deposit {
				nc,
				nc_filled,
				..
			} = &mut self.slots[idx]
			{
				nc[*nc_filled] = nc_note;
				*nc_filled += 1;
				if *nc_filled >= NOTES_PER_SLOT {
					// Slot is full — close it.
					self.open_deposit = None;
				}
				return Ok(self.is_full());
			}
		}

		// No open deposit slot — allocate a new one.
		anyhow::ensure!(
			!self.is_full(),
			"batch is full; cannot allocate new deposit slot"
		);

		let slot_idx = self.slots.len();

		// Derive dummy leaves for AC, AN, NN.
		let ac = derive_dummy_leaf(self.ac_start + slot_idx, &self.ac_root);
		let an = derive_dummy_leaf(self.an_start + slot_idx, &self.an_root);

		let nn_base = self.nn_start + slot_idx * NOTES_PER_SLOT;
		let nn: [[u8; 32]; 8] =
			core::array::from_fn(|j| derive_dummy_leaf(nn_base + j, &self.nn_root));

		// NC: first position is the real deposit note; rest will be filled at finalize.
		let mut nc = [[0u8; 32]; 8];
		nc[0] = nc_note;

		self.slots.push(BatchSlot::Deposit {
			ac,
			an,
			nc,
			nc_filled: 1,
			nn,
		});

		self.open_deposit = Some(slot_idx);

		Ok(self.is_full())
	}

	/// Return the public inputs (AC, AN, NC, NN leaves) for the i-th slot.
	///
	/// Call after [`pad()`](Self::pad) to get fully-materialized leaves
	/// (including dummies); before padding, partially-filled deposit slots
	/// will have zeros in unfilled NC positions.
	///
	/// # Panics
	/// Panics if `i >= self.slots.len()`.
	pub fn tx_pi(&self, i: usize) -> SlotPI {
		match &self.slots[i] {
			BatchSlot::PrivateTx {
				ac,
				an,
				nc,
				nn,
				..
			}
			| BatchSlot::Deposit {
				ac,
				an,
				nc,
				nn,
				..
			}
			| BatchSlot::Empty {
				ac,
				an,
				nc,
				nn,
			} => SlotPI {
				ac: *ac,
				an: *an,
				nc: *nc,
				nn: *nn,
			},
		}
	}

	/// Fill remaining NC positions in open deposit slots with dummies and
	/// pad remaining slots with `Empty` up to `account_batch_size`.
	///
	/// Idempotent: calling `pad()` on an already-padded builder is a no-op.
	pub fn pad(&mut self) {
		// 1. Finalize open deposit slots: fill nc[nc_filled..8] with dummies.
		for (slot_idx, slot) in self.slots.iter_mut().enumerate() {
			if let BatchSlot::Deposit {
				nc,
				nc_filled,
				..
			} = slot
			{
				let nc_base = self.nc_start + slot_idx * NOTES_PER_SLOT;
				for (j, nc_slot) in nc
					.iter_mut()
					.enumerate()
					.skip(*nc_filled)
					.take(NOTES_PER_SLOT - *nc_filled)
				{
					*nc_slot = derive_dummy_leaf(nc_base + j, &self.nc_root);
				}
				*nc_filled = NOTES_PER_SLOT;
			}
		}

		// 2. Pad remaining slots with Empty.
		while self.slots.len() < self.account_batch_size {
			let slot_idx = self.slots.len();
			let ac = derive_dummy_leaf(self.ac_start + slot_idx, &self.ac_root);
			let an = derive_dummy_leaf(self.an_start + slot_idx, &self.an_root);

			let nc_base = self.nc_start + slot_idx * NOTES_PER_SLOT;
			let nc: [[u8; 32]; 8] =
				core::array::from_fn(|j| derive_dummy_leaf(nc_base + j, &self.nc_root));

			let nn_base = self.nn_start + slot_idx * NOTES_PER_SLOT;
			let nn: [[u8; 32]; 8] =
				core::array::from_fn(|j| derive_dummy_leaf(nn_base + j, &self.nn_root));

			self.slots.push(BatchSlot::Empty {
				ac,
				an,
				nc,
				nn,
			});
		}
	}

	/// Finalize the batch: pad, build leaf arrays, sort AN/NN, and return the
	/// [`FinalizedBatch`].
	///
	/// After this call the `BatchBuilder` is consumed.
	pub fn finalize(mut self) -> FinalizedBatch {
		self.pad();

		// 3. Build leaf arrays from slot data.
		let mut ac_leaves = Vec::with_capacity(self.account_batch_size);
		let mut an_unsorted = Vec::with_capacity(self.account_batch_size);
		let mut nc_leaves = Vec::with_capacity(self.note_batch_size);
		let mut nn_unsorted = Vec::with_capacity(self.note_batch_size);
		let mut tx_proofs_by_slot = HashMap::new();

		for (s, slot) in self.slots.into_iter().enumerate() {
			match slot {
				BatchSlot::PrivateTx {
					tx_proof,
					ac,
					an,
					nc,
					nn,
				} => {
					tx_proofs_by_slot.insert(s, tx_proof);
					ac_leaves.push(ac);
					an_unsorted.push(an);
					nc_leaves.extend_from_slice(&nc);
					nn_unsorted.extend_from_slice(&nn);
				},
				BatchSlot::Deposit {
					ac,
					an,
					nc,
					nn,
					..
				} => {
					ac_leaves.push(ac);
					an_unsorted.push(an);
					nc_leaves.extend_from_slice(&nc);
					nn_unsorted.extend_from_slice(&nn);
				},
				BatchSlot::Empty {
					ac,
					an,
					nc,
					nn,
				} => {
					ac_leaves.push(ac);
					an_unsorted.push(an);
					nc_leaves.extend_from_slice(&nc);
					nn_unsorted.extend_from_slice(&nn);
				},
			}
		}

		// 4. Sort AN and NN as [u64; 4] big-endian (matches HashOutput::Ord), tracking the
		//    permutation so the prover can map slot→sorted_position.
		let an_sort_perm = argsort_bytes32_as_u256(&an_unsorted);
		let an_sorted: Vec<[u8; 32]> = an_sort_perm.iter().map(|&i| an_unsorted[i]).collect();
		// Invert: sort_perm_inv[original_slot] = sorted_position
		let mut an_sort_perm_inv = vec![0usize; an_sort_perm.len()];
		for (sorted_pos, &orig_slot) in an_sort_perm.iter().enumerate() {
			an_sort_perm_inv[orig_slot] = sorted_pos;
		}

		let nn_sort_perm = argsort_bytes32_as_u256(&nn_unsorted);
		let nn_sorted: Vec<[u8; 32]> = nn_sort_perm.iter().map(|&i| nn_unsorted[i]).collect();
		let mut nn_sort_perm_inv = vec![0usize; nn_sort_perm.len()];
		for (sorted_pos, &orig_slot) in nn_sort_perm.iter().enumerate() {
			nn_sort_perm_inv[orig_slot] = sorted_pos;
		}

		// 5. Assert sorting (defensive check at sequencer exit point).
		debug_assert!(
			is_sorted_u256(&an_sorted),
			"AN leaves not sorted after finalize"
		);
		debug_assert!(
			is_sorted_u256(&nn_sorted),
			"NN leaves not sorted after finalize"
		);

		FinalizedBatch {
			ac_leaves,
			an_sorted,
			an_sort_perm: an_sort_perm_inv,
			nc_leaves,
			nn_sorted,
			nn_sort_perm: nn_sort_perm_inv,
			tx_proofs_by_slot,
		}
	}
}

/// Return indices that would sort `v` as `[u64; 4]` big-endian (argsort).
/// `result[sorted_pos] = original_index`.
pub fn argsort_bytes32_as_u256(v: &[[u8; 32]]) -> Vec<usize> {
	let mut indices: Vec<usize> = (0..v.len()).collect();
	indices.sort_by(|&a, &b| {
		let a_u64: [u64; 4] = core::array::from_fn(|i| {
			u64::from_be_bytes(v[a][i * 8..(i + 1) * 8].try_into().unwrap())
		});
		let b_u64: [u64; 4] = core::array::from_fn(|i| {
			u64::from_be_bytes(v[b][i * 8..(i + 1) * 8].try_into().unwrap())
		});
		a_u64.cmp(&b_u64)
	});
	indices
}

/// Check that a `[u8; 32]` slice is sorted as `[u64; 4]` big-endian.
pub fn is_sorted_u256(v: &[[u8; 32]]) -> bool {
	v.windows(2).all(|w| {
		let a: [u64; 4] = core::array::from_fn(|i| {
			u64::from_be_bytes(w[0][i * 8..(i + 1) * 8].try_into().unwrap())
		});
		let b: [u64; 4] = core::array::from_fn(|i| {
			u64::from_be_bytes(w[1][i * 8..(i + 1) * 8].try_into().unwrap())
		});
		a <= b
	})
}

impl FinalizedBatch {
	/// Return the public inputs for the i-th slot (arrival order).
	///
	/// AC and NC are stored in arrival order already.
	/// AN and NN are stored sorted — this method inverts the sort
	/// permutation to recover slot-order values.
	///
	/// # Panics
	/// Panics if `i` is out of range for the batch.
	pub fn tx_pi(&self, i: usize) -> SlotPI {
		let ac = self.ac_leaves[i];
		let an = self.an_sorted[self.an_sort_perm[i]];

		let nc_base = i * NOTES_PER_SLOT;
		let nc: [[u8; 32]; 8] = core::array::from_fn(|j| self.nc_leaves[nc_base + j]);

		let nn_base = i * NOTES_PER_SLOT;
		let nn: [[u8; 32]; 8] =
			core::array::from_fn(|j| self.nn_sorted[self.nn_sort_perm[nn_base + j]]);

		SlotPI {
			ac,
			an,
			nc,
			nn,
		}
	}

	/// Build native tree proofs and assemble a [`ProveRequest`].
	///
	/// Clones the four trees, inserts the finalized leaf arrays, and returns
	/// the resulting batch proofs + the full `ProveRequest`.
	#[allow(clippy::too_many_arguments, clippy::wrong_self_convention)]
	pub fn into_prove_request(
		&self,
		batch_id: u64,
		ac_tree: &CommitmentTree<HashOutput>,
		an_tree: &NullifierTree<HashOutput>,
		nc_tree: &CommitmentTree<HashOutput>,
		nn_tree: &NullifierTree<HashOutput>,
	) -> anyhow::Result<ProveRequest> {
		// NC: arrival order → commitment tree
		let nc_hashes = contract::bytes_slice_to_hashes(&self.nc_leaves)?;
		let mut nc_tmp = nc_tree.clone();
		let nc_proof = nc_tmp.insert_batch(nc_hashes)?;
		anyhow::ensure!(nc_proof.verify(), "NC native proof verification failed");

		// NN: sorted → nullifier tree
		let nn_hashes = contract::bytes_slice_to_hashes(&self.nn_sorted)?;
		let mut nn_tmp = nn_tree.clone();
		let nn_proof = nn_tmp.insert_batch(nn_hashes)?;
		anyhow::ensure!(nn_proof.verify(), "NN native proof verification failed");

		// AC: arrival order → commitment tree
		let ac_hashes = contract::bytes_slice_to_hashes(&self.ac_leaves)?;
		let mut ac_tmp = ac_tree.clone();
		let ac_proof = ac_tmp.insert_batch(ac_hashes)?;
		anyhow::ensure!(ac_proof.verify(), "AC native proof verification failed");

		// AN: sorted → nullifier tree
		let an_hashes = contract::bytes_slice_to_hashes(&self.an_sorted)?;
		let mut an_tmp = an_tree.clone();
		let an_proof = an_tmp.insert_batch(an_hashes)?;
		anyhow::ensure!(an_proof.verify(), "AN native proof verification failed");

		Ok(ProveRequest {
			batch_id,
			notes_commitment_proof: nc_proof,
			notes_nullifier_proof: nn_proof,
			accounts_commitment_proof: ac_proof,
			accounts_nullifier_proof: an_proof,
			nc_sorted_leaves: self.nc_leaves.clone(),
			nn_sorted_leaves: self.nn_sorted.clone(),
			ac_sorted_leaves: self.ac_leaves.clone(),
			an_sorted_leaves: self.an_sorted.clone(),
			an_sort_perm: self.an_sort_perm.clone(),
			nn_sort_perm: self.nn_sort_perm.clone(),
			tx_proofs_by_slot: self.tx_proofs_by_slot.clone(),
		})
	}

	/// Convert sorted leaf arrays to `FixedBytes<32>` for on-chain submission.
	pub fn nc_fixed(&self) -> Vec<FixedBytes<32>> {
		self.nc_leaves
			.iter()
			.map(|b| FixedBytes::from(*b))
			.collect()
	}

	pub fn nn_fixed(&self) -> Vec<FixedBytes<32>> {
		self.nn_sorted
			.iter()
			.map(|b| FixedBytes::from(*b))
			.collect()
	}

	pub fn ac_fixed(&self) -> Vec<FixedBytes<32>> {
		self.ac_leaves
			.iter()
			.map(|b| FixedBytes::from(*b))
			.collect()
	}

	pub fn an_fixed(&self) -> Vec<FixedBytes<32>> {
		self.an_sorted
			.iter()
			.map(|b| FixedBytes::from(*b))
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use tessera_trees::tree::{CommitmentTree, NullifierTree};

	use super::*;

	const DEPTH: usize = 8;
	const ACCOUNT_BATCH: usize = 4;

	fn make_trees() -> (
		CommitmentTree<HashOutput>,
		NullifierTree<HashOutput>,
		CommitmentTree<HashOutput>,
		NullifierTree<HashOutput>,
	) {
		(
			CommitmentTree::new(DEPTH),
			NullifierTree::new_with_padding(DEPTH, ACCOUNT_BATCH),
			CommitmentTree::new(DEPTH),
			NullifierTree::new_with_padding(DEPTH, ACCOUNT_BATCH * NOTES_PER_SLOT),
		)
	}

	fn dummy_leaf(val: u8) -> [u8; 32] {
		[val; 32]
	}

	#[test]
	fn add_private_tx_fills_batch() {
		let (ac, an, nc, nn) = make_trees();
		let mut bb = BatchBuilder::new(ACCOUNT_BATCH, &ac, &an, &nc, &nn);
		for i in 0..ACCOUNT_BATCH {
			let full = bb
				.add_private_tx(
					vec![i as u8],
					dummy_leaf(i as u8),
					dummy_leaf(i as u8 + 100),
					[dummy_leaf(i as u8 + 10); 8],
					[dummy_leaf(i as u8 + 20); 8],
				)
				.unwrap();
			assert_eq!(full, i == ACCOUNT_BATCH - 1);
		}
		assert!(bb.is_full());

		// Should fail to add more.
		assert!(bb
			.add_private_tx(vec![], [0; 32], [0; 32], [[0; 32]; 8], [[0; 32]; 8])
			.is_err());
	}

	#[test]
	fn deposit_mini_batching() {
		let (ac, an, nc, nn) = make_trees();
		let mut bb = BatchBuilder::new(ACCOUNT_BATCH, &ac, &an, &nc, &nn);

		// Add 5 deposits: should create 1 slot (8 NC positions, 5 filled).
		for i in 0..5 {
			bb.add_deposit(dummy_leaf(i)).unwrap();
		}
		// Only 1 slot allocated (not 5).
		assert_eq!(bb.len(), 1);
		assert!(bb.open_deposit.is_some());

		// Add 3 more: fills the first slot.
		for i in 5..8 {
			bb.add_deposit(dummy_leaf(i)).unwrap();
		}
		assert_eq!(bb.len(), 1);
		assert!(bb.open_deposit.is_none()); // Closed — full.

		// Next deposit allocates a new slot.
		bb.add_deposit(dummy_leaf(99)).unwrap();
		assert_eq!(bb.len(), 2);
		assert!(bb.open_deposit.is_some());
	}

	#[test]
	fn finalize_pads_and_sorts() {
		let (ac, an, nc, nn) = make_trees();
		let mut bb = BatchBuilder::new(ACCOUNT_BATCH, &ac, &an, &nc, &nn);

		// 1 real TX + 2 deposits
		bb.add_private_tx(
			vec![0xFF],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		bb.add_deposit(dummy_leaf(10)).unwrap();
		bb.add_deposit(dummy_leaf(11)).unwrap();

		let batch = bb.finalize();

		// Should have ACCOUNT_BATCH AC leaves and ACCOUNT_BATCH * 8 NC leaves.
		assert_eq!(batch.ac_leaves.len(), ACCOUNT_BATCH);
		assert_eq!(batch.nc_leaves.len(), ACCOUNT_BATCH * NOTES_PER_SLOT);
		assert_eq!(batch.an_sorted.len(), ACCOUNT_BATCH);
		assert_eq!(batch.nn_sorted.len(), ACCOUNT_BATCH * NOTES_PER_SLOT);

		// Real slots: only slot 0 (has a tx proof).
		assert_eq!(batch.tx_proofs_by_slot.len(), 1);
		assert!(batch.tx_proofs_by_slot.contains_key(&0));

		// AN and NN should be sorted.
		assert!(is_sorted_u256(&batch.an_sorted));
		assert!(is_sorted_u256(&batch.nn_sorted));
	}

	#[test]
	fn tx_pi_matches_after_finalize() {
		let (ac, an, nc, nn) = make_trees();
		let mut bb = BatchBuilder::new(ACCOUNT_BATCH, &ac, &an, &nc, &nn);

		// 1 real TX + 2 deposits (partially filling one deposit slot)
		bb.add_private_tx(
			vec![0xFF],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		bb.add_deposit(dummy_leaf(10)).unwrap();
		bb.add_deposit(dummy_leaf(11)).unwrap();

		// Pad in place so we can read PIs before consuming
		bb.pad();

		// Snapshot PIs from builder
		let builder_pis: Vec<SlotPI> = (0..ACCOUNT_BATCH).map(|i| bb.tx_pi(i)).collect();

		// Finalize (consumes builder)
		let fb = bb.finalize();

		// Compare slot-by-slot
		for i in 0..ACCOUNT_BATCH {
			let fb_pi = fb.tx_pi(i);
			assert_eq!(builder_pis[i].ac, fb_pi.ac, "AC mismatch at slot {i}");
			assert_eq!(builder_pis[i].an, fb_pi.an, "AN mismatch at slot {i}");
			assert_eq!(builder_pis[i].nc, fb_pi.nc, "NC mismatch at slot {i}");
			assert_eq!(builder_pis[i].nn, fb_pi.nn, "NN mismatch at slot {i}");
		}
	}
}
