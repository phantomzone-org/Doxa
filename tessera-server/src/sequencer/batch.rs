//! Slot-centric batch builder for the sequencer.
//!
//! Replaces the old four-independent-queue approach with a single array of
//! [`BatchSlot`]s.  Each slot is either a real private TX, a deposit
//! mini-batch (up to 8 NC notes packed), or an empty (all-dummy) slot.

use std::collections::{HashMap, HashSet};

use alloy::primitives::FixedBytes;
use tessera_trees::{
	proof_aggregation::SubtreeRootCircuit,
	tree::hasher::HashOutput,
	F,
};

use crate::{
	dummy::derive_dummy_leaf,
	types::{ConsumeProveRequest, ProveRequestV2},
};

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
	/// Poseidon Merkle root of the NC leaves (V2).
	///
	/// Equal to `SubtreeRootCircuit::compute_root_native(nc_leaves_as_HashOutput)`.
	/// Passed to `submitTransactionBatch` on-chain and proved in-circuit by
	/// `SubtreeRootCircuit`.
	pub batch_poseidon_root: HashOutput,
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
	/// Create a new batch builder for the V2 sequencer (no off-chain trees).
	///
	/// Uses `dummy_root` for deterministic dummy leaf derivation and zero-based
	/// start indices for all four leaf arrays.  In V2, the root and start index
	/// only affect padding leaves, which are discarded after proving.
	pub fn new_v2(account_batch_size: usize, dummy_root: [u8; 32]) -> Self {
		let note_batch_size = account_batch_size * NOTES_PER_SLOT;
		Self {
			slots: Vec::with_capacity(account_batch_size),
			account_batch_size,
			note_batch_size,
			open_deposit: None,
			ac_root: dummy_root,
			an_root: dummy_root,
			nc_root: dummy_root,
			nn_root: dummy_root,
			ac_start: 0,
			an_start: 0,
			nc_start: 0,
			nn_start: 0,
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

		// 6. Compute V2 Poseidon subtree root over NC leaves.
		//
		// Uses non-validating conversion so that V1 keccak-derived dummy leaves
		// (which may be out of the Goldilocks range) don't cause a panic here.
		// V2 NC leaves are always valid Goldilocks elements, so the result is
		// correct for V2 use.  V1 code never reads `batch_poseidon_root`.
		let nc_hashes: Vec<HashOutput> = nc_leaves.iter().map(nc_leaf_to_hash_unchecked).collect();
		let batch_poseidon_root = SubtreeRootCircuit::compute_root_native(&nc_hashes);

		FinalizedBatch {
			ac_leaves,
			an_sorted,
			an_sort_perm: an_sort_perm_inv,
			nc_leaves,
			nn_sorted,
			nn_sort_perm: nn_sort_perm_inv,
			tx_proofs_by_slot,
			batch_poseidon_root,
		}
	}
}

/// Convert a 32-byte leaf (big-endian 4 × u64) to a `HashOutput` without range validation.
///
/// Each 8-byte chunk is interpreted as a big-endian `u64` and stored as a
/// Goldilocks field element via `from_noncanonical_u64` (which does NOT check
/// that the value is below the Goldilocks prime).  This is safe for V2 NC
/// leaves (which are always valid field elements) and avoids panics for V1
/// keccak-derived dummy leaves (which may be out of range but are never fed
/// into V2 circuits).
fn nc_leaf_to_hash_unchecked(b: &[u8; 32]) -> HashOutput {
	use plonky2::field::types::Field;
	HashOutput::new(core::array::from_fn(|i| {
		let val = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
		F::from_noncanonical_u64(val)
	}))
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

	/// Assemble a [`ProveRequestV2`] from the finalized V2 batch.
	///
	/// The `nc_leaves` and `tx_proofs_by_slot` come from the batch; the three
	/// root values are provided by the caller from the Sequencer's current
	/// on-chain state.
	pub fn into_prove_request_v2(
		&self,
		batch_id: u64,
		ac_root: HashOutput,
		nc_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> ProveRequestV2 {
		ProveRequestV2 {
			batch_id,
			nc_leaves: self.nc_leaves.clone(),
			ac_root,
			nc_root,
			main_pool_cfg_root,
			tx_proofs_by_slot: self.tx_proofs_by_slot.clone(),
		}
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

// ---------------------------------------------------------------------------
// Consume (deposit) batch builder
// ---------------------------------------------------------------------------

/// Leaf data produced by [`ConsumeBatchBuilder::finalize`].
pub struct FinalizedConsumeBatch {
	/// Real deposit note commitments in arrival order (for `submitDepositBatch`).
	///
	/// All entries are validated `Pending` on-chain before submission.
	/// Length ≤ `note_batch_size`.
	pub deposit_note_commitments: Vec<[u8; 32]>,
	/// NC leaves (real + dummy padding) for the SubtreeRootCircuit.
	///
	/// Length = `note_batch_size`.
	pub nc_leaves: Vec<[u8; 32]>,
	/// Poseidon Merkle root over `nc_leaves`.
	pub batch_poseidon_root: HashOutput,
	/// Consume proof bytes keyed by note index.
	///
	/// Present for each real deposit note that was submitted with a proof.
	/// The prover uses these as consume-circuit leaf proofs.
	pub consume_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

impl FinalizedConsumeBatch {
	/// Assemble a [`ConsumeProveRequest`] from this finalized consume batch.
	pub fn into_prove_request(
		&self,
		batch_id: u64,
		ac_root: HashOutput,
		nc_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> ConsumeProveRequest {
		ConsumeProveRequest {
			batch_id,
			nc_leaves: self.nc_leaves.clone(),
			ac_root,
			nc_root,
			main_pool_cfg_root,
			consume_proofs_by_slot: self.consume_proofs_by_slot.clone(),
		}
	}
}

/// Accumulates deposit note commitments for a consume (deposit) batch.
///
/// Each batch holds up to `note_batch_size` real deposit notes (from
/// individual `/consume-request` API calls).  At finalization the real notes
/// are padded with deterministic dummy leaves to reach `note_batch_size`,
/// and the Poseidon subtree root is computed over the full padded array.
pub struct ConsumeBatchBuilder {
	/// Real deposit notes in arrival order, paired with their consume proofs.
	notes: Vec<([u8; 32], Option<Vec<u8>>)>,
	/// Total capacity (= `account_batch_size × NOTES_PER_SLOT`).
	note_batch_size: usize,
	/// Dummy-leaf derivation root (= `confirmed_root` bytes at creation time).
	dummy_root: [u8; 32],
}

impl ConsumeBatchBuilder {
	/// Create a new consume batch builder.
	///
	/// - `note_batch_size`: total leaf capacity (= account_batch_size × 8).
	/// - `dummy_root`: bytes used for deterministic dummy-leaf derivation.
	pub fn new(note_batch_size: usize, dummy_root: [u8; 32]) -> Self {
		Self {
			notes: Vec::with_capacity(note_batch_size),
			note_batch_size,
			dummy_root,
		}
	}

	/// Number of real deposit notes currently in this batch.
	pub fn len(&self) -> usize {
		self.notes.len()
	}

	/// Whether the batch has no real notes yet.
	#[allow(dead_code)]
	pub fn is_empty(&self) -> bool {
		self.notes.is_empty()
	}

	/// Whether the batch is full (all note slots allocated).
	pub fn is_full(&self) -> bool {
		self.notes.len() >= self.note_batch_size
	}

	/// Add a deposit note to this batch.
	///
	/// `consume_proof`: optional proof bytes submitted by the client.
	///
	/// # Errors
	/// Returns `Err` if the batch is already full.
	pub fn add_note(
		&mut self,
		note: [u8; 32],
		consume_proof: Option<Vec<u8>>,
	) -> anyhow::Result<()> {
		anyhow::ensure!(
			!self.is_full(),
			"consume batch full; cannot add deposit note"
		);
		self.notes.push((note, consume_proof));
		Ok(())
	}

	/// Finalize: pad real notes to `note_batch_size` with dummies and compute
	/// the Poseidon subtree root.
	pub fn finalize(self) -> FinalizedConsumeBatch {
		let real_count = self.notes.len();
		let mut nc_leaves = Vec::with_capacity(self.note_batch_size);
		let mut deposit_note_commitments = Vec::with_capacity(real_count);
		let mut consume_proofs_by_slot = HashMap::new();

		for (idx, (note, proof)) in self.notes.into_iter().enumerate() {
			deposit_note_commitments.push(note);
			nc_leaves.push(note);
			if let Some(p) = proof {
				consume_proofs_by_slot.insert(idx, p);
			}
		}

		// Pad remaining slots with deterministic dummy leaves.
		for idx in real_count..self.note_batch_size {
			nc_leaves.push(derive_dummy_leaf(idx, &self.dummy_root));
		}

		let nc_hashes: Vec<HashOutput> = nc_leaves.iter().map(nc_leaf_to_hash_unchecked).collect();
		let batch_poseidon_root = SubtreeRootCircuit::compute_root_native(&nc_hashes);

		FinalizedConsumeBatch {
			deposit_note_commitments,
			nc_leaves,
			batch_poseidon_root,
			consume_proofs_by_slot,
		}
	}
}

#[cfg(test)]
mod tests {
	use plonky2::field::types::Field;

	use super::*;
	use crate::contract;

	const ACCOUNT_BATCH: usize = 4;
	const NOTE_BATCH: usize = ACCOUNT_BATCH * NOTES_PER_SLOT;

	fn dummy_root() -> [u8; 32] {
		[0u8; 32]
	}

	fn dummy_leaf(val: u8) -> [u8; 32] {
		[val; 32]
	}

	#[test]
	fn add_private_tx_fills_batch() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
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
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());

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
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());

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

		// V2: batch_poseidon_root must equal the native Poseidon Merkle root of NC leaves.
		let nc_hashes = contract::bytes_slice_to_hashes(&batch.nc_leaves).unwrap();
		let expected_root = SubtreeRootCircuit::compute_root_native(&nc_hashes);
		assert_eq!(
			batch.batch_poseidon_root, expected_root,
			"batch_poseidon_root mismatch"
		);
	}

	#[test]
	fn tx_pi_matches_after_finalize() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());

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

	#[test]
	fn v2_fills_to_capacity() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		assert!(!bb.is_full());
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
			assert_eq!(
				full,
				i == ACCOUNT_BATCH - 1,
				"is_full signal wrong at slot {i}"
			);
		}
		assert!(bb.is_full());
		assert!(bb
			.add_private_tx(vec![], [0; 32], [0; 32], [[0; 32]; 8], [[0; 32]; 8])
			.is_err());
	}

	#[test]
	fn v2_finalize_leaf_counts() {
		// 2 private TXs + 3 deposits → 3 slots (deposit packs into 1 slot).
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		bb.add_private_tx(
			vec![1],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		bb.add_private_tx(
			vec![2],
			dummy_leaf(5),
			dummy_leaf(6),
			[dummy_leaf(7); 8],
			[dummy_leaf(8); 8],
		)
		.unwrap();
		for i in 0..3u8 {
			bb.add_deposit(dummy_leaf(50 + i)).unwrap();
		}

		let fb = bb.finalize();

		assert_eq!(fb.ac_leaves.len(), ACCOUNT_BATCH, "ac_leaves len");
		assert_eq!(fb.an_sorted.len(), ACCOUNT_BATCH, "an_sorted len");
		assert_eq!(fb.an_sort_perm.len(), ACCOUNT_BATCH, "an_sort_perm len");
		assert_eq!(
			fb.nc_leaves.len(),
			ACCOUNT_BATCH * NOTES_PER_SLOT,
			"nc_leaves len"
		);
		assert_eq!(
			fb.nn_sorted.len(),
			ACCOUNT_BATCH * NOTES_PER_SLOT,
			"nn_sorted len"
		);
		assert_eq!(
			fb.nn_sort_perm.len(),
			ACCOUNT_BATCH * NOTES_PER_SLOT,
			"nn_sort_perm len"
		);
		// 2 real TX slots.
		assert_eq!(fb.tx_proofs_by_slot.len(), 2);
		assert!(fb.tx_proofs_by_slot.contains_key(&0));
		assert!(fb.tx_proofs_by_slot.contains_key(&1));
	}

	#[test]
	fn v2_finalize_poseidon_root() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		bb.add_private_tx(
			vec![0xFF],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		bb.add_deposit(dummy_leaf(10)).unwrap();

		let fb = bb.finalize();

		let nc_hashes = contract::bytes_slice_to_hashes(&fb.nc_leaves).unwrap();
		let expected = SubtreeRootCircuit::compute_root_native(&nc_hashes);
		assert_eq!(
			fb.batch_poseidon_root, expected,
			"V2 batch_poseidon_root does not match recomputed native root"
		);
	}

	#[test]
	fn v2_tx_proofs_keyed_by_slot() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		// Slot 0: private TX with proof bytes [0xAA].
		bb.add_private_tx(
			vec![0xAA],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		// Slot 1: deposit (no proof).
		bb.add_deposit(dummy_leaf(10)).unwrap();
		// Slot 2: private TX with proof bytes [0xBB].
		bb.add_private_tx(
			vec![0xBB],
			dummy_leaf(5),
			dummy_leaf(6),
			[dummy_leaf(7); 8],
			[dummy_leaf(8); 8],
		)
		.unwrap();

		let fb = bb.finalize();

		assert_eq!(fb.tx_proofs_by_slot.len(), 2, "should have 2 real proofs");
		assert_eq!(
			fb.tx_proofs_by_slot[&0],
			vec![0xAA],
			"slot 0 proof mismatch"
		);
		assert_eq!(
			fb.tx_proofs_by_slot[&2],
			vec![0xBB],
			"slot 2 proof mismatch"
		);
		assert!(
			!fb.tx_proofs_by_slot.contains_key(&1),
			"slot 1 should be absent (deposit)"
		);
	}

	#[test]
	fn v2_sorted_leaves() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		// Add slots with deliberately out-of-order AN / NN bytes.
		for i in (0..ACCOUNT_BATCH as u8).rev() {
			bb.add_private_tx(
				vec![i],
				dummy_leaf(i),
				dummy_leaf(i + 100), // AN values: 103, 102, 101, 100 — reverse order
				[dummy_leaf(i + 10); 8],
				[dummy_leaf(i + 20); 8], // NN values: similarly reverse
			)
			.unwrap();
		}
		let fb = bb.finalize();
		assert!(is_sorted_u256(&fb.an_sorted), "an_sorted is not sorted");
		assert!(is_sorted_u256(&fb.nn_sorted), "nn_sorted is not sorted");
	}

	#[test]
	fn v2_contains_an_nn_dedup() {
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		let an = dummy_leaf(0xAA);
		let nn = dummy_leaf(0xBB);

		assert!(!bb.contains_an(&an));
		assert!(!bb.contains_nn(&nn));

		bb.add_private_tx(vec![1], dummy_leaf(1), an, [[0; 32]; 8], [nn; 8])
			.unwrap();

		assert!(bb.contains_an(&an), "AN should be in batch after adding TX");
		assert!(bb.contains_nn(&nn), "NN should be in batch after adding TX");
	}

	#[test]
	fn v2_into_prove_request() {
		use plonky2::field::types::Field;
		let mut bb = BatchBuilder::new_v2(ACCOUNT_BATCH, dummy_root());
		bb.add_private_tx(
			vec![0xCC],
			dummy_leaf(1),
			dummy_leaf(2),
			[dummy_leaf(3); 8],
			[dummy_leaf(4); 8],
		)
		.unwrap();
		let fb = bb.finalize();

		let ac_root = HashOutput::new([F::from_canonical_u64(1), F::ZERO, F::ZERO, F::ZERO]);
		let nc_root = HashOutput::new([F::from_canonical_u64(2), F::ZERO, F::ZERO, F::ZERO]);
		let cfg_root = [0x11u8; 32];

		let req = fb.into_prove_request_v2(42, ac_root, nc_root, cfg_root);

		assert_eq!(req.batch_id, 42);
		assert_eq!(req.nc_leaves, fb.nc_leaves);
		assert_eq!(req.ac_root, ac_root);
		assert_eq!(req.nc_root, nc_root);
		assert_eq!(req.main_pool_cfg_root, cfg_root);
		assert_eq!(req.tx_proofs_by_slot, fb.tx_proofs_by_slot);
	}

	// -------------------------------------------------------------------------
	// ConsumeBatchBuilder tests
	// -------------------------------------------------------------------------

	#[test]
	fn consume_builder_fills_to_capacity() {
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		assert!(cb.is_empty());
		for i in 0..NOTE_BATCH {
			cb.add_note(dummy_leaf(i as u8), None).unwrap();
			assert_eq!(cb.len(), i + 1);
		}
		assert!(cb.is_full());
		assert!(
			cb.add_note([0; 32], None).is_err(),
			"should reject when full"
		);
	}

	#[test]
	fn consume_finalize_leaf_counts() {
		let real_notes = 5usize;
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		for i in 0..real_notes {
			cb.add_note(dummy_leaf(i as u8), None).unwrap();
		}
		let fb = cb.finalize();

		assert_eq!(
			fb.nc_leaves.len(),
			NOTE_BATCH,
			"nc_leaves must be padded to full note_batch_size"
		);
		assert_eq!(
			fb.deposit_note_commitments.len(),
			real_notes,
			"deposit_note_commitments should contain only real notes"
		);
	}

	#[test]
	fn consume_finalize_real_notes_first() {
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		let note_a = [0xAAu8; 32];
		let note_b = [0xBBu8; 32];
		cb.add_note(note_a, None).unwrap();
		cb.add_note(note_b, None).unwrap();

		let fb = cb.finalize();

		// First two nc_leaves must be the real notes in arrival order.
		assert_eq!(fb.nc_leaves[0], note_a, "first nc leaf should be note_a");
		assert_eq!(fb.nc_leaves[1], note_b, "second nc leaf should be note_b");
		// deposit_note_commitments matches.
		assert_eq!(fb.deposit_note_commitments, vec![note_a, note_b]);
	}

	#[test]
	fn consume_finalize_poseidon_root() {
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		for i in 0..3u8 {
			cb.add_note(dummy_leaf(i), Some(vec![i])).unwrap();
		}
		let fb = cb.finalize();

		let nc_hashes: Vec<HashOutput> = fb
			.nc_leaves
			.iter()
			.map(|b| {
				HashOutput::new(core::array::from_fn(|i| {
					F::from_canonical_u64(u64::from_be_bytes(
						b[i * 8..(i + 1) * 8].try_into().unwrap(),
					))
				}))
			})
			.collect();
		let expected = SubtreeRootCircuit::compute_root_native(&nc_hashes);
		assert_eq!(
			fb.batch_poseidon_root, expected,
			"consume batch_poseidon_root mismatch"
		);
	}

	#[test]
	fn consume_finalize_proofs_by_slot() {
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		// Note 0: has proof.
		cb.add_note(dummy_leaf(1), Some(vec![0xAA])).unwrap();
		// Note 1: no proof.
		cb.add_note(dummy_leaf(2), None).unwrap();
		// Note 2: has proof.
		cb.add_note(dummy_leaf(3), Some(vec![0xBB])).unwrap();

		let fb = cb.finalize();

		assert_eq!(fb.consume_proofs_by_slot.len(), 2, "should have 2 proofs");
		assert_eq!(fb.consume_proofs_by_slot[&0], vec![0xAA], "slot 0 proof");
		assert!(!fb.consume_proofs_by_slot.contains_key(&1), "slot 1 absent");
		assert_eq!(fb.consume_proofs_by_slot[&2], vec![0xBB], "slot 2 proof");
	}

	#[test]
	fn consume_into_prove_request() {
		let mut cb = ConsumeBatchBuilder::new(NOTE_BATCH, dummy_root());
		cb.add_note(dummy_leaf(1), Some(vec![0xDD])).unwrap();
		cb.add_note(dummy_leaf(2), None).unwrap();
		let fb = cb.finalize();

		let ac_root = HashOutput::new([F::from_canonical_u64(10), F::ZERO, F::ZERO, F::ZERO]);
		let nc_root = HashOutput::new([F::from_canonical_u64(20), F::ZERO, F::ZERO, F::ZERO]);
		let cfg_root = [0x22u8; 32];

		let req = fb.into_prove_request(99, ac_root, nc_root, cfg_root);

		assert_eq!(req.batch_id, 99);
		assert_eq!(req.nc_leaves, fb.nc_leaves);
		assert_eq!(req.ac_root, ac_root);
		assert_eq!(req.nc_root, nc_root);
		assert_eq!(req.main_pool_cfg_root, cfg_root);
		assert_eq!(req.consume_proofs_by_slot, fb.consume_proofs_by_slot);
	}
}
