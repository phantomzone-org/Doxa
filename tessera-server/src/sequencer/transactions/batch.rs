//! Slot-centric batch builder for the sequencer.
//!
//! Replaces the old four-independent-queue approach with a single array of
//! [`BatchSlot`]s.  Each slot is either a real private TX, a deposit
//! mini-batch (up to 8 NC notes packed), or an empty (all-dummy) slot.

use std::collections::{HashMap, HashSet};

use alloy::primitives::FixedBytes;
use plonky2::field::types::{Field, PrimeField64};
use tessera_client::{NOTE_BATCH, PRIV_TX_BATCH_SIZE};
use tessera_utils::{hasher::HashOutput, F};

use crate::{proof_aggregation::SubtreeRootCircuit, types::ProveRequest};

/// Fixed dummy leaf value for all padding/empty slots.
///
/// Equals `double_hash_native([0;4])` encoded as 4 × big-endian u64.
/// The pre-computed dummy TX proof (is_fake=true) produces this value for
/// all AN, AC, NC, and NN public inputs, ensuring the on-chain batch data
/// matches the circuit's keccak piCommitment preimage.
pub fn dummy_leaf() -> [u8; 32] {
	let h = tessera_client::double_hash_native([F::ZERO; 4]);
	let mut out = [0u8; 32];
	for (i, &f) in h.iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_be_bytes());
	}
	out
}

/// Per-slot public inputs: the four tree leaves for one account-level slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotPI {
	pub ac: [u8; 32],
	pub an: [u8; 32],
	pub nc: [[u8; 32]; NOTE_BATCH],
	pub nn: [[u8; 32]; NOTE_BATCH],
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
		/// NC leaves: extracted from tx_proof PIs.
		nc: [[u8; 32]; NOTE_BATCH],
		/// NN leaves: extracted from tx_proof PIs.
		nn: [[u8; 32]; NOTE_BATCH],
	},
	/// Empty: all four trees padded with deterministic dummies.
	Empty {
		ac: [u8; 32],
		an: [u8; 32],
		nc: [[u8; 32]; NOTE_BATCH],
		nn: [[u8; 32]; NOTE_BATCH],
	},
}

/// Leaf arrays produced by [`BatchBuilder::finalize`].
///
/// All arrays are in slot/arrival order, matching the circuit's layout.
#[allow(dead_code)]
pub struct FinalizedBatch {
	/// AC leaves in slot order (len = `priv_tx_batch_size`).
	pub ac_leaves: Vec<[u8; 32]>,
	/// AN leaves in slot order (len = `priv_tx_batch_size`).
	pub an_leaves: Vec<[u8; 32]>,
	/// NC leaves in slot order (len = `note_batch_size`).
	pub nc_leaves: Vec<[u8; 32]>,
	/// NN leaves in slot order (len = `note_batch_size`).
	pub nn_leaves: Vec<[u8; 32]>,
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

/// Incrementally builds a batch of `priv_tx_batch_size` slots.
///
/// Tree batch sizes:
///   - AC, AN: `priv_tx_batch_size` leaves (1 per slot).
///   - NC, NN: `note_batch_size = priv_tx_batch_size ×` [`NOTE_BATCH`] leaves ([`NOTE_BATCH`] per
///     slot).
pub struct BatchBuilder {
	slots: Vec<BatchSlot>,
	/// AN leaves currently in this batch (for duplicate detection).
	an_in_batch: HashSet<[u8; 32]>,
	/// NN leaves currently in this batch (for duplicate detection).
	nn_in_batch: HashSet<[u8; 32]>,
}

impl BatchBuilder {
	/// Create a new batch builder for the V2 sequencer.
	///
	/// Padding leaves use the fixed `dummy_leaf()` value, which matches the
	/// pre-computed dummy TX proof's public inputs.
	pub fn new() -> Self {
		Self {
			slots: Vec::with_capacity(PRIV_TX_BATCH_SIZE),
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
		self.slots.len() >= PRIV_TX_BATCH_SIZE
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
		nc: [[u8; 32]; NOTE_BATCH],
		nn: [[u8; 32]; NOTE_BATCH],
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
	/// pad remaining slots with `Empty` up to `priv_tx_batch_size`.
	///
	/// Idempotent: calling `pad()` on an already-padded builder is a no-op.
	pub fn pad(&mut self) {
		// 1. Pad remaining slots with Empty.
		while self.slots.len() < PRIV_TX_BATCH_SIZE {
			let padding_commitment_leaf = dummy_leaf(); // TODO: ensure it matches fixed fake proof PI
			let padding_nullifier_leaf = dummy_leaf(); // TODO: ensure it matches fixed fake proof PI

			let nc: [[u8; 32]; NOTE_BATCH] = core::array::from_fn(|_| padding_commitment_leaf);

			let nn: [[u8; 32]; NOTE_BATCH] = core::array::from_fn(|_| padding_nullifier_leaf);

			self.slots.push(BatchSlot::Empty {
				ac: padding_commitment_leaf,
				an: padding_nullifier_leaf,
				nc,
				nn,
			});
		}
	}

	/// Finalize the batch: pad, build leaf arrays, and return the
	/// [`FinalizedBatch`].
	///
	/// All leaf arrays are stored in slot/arrival order, matching the circuit
	/// layout (no sorting).
	///
	/// After this call the `BatchBuilder` is consumed.
	pub fn finalize(mut self) -> FinalizedBatch {
		self.pad();

		let mut ac_leaves = Vec::with_capacity(PRIV_TX_BATCH_SIZE);
		let mut an_leaves = Vec::with_capacity(PRIV_TX_BATCH_SIZE);
		// nc_leaves: 8 entries per slot (7 NC + 1 AC), total 512.
		let mut nc_leaves = Vec::with_capacity(PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1));
		// nn_leaves: 8 entries per slot (7 NN + 1 AN), total 512.
		let mut nn_leaves = Vec::with_capacity(PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1));
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
					an_leaves.push(an);
					nc_leaves.extend_from_slice(&nc);
					nc_leaves.push(ac);
					nn_leaves.extend_from_slice(&nn);
					nn_leaves.push(an);
				},
				BatchSlot::Empty {
					ac,
					an,
					nc,
					nn,
				} => {
					ac_leaves.push(ac);
					an_leaves.push(an);
					nc_leaves.extend_from_slice(&nc);
					nc_leaves.push(ac);
					nn_leaves.extend_from_slice(&nn);
					nn_leaves.push(an);
				},
			}
		}

		// Poseidon subtree root over nc_leaves: 8 per slot × 64 slots = 512 (power of two).
		let nc_hashes: Vec<HashOutput> = nc_leaves
			.iter()
			.map(|c| HashOutput::from_encoded_fields(*c))
			.collect();
		let batch_poseidon_root = SubtreeRootCircuit::compute_root_native(&nc_hashes);

		FinalizedBatch {
			ac_leaves,
			an_leaves,
			nc_leaves,
			nn_leaves,
			tx_proofs_by_slot,
			batch_poseidon_root,
		}
	}
}

impl FinalizedBatch {
	/// Return the public inputs for the i-th slot (arrival/slot order).
	///
	/// # Panics
	/// Panics if `i` is out of range for the batch.
	pub fn tx_pi(&self, i: usize) -> SlotPI {
		let ac = self.ac_leaves[i];
		let an = self.an_leaves[i];

		let stride = NOTE_BATCH + 1;
		let nc_base = i * stride;
		let nc: [[u8; 32]; NOTE_BATCH] = core::array::from_fn(|j| self.nc_leaves[nc_base + j]);

		let nn_base = i * stride;
		let nn: [[u8; 32]; NOTE_BATCH] = core::array::from_fn(|j| self.nn_leaves[nn_base + j]);

		SlotPI {
			ac,
			an,
			nc,
			nn,
		}
	}

	/// Assemble a [`ProveRequestV2`] from the finalized V2 batch.
	///
	/// The `nc_leaves` and `tx_proofs_by_slot` come from the batch; the root and
	/// pool-config root are provided by the caller from the Sequencer's current
	/// on-chain state.
	pub fn into_prove_request_v2(
		&self,
		batch_id: u64,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> ProveRequest {
		ProveRequest {
			batch_id,
			nc_leaves: self.nc_leaves.clone(),
			root,
			main_pool_cfg_root,
			tx_proofs_by_slot: self.tx_proofs_by_slot.clone(),
		}
	}

	/// Convert leaf arrays to `FixedBytes<32>` for on-chain submission.
	pub fn nc_fixed(&self) -> Vec<FixedBytes<32>> {
		self.nc_leaves
			.iter()
			.map(|b| FixedBytes::from(*b))
			.collect()
	}

	pub fn nn_fixed(&self) -> Vec<FixedBytes<32>> {
		self.nn_leaves
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
		self.an_leaves
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

#[cfg(test)]
mod tests {
	use tessera_client::PRIV_TX_BATCH_SIZE;

	use super::*;
	use crate::contract;

	fn test_leaf(val: u8) -> [u8; 32] {
		[val; 32]
	}

	#[test]
	fn add_private_tx_fills_batch() {
		let mut bb = BatchBuilder::new();
		for i in 0..PRIV_TX_BATCH_SIZE {
			let full = bb
				.add_private_tx(
					vec![i as u8],
					test_leaf(i as u8),
					test_leaf(i as u8 + 100),
					[test_leaf(i as u8 + 10); NOTE_BATCH],
					[test_leaf(i as u8 + 20); NOTE_BATCH],
				)
				.unwrap();
			assert_eq!(full, i == PRIV_TX_BATCH_SIZE - 1);
		}
		assert!(bb.is_full());

		// Should fail to add more.
		assert!(bb
			.add_private_tx(
				vec![],
				[0; 32],
				[0; 32],
				[[0; 32]; NOTE_BATCH],
				[[0; 32]; NOTE_BATCH]
			)
			.is_err());
	}

	#[test]
	fn finalize_pads_correctly() {
		let mut bb = BatchBuilder::new();

		// 1 real TX + 2 deposits
		bb.add_private_tx(
			vec![0xFF],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();

		let batch = bb.finalize();

		// Should have PRIV_TX_BATCH_SIZE AC/AN leaves and PRIV_TX_BATCH_SIZE * 8 NC/NN leaves.
		assert_eq!(batch.ac_leaves.len(), PRIV_TX_BATCH_SIZE);
		assert_eq!(batch.an_leaves.len(), PRIV_TX_BATCH_SIZE);
		assert_eq!(batch.nc_leaves.len(), PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1));
		assert_eq!(batch.nn_leaves.len(), PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1));

		// Real slots: only slot 0 (has a tx proof).
		assert_eq!(batch.tx_proofs_by_slot.len(), 1);
		assert!(batch.tx_proofs_by_slot.contains_key(&0));

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
		let mut bb = BatchBuilder::new();

		// 1 real TX + 2 deposits (partially filling one deposit slot)
		bb.add_private_tx(
			vec![0xFF],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();

		// Pad in place so we can read PIs before consuming
		bb.pad();

		// Snapshot PIs from builder
		let builder_pis: Vec<SlotPI> = (0..PRIV_TX_BATCH_SIZE).map(|i| bb.tx_pi(i)).collect();

		// Finalize (consumes builder)
		let fb = bb.finalize();

		// Compare slot-by-slot
		for (i, bpi) in builder_pis.iter().enumerate().take(PRIV_TX_BATCH_SIZE) {
			let fb_pi = fb.tx_pi(i);
			assert_eq!(bpi.ac, fb_pi.ac, "AC mismatch at slot {i}");
			assert_eq!(bpi.an, fb_pi.an, "AN mismatch at slot {i}");
			assert_eq!(bpi.nc, fb_pi.nc, "NC mismatch at slot {i}");
			assert_eq!(bpi.nn, fb_pi.nn, "NN mismatch at slot {i}");
		}
	}

	#[test]
	fn v2_fills_to_capacity() {
		let mut bb = BatchBuilder::new();
		assert!(!bb.is_full());
		for i in 0..PRIV_TX_BATCH_SIZE {
			let full = bb
				.add_private_tx(
					vec![i as u8],
					test_leaf(i as u8),
					test_leaf(i as u8 + 100),
					[test_leaf(i as u8 + 10); NOTE_BATCH],
					[test_leaf(i as u8 + 20); NOTE_BATCH],
				)
				.unwrap();
			assert_eq!(
				full,
				i == PRIV_TX_BATCH_SIZE - 1,
				"is_full signal wrong at slot {i}"
			);
		}
		assert!(bb.is_full());
		assert!(bb
			.add_private_tx(
				vec![],
				[0; 32],
				[0; 32],
				[[0; 32]; NOTE_BATCH],
				[[0; 32]; NOTE_BATCH]
			)
			.is_err());
	}

	#[test]
	fn v2_finalize_leaf_counts() {
		// 2 private TXs + 3 deposits → 3 slots (deposit packs into 1 slot).
		let mut bb = BatchBuilder::new();
		bb.add_private_tx(
			vec![1],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();
		bb.add_private_tx(
			vec![2],
			test_leaf(5),
			test_leaf(6),
			[test_leaf(7); NOTE_BATCH],
			[test_leaf(8); NOTE_BATCH],
		)
		.unwrap();

		let fb = bb.finalize();

		assert_eq!(fb.ac_leaves.len(), PRIV_TX_BATCH_SIZE, "ac_leaves len");
		assert_eq!(fb.an_leaves.len(), PRIV_TX_BATCH_SIZE, "an_leaves len");
		assert_eq!(
			fb.nc_leaves.len(),
			PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1),
			"nc_leaves len"
		);
		assert_eq!(
			fb.nn_leaves.len(),
			PRIV_TX_BATCH_SIZE * (NOTE_BATCH + 1),
			"nn_leaves len"
		);
		// 2 real TX slots.
		assert_eq!(fb.tx_proofs_by_slot.len(), 2);
		assert!(fb.tx_proofs_by_slot.contains_key(&0));
		assert!(fb.tx_proofs_by_slot.contains_key(&1));
	}

	#[test]
	fn v2_finalize_poseidon_root() {
		let mut bb = BatchBuilder::new();
		bb.add_private_tx(
			vec![0xFF],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();

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
		let mut bb = BatchBuilder::new();
		// Slot 0: private TX with proof bytes [0xAA].
		bb.add_private_tx(
			vec![0xAA],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();
		// Slot 2: private TX with proof bytes [0xBB].
		bb.add_private_tx(
			vec![0xBB],
			test_leaf(5),
			test_leaf(6),
			[test_leaf(7); NOTE_BATCH],
			[test_leaf(8); NOTE_BATCH],
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
	fn v2_contains_an_nn_dedup() {
		let mut bb = BatchBuilder::new();
		let an = test_leaf(0xAA);
		let nn = test_leaf(0xBB);

		assert!(!bb.contains_an(&an));
		assert!(!bb.contains_nn(&nn));

		bb.add_private_tx(
			vec![1],
			test_leaf(1),
			an,
			[[0; 32]; NOTE_BATCH],
			[nn; NOTE_BATCH],
		)
		.unwrap();

		assert!(bb.contains_an(&an), "AN should be in batch after adding TX");
		assert!(bb.contains_nn(&nn), "NN should be in batch after adding TX");
	}

	#[test]
	fn v2_into_prove_request() {
		use plonky2::field::types::Field;
		let mut bb = BatchBuilder::new();
		bb.add_private_tx(
			vec![0xCC],
			test_leaf(1),
			test_leaf(2),
			[test_leaf(3); NOTE_BATCH],
			[test_leaf(4); NOTE_BATCH],
		)
		.unwrap();
		let fb = bb.finalize();

		let root = HashOutput::new([F::from_canonical_u64(1), F::ZERO, F::ZERO, F::ZERO]);
		let cfg_root = [0x11u8; 32];

		let req = fb.into_prove_request_v2(42, root, cfg_root);

		assert_eq!(req.batch_id, 42);
		assert_eq!(req.nc_leaves, fb.nc_leaves);
		assert_eq!(req.root, root);
		assert_eq!(req.main_pool_cfg_root, cfg_root);
		assert_eq!(req.tx_proofs_by_slot, fb.tx_proofs_by_slot);
	}
}
