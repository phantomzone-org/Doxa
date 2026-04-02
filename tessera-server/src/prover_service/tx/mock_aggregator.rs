use alloy::primitives::U256;
use tessera_client::NOTE_BATCH;
use tessera_utils::hasher::HashOutput;

use super::aggregator::TxAggregator;
use crate::{
	proof_aggregation::tx_super_aggregator_v2::SuperAggregator,
	sequencer::FinalizedBatch,
	types::{ProveOutcome, SolidityProof},
};

// ---------------------------------------------------------------------------
// MockTxAggregator
// ---------------------------------------------------------------------------

/// A [`TxAggregator`] implementation for tests and development.
///
/// Produces a [`ProveOutcome::Success`] with:
///
/// * **`batch_poseidon_root`** — taken directly from `batch` (computed correctly by
///   [`FinalizedBatch::finalize`] via `SubtreeRootCircuit::compute_root_native`).
/// * **`super_pi_commitment`** — computed via [`SuperAggregator::compute_pi_commitment_native`],
///   which matches the Solidity contract's `_computeTxPiCommitment`.
/// * **`solidity_proof`** — random `[U256; 8]` elements, accepted by the `AcceptAllVerifier` stub
///   deployed in tests.
pub struct MockTxAggregator;

impl TxAggregator for MockTxAggregator {
	fn compute_pi_commitment(
		&self,
		batch: &FinalizedBatch,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> anyhow::Result<[u8; 32]> {
		// `nc_leaves` / `nn_leaves` have stride = NOTE_BATCH + 1 = 8:
		//   indices 0..NOTE_BATCH-1 are NC/NN, index NOTE_BATCH is the AC/AN copy.
		let stride = NOTE_BATCH + 1;
		let n_slots = batch.ac_leaves.len();

		let account_commitments: Vec<HashOutput> = batch
			.ac_leaves
			.iter()
			.map(|b| HashOutput::from_encoded_fields_unchecked(*b))
			.collect();

		let mut account_nullifiers: Vec<HashOutput> =
			Vec::with_capacity(batch.tx_proofs_by_slot.len());
		let mut note_nullifiers: Vec<HashOutput> =
			Vec::with_capacity(batch.tx_proofs_by_slot.len() * NOTE_BATCH);
		for s in 0..n_slots {
			if batch.tx_proofs_by_slot.contains_key(&s) {
				account_nullifiers.push(HashOutput::from_encoded_fields_unchecked(
					batch.an_leaves[s],
				));
				let nn_base = s * stride;
				for j in 0..NOTE_BATCH {
					note_nullifiers.push(HashOutput::from_encoded_fields_unchecked(
						batch.nn_leaves[nn_base + j],
					));
				}
			}
		}

		let mut note_commitments: Vec<HashOutput> = Vec::with_capacity(n_slots * NOTE_BATCH);
		for s in 0..n_slots {
			let nc_base = s * stride;
			for j in 0..NOTE_BATCH {
				note_commitments.push(HashOutput::from_encoded_fields_unchecked(
					batch.nc_leaves[nc_base + j],
				));
			}
		}

		let u32s = SuperAggregator::compute_pi_commitment_native(
			root,
			main_pool_cfg_root,
			batch.batch_poseidon_root,
			&account_commitments,
			&account_nullifiers,
			&note_commitments,
			&note_nullifiers,
		);

		let mut result = [0u8; 32];
		for (i, &w) in u32s.iter().enumerate() {
			result[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
		}
		Ok(result)
	}

	fn prove(
		&self,
		batch: &FinalizedBatch,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
		batch_id: u64,
	) -> anyhow::Result<ProveOutcome> {
		let super_pi_commitment = self.compute_pi_commitment(batch, root, main_pool_cfg_root)?;

		Ok(ProveOutcome::Success {
			batch_id,
			batch_poseidon_root: batch.batch_poseidon_root,
			solidity_proof: Box::new(random_solidity_proof()),
			super_pi_commitment,
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_solidity_proof() -> SolidityProof {
	SolidityProof {
		proof: std::array::from_fn(|_| random_u256()),
		commitments: std::array::from_fn(|_| random_u256()),
		commitment_pok: std::array::from_fn(|_| random_u256()),
	}
}

fn random_u256() -> U256 {
	let lo = rand::random::<u128>();
	let hi = rand::random::<u128>();
	U256::from(lo) | (U256::from(hi) << 128)
}
