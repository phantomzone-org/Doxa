use alloy::primitives::U256;
use plonky2::field::types::Field;
use tessera_client::DEPOSIT_BATCH_SIZE;
use tessera_utils::{hasher::HashOutput, F};

use super::aggregator::DepositAggregator;
use crate::{
	proof_aggregation::deposit_super_aggregator_v2::{
		DepositSuperAggregatorV2, DEPOSIT_LEAF_PI_SIZE, ETH_ADDR_LEN, ETH_ADDR_OFFSET,
	},
	prover_service::deposit::DepositBatch,
	types::{ProveOutcome, SolidityProof},
};

// ---------------------------------------------------------------------------
// MockDepositAggregator
// ---------------------------------------------------------------------------

/// A [`DepositAggregator`] implementation for tests and development.
///
/// Produces a [`ProveOutcome::Success`] with:
///
/// * **`batch_poseidon_root`** — taken directly from `batch` (computed correctly by
///   [`DepositBatchBuilder::finalize`]).
/// * **`super_pi_commitment`** — computed via
///   [`DepositSuperAggregatorV2::compute_deposit_pi_commitment_native`], which matches the Solidity
///   contract's `_computeDepositPiCommitment`.
/// * **`solidity_proof`** — random `[U256; 8]` elements, accepted by the `AcceptAllVerifier` stub
///   deployed in tests.
pub struct MockDepositAggregator;

impl DepositAggregator for MockDepositAggregator {
	fn prove(
		&self,
		batch: &FinalizedDepositBatchValidation,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
		batch_id: u64,
	) -> anyhow::Result<ProveOutcome> {
		let super_pi_commitment = self.compute_pi_commitment(batch, root, main_pool_cfg_root)?;

		Ok(ProveOutcome::Success {
			batch_id,
			batch_poseidon_root: batch.batch_root,
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
