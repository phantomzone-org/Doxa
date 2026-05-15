use alloy::primitives::U256;

use crate::{
	batch_helper::{BatchHelper, SolidityKeccak256},
	prover_service::Aggregator,
	types::{ProveOutcome, SolidityProof},
};

// ---------------------------------------------------------------------------
// MockTxAggregator
// ---------------------------------------------------------------------------

/// A [`TxAggregator`] implementation for tests and development.
pub struct MockTxAggregator;

impl Aggregator<SolidityKeccak256> for MockTxAggregator {
	fn prove(&self, batch: &impl BatchHelper, batch_id: u64) -> anyhow::Result<ProveOutcome> {
		let super_pi_commitment = batch.pi_commitment::<SolidityKeccak256>()?;

		Ok(ProveOutcome::Success {
			batch_id,
			batch_poseidon_root: batch.commitments_subtree_root()?,
			solidity_proof: random_solidity_proof(),
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
