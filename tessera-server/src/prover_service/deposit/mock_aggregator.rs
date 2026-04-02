use alloy::primitives::U256;
use tessera_client::DEPOSIT_BATCH_SIZE;
use tessera_utils::{hasher::HashOutput, F};
use plonky2::field::types::Field;

use crate::{
    proof_aggregation::deposit_super_aggregator_v2::{
        DEPOSIT_LEAF_PI_SIZE, DepositSuperAggregatorV2, ETH_ADDR_LEN, ETH_ADDR_OFFSET
    }, prover_service::deposit::DepositBatch, types::{ProveOutcome, SolidityProof}
};

use super::{aggregator::DepositAggregator};

// ---------------------------------------------------------------------------
// MockDepositAggregator
// ---------------------------------------------------------------------------

/// A [`DepositAggregator`] implementation for tests and development.
///
/// Produces a [`ProveOutcome::Success`] with:
///
/// * **`batch_poseidon_root`** — taken directly from `batch` (computed
///   correctly by [`DepositBatchBuilder::finalize`]).
/// * **`super_pi_commitment`** — computed via
///   [`DepositSuperAggregatorV2::compute_deposit_pi_commitment_native`], which
///   matches the Solidity contract's `_computeDepositPiCommitment`.
/// * **`solidity_proof`** — random `[U256; 8]` elements, accepted by the
///   `AcceptAllVerifier` stub deployed in tests.
pub struct MockDepositAggregator;

impl DepositAggregator for MockDepositAggregator {
    fn compute_pi_commitment(
        &self,
        batch: &DepositBatch,
        root: HashOutput,
        main_pool_cfg_root: HashOutput,
    ) -> anyhow::Result<HashOutput> {


        // Build deposit_pis: n_slots * DEPOSIT_LEAF_PI_SIZE field elements,
        // zeroed everywhere except the ETH address limbs for real deposit slots.
        let mut deposit_pis = vec![F::ZERO; DEPOSIT_BATCH_SIZE * DEPOSIT_LEAF_PI_SIZE];

        for

        for (s, addr) in batch.eth_addresses.iter().enumerate().take(n_real) {
            let base = s * DEPOSIT_LEAF_PI_SIZE + ETH_ADDR_OFFSET;
            for k in 0..ETH_ADDR_LEN {
                // Pack 4 bytes of the 20-byte address into a u32 LE limb.
                // ETH_ADDR_LEN = 5 limbs × 4 bytes = 20 bytes.
                let limb = u32::from_le_bytes(addr[k * 4..(k + 1) * 4].try_into().unwrap());
                deposit_pis[base + k] = F::from_canonical_u32(limb);
            }
        }

        let u32s = DepositSuperAggregatorV2::compute_deposit_pi_commitment_native(
            root,
            main_pool_cfg_root,
            batch.batch_root,
            &deposit_pis,
            n_slots,
        );

        let mut result = [0u8; 32];
        for (i, &w) in u32s.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }
        Ok(result)
    }

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
