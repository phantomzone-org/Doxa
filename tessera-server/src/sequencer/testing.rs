//! Test-mode sequencer methods.
//!
//! Only active when `TESSERA_TESTING=1`. Provides four operations that bypass
//! production guards (on-chain Pending check, Plonky2 proof verification) so
//! the full pipeline can be driven from HTTP calls without a real prover.

use alloy::{primitives::U256, providers::Provider};
use plonky2::field::types::Field;
use tessera_utils::hasher::HashOutput;

use super::{ConsumeBatchV2, Sequencer, TestTxRequest, TxBatchV2};
use crate::types::{ConsumeOutcome, ProveOutcomeV2, SolidityProof};

fn zero_solidity_proof() -> Box<SolidityProof> {
	Box::new(SolidityProof {
		proof: [U256::ZERO; 8],
		commitments: [U256::ZERO; 2],
		commitment_pok: [U256::ZERO; 2],
	})
}

impl Sequencer {
	/// Add a deposit note directly — no on-chain Pending check, no consume proof.
	pub(super) fn handle_test_deposit(&mut self, note: [u8; 32]) -> anyhow::Result<()> {
		self.ensure_consume_batch_builder().add_note(note, None)
	}

	/// Add a transaction slot with raw leaf values — no Plonky2 proof required.
	///
	/// An empty proof is stored; the test flush path never forwards it to the prover.
	pub(super) fn handle_test_tx(&mut self, req: TestTxRequest) -> anyhow::Result<()> {
		self.ensure_batch_builder()
			.add_private_tx(vec![], req.ac, req.an, req.nc, req.nn)
			.map(|_| ())
	}

	/// Flush the current consume batch on-chain, then immediately confirm it with a
	/// zero Groth16 proof (no remote prover involved).
	pub(super) async fn flush_consume_batch_testing<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (batch_id, pi_commitment, _prove_req) =
			self.submit_consume_batch_on_chain(provider).await?;
		self.pending_consume_batches.insert(
			batch_id,
			ConsumeBatchV2 {
				pi_commitment,
			},
		);

		let fake = ConsumeOutcome::Success {
			batch_id,
			batch_poseidon_root: HashOutput::new([tessera_utils::F::ZERO; 4]),
			solidity_proof: zero_solidity_proof(),
			super_pi_commitment: [0u8; 32],
		};
		self.confirm_consume_batch(provider, fake).await
	}

	/// Flush the current TX batch on-chain, then immediately confirm it with a
	/// zero Groth16 proof (no remote prover involved).
	pub(super) async fn flush_batch_testing<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (batch_id, pi_commitment, _prove_req) = self.submit_tx_batch_on_chain(provider).await?;
		self.pending_batches.insert(
			batch_id,
			TxBatchV2 {
				pi_commitment,
			},
		);

		let fake = ProveOutcomeV2::Success {
			batch_id,
			batch_poseidon_root: HashOutput::new([tessera_utils::F::ZERO; 4]),
			solidity_proof: zero_solidity_proof(),
			super_pi_commitment: [0u8; 32],
		};
		self.confirm_tx_batch(provider, fake).await
	}
}
