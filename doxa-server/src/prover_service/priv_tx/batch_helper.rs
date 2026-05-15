use doxa_client::{
	build_priv_tx_circuit, plonky2_gadgets::priv_tx::PrivTxCircuit, FakeSpendTxBuilder, PIHelper,
	PrivTxProof, PRIV_TX_BATCH_SIZE,
};
use doxa_utils::hasher::HashOutput;

use crate::batch_helper::BatchHelper;

pub struct PrivateTxBatch {
	proofs: Vec<PrivTxProof>,
	batch_poseidon_root: Option<HashOutput>,
	circuit: PrivTxCircuit,
}

impl PrivateTxBatch {
	pub fn new() -> Self {
		let circuit = build_priv_tx_circuit();
		Self {
			proofs: Vec::new(),
			batch_poseidon_root: None,
			circuit,
		}
	}

	pub fn len(&self) -> usize {
		self.proofs.len()
	}

	pub fn is_empty(&self) -> bool {
		self.proofs.is_empty()
	}
}

impl Default for PrivateTxBatch {
	fn default() -> Self {
		Self::new()
	}
}

impl BatchHelper for PrivateTxBatch {
	type Proof = PrivTxProof;

	const PROOF_BATCH_SIZE: usize = PRIV_TX_BATCH_SIZE;

	fn add_proof(&mut self, proof: PrivTxProof) -> anyhow::Result<bool> {
		anyhow::ensure!(!self.is_full(), "batch is full");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");
		if !self.proofs.is_empty() {
			anyhow::ensure!(
				proof.act_root() == self.proofs[0].act_root(),
				"act_root mismatch"
			);
			anyhow::ensure!(
				proof.mainpool_config_root() == self.proofs[0].mainpool_config_root(),
				"mainpool_config_root mismatch"
			);
		}
		self.proofs.push(proof);

		Ok(self.is_full())
	}

	fn common_act_root(&self) -> anyhow::Result<HashOutput> {
		anyhow::ensure!(!self.is_empty(), "batch is empty");
		Ok(self.proofs()[0].act_root())
	}

	fn common_main_config_root(&self) -> anyhow::Result<HashOutput> {
		anyhow::ensure!(!self.is_empty(), "batch is empty");
		Ok(self.proofs()[0].mainpool_config_root())
	}

	fn is_finalized(&self) -> bool {
		self.batch_poseidon_root.is_some()
	}

	fn commitments_subtree_root(&self) -> anyhow::Result<HashOutput> {
		self.batch_poseidon_root
			.ok_or_else(|| anyhow::anyhow!("batch is not finalized"))
	}

	fn proofs(&self) -> &[PrivTxProof] {
		&self.proofs
	}

	/// Generate one padding proof sharing the same common PIs, clone it into
	/// all remaining slots, then compute the Poseidon Merkle root over all
	/// `output_commitments()` in slot order.
	fn finalize(&mut self) -> anyhow::Result<()> {
		anyhow::ensure!(!self.is_empty(), "batch is empty");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");

		let n_padding = PRIV_TX_BATCH_SIZE - self.proofs.len();
		if n_padding > 0 {
			let act_root = self.proofs[0].act_root();
			let mainpool_config_root = self.proofs[0].mainpool_config_root();
			let padding_proof = FakeSpendTxBuilder::new(act_root, mainpool_config_root)
				.build()
				.into_priv_tx()
				.prove(&self.circuit.circuit_data, &self.circuit.targets)?;
			for _ in 0..n_padding {
				self.proofs.push(padding_proof.clone());
			}
		}

		self.batch_poseidon_root = Some(self.batch_poseidon_root()?);
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Encoding helper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use plonky2::field::types::Field;
	use rand::Rng;
	use doxa_client::{
		build_priv_tx_circuit, FakeSpendTxBuilder, PIHelper, PrivTxProof, PRIV_TX_BATCH_SIZE,
	};
	use doxa_utils::{hasher::HashOutput, F};

	use super::*;
	use crate::batch_helper::{BatchHelper, SolidityKeccak256};

	fn zero_hash() -> HashOutput {
		HashOutput([F::ZERO; 4])
	}

	fn rand_hash() -> HashOutput {
		let mut rng = rand::rng();
		HashOutput(core::array::from_fn(|_| {
			F::from_noncanonical_u64(rng.next_u64())
		}))
	}

	fn make_priv_proof(act_root: HashOutput, mainpool_config_root: HashOutput) -> PrivTxProof {
		let circuit = build_priv_tx_circuit();
		FakeSpendTxBuilder::new(act_root, mainpool_config_root)
			.build()
			.into_priv_tx()
			.prove(&circuit.circuit_data, &circuit.targets)
			.unwrap()
	}

	// ── Cheap tests (no ZK proving) ──────────────────────────────────────────

	/// `finalize` on a freshly-created empty batch must return an error.
	#[test]
	fn finalize_empty_fails() {
		let mut batch = PrivateTxBatch::new();
		assert!(
			batch.finalize().is_err(),
			"finalize on empty batch must fail"
		);
	}

	// ── Slow tests (ZK proving required — run with: cargo test -- --include-ignored) ─

	/// A second `finalize` call on an already-finalized batch must fail.
	#[test]
	#[ignore]
	fn double_finalize_fails() {
		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch.finalize().unwrap();
		assert!(
			batch.finalize().is_err(),
			"second finalize must be rejected"
		);
	}

	/// A second proof with a different `act_root` must be rejected.
	#[test]
	#[ignore]
	fn add_mismatched_act_root_fails() {
		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			batch
				.add_proof(make_priv_proof(rand_hash(), zero_hash()))
				.is_err(),
			"mismatched act_root must be rejected"
		);
	}

	/// A second proof with a different `mainpool_config_root` must be rejected.
	#[test]
	#[ignore]
	fn add_mismatched_config_root_fails() {
		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			batch
				.add_proof(make_priv_proof(zero_hash(), rand_hash()))
				.is_err(),
			"mismatched mainpool_config_root must be rejected"
		);
	}

	/// After `finalize`, `proofs()` has exactly `PRIV_TX_BATCH_SIZE` entries.
	#[test]
	#[ignore]
	fn finalize_pads_to_capacity() {
		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert_eq!(batch.len(), 1, "one proof before finalize");
		batch.finalize().unwrap();
		assert_eq!(
			batch.proofs().len(),
			PRIV_TX_BATCH_SIZE,
			"must have PRIV_TX_BATCH_SIZE proofs after finalize"
		);
	}

	/// All padding proofs added by `finalize` carry the same roots as the real proof.
	#[test]
	#[ignore]
	fn finalize_padding_shares_common_roots() {
		let act_root = rand_hash();
		let config_root = rand_hash();

		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(act_root, config_root))
			.unwrap();
		batch.finalize().unwrap();

		for (i, p) in batch.proofs().iter().enumerate() {
			assert_eq!(p.act_root(), act_root, "slot {i}: act_root mismatch");
			assert_eq!(
				p.mainpool_config_root(),
				config_root,
				"slot {i}: config_root mismatch"
			);
		}
	}

	/// `commitments_subtree_root()` is deterministic: same inputs → same root.
	#[test]
	#[ignore]
	fn subtree_root_is_deterministic() {
		fn finalized_batch() -> PrivateTxBatch {
			let mut b = PrivateTxBatch::new();
			b.add_proof(make_priv_proof(zero_hash(), zero_hash()))
				.unwrap();
			b.finalize().unwrap();
			b
		}
		let r1 = finalized_batch().commitments_subtree_root().unwrap();
		let r2 = finalized_batch().commitments_subtree_root().unwrap();
		assert_eq!(r1, r2, "subtree root must be deterministic");
	}

	/// `pi_commitment` is deterministic: same inputs → same 32-byte commitment.
	#[test]
	#[ignore]
	fn pi_commitment_is_deterministic() {
		fn finalized_batch() -> PrivateTxBatch {
			let mut b = PrivateTxBatch::new();
			b.add_proof(make_priv_proof(zero_hash(), zero_hash()))
				.unwrap();
			b.finalize().unwrap();
			b
		}
		let c1 = finalized_batch()
			.pi_commitment::<SolidityKeccak256>()
			.unwrap();
		let c2 = finalized_batch()
			.pi_commitment::<SolidityKeccak256>()
			.unwrap();
		assert_eq!(c1, c2, "pi_commitment must be deterministic");
	}

	/// `MockTxAggregator::prove` returns `ProveOutcome::Success` with the correct
	/// Poseidon root echoed back.
	#[test]
	#[ignore]
	fn mock_aggregator_returns_success() {
		use crate::{
			prover_service::{Aggregator, MockTxAggregator},
			types::ProveOutcome,
		};

		let mut batch = PrivateTxBatch::new();
		batch
			.add_proof(make_priv_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch.finalize().unwrap();

		let outcome = MockTxAggregator.prove(&batch, 42).unwrap();
		match outcome {
			ProveOutcome::Success {
				batch_id,
				batch_poseidon_root,
				..
			} => {
				assert_eq!(batch_id, 42, "batch_id must be echoed");
				assert_eq!(
					batch_poseidon_root,
					batch.commitments_subtree_root().unwrap(),
					"batch_poseidon_root must match commitments_subtree_root"
				);
			},
			ProveOutcome::Failure {
				error, ..
			} => panic!("expected ProveOutcome::Success, got Failure: {error}"),
		}
	}
}
