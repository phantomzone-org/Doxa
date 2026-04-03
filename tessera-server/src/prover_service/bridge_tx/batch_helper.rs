use tessera_client::{
	build_deposit_tx_circuit, build_withdraw_tx_circuit, DepositProof, DepositTxCircuit, PIHelper,
	WithdrawProof, WithdrawTxCircuit, BRIDGE_TX_BATCH_SIZE,
};
use tessera_utils::hasher::HashOutput;

use crate::batch_helper::{BatchHelper, TxProof};

pub struct BridgeTxBatch {
	proofs: Vec<TxProof>,
	withdraw_proofs: usize,
	deposit_proofs: usize,
	common_act_root: Option<HashOutput>,
	common_main_config_root: Option<HashOutput>,
	batch_poseidon_root: Option<HashOutput>,
	withdraw_circuit: WithdrawTxCircuit,
	deposit_circuit: DepositTxCircuit,
}

impl BridgeTxBatch {
	pub fn new() -> Self {
		Self {
			proofs: vec![TxProof::None(); BRIDGE_TX_BATCH_SIZE],
			withdraw_proofs: 0,
			deposit_proofs: 0,
			common_act_root: None,
			common_main_config_root: None,
			batch_poseidon_root: None,
			withdraw_circuit: build_withdraw_tx_circuit(),
			deposit_circuit: build_deposit_tx_circuit(),
		}
	}
}

impl Default for BridgeTxBatch {
	fn default() -> Self {
		Self::new()
	}
}

impl BatchHelper for BridgeTxBatch {
	const PROOF_BATCH_SIZE: usize = BRIDGE_TX_BATCH_SIZE;

	fn add_proof(&mut self, proof: TxProof) -> anyhow::Result<bool> {
		anyhow::ensure!(!self.is_full(), "batch is full");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");
		match proof {
			TxProof::Withdraw(_) => {
				if self.common_act_root.is_some() {
					anyhow::ensure!(
						proof.act_root() == self.common_act_root()?,
						"act_root mismatch"
					);
					anyhow::ensure!(
						proof.mainpool_config_root() == self.common_main_config_root()?,
						"mainpool_config_root mismatch"
					);
				} else {
					self.common_act_root = Some(proof.act_root());
					self.common_main_config_root = Some(proof.mainpool_config_root());
				}
				self.proofs[self.withdraw_proofs] = proof;
				self.withdraw_proofs += 1;
			},

			TxProof::Deposit(_) => {
				if self.common_act_root.is_some() {
					anyhow::ensure!(
						proof.act_root() == self.common_act_root()?,
						"act_root mismatch"
					);
					anyhow::ensure!(
						proof.mainpool_config_root() == self.common_main_config_root()?,
						"mainpool_config_root mismatch"
					);
				} else {
					self.common_act_root = Some(proof.act_root());
					self.common_main_config_root = Some(proof.mainpool_config_root());
				}
				self.proofs[(Self::PROOF_BATCH_SIZE >> 1) + self.deposit_proofs] = proof;
				self.deposit_proofs += 1;
			},
			other => anyhow::bail!(
				"expected TxProof::Withdraw or TxProof::Deposit, got {}",
				other.kind()
			),
		};

		Ok(self.is_full())
	}

	fn is_full(&self) -> bool {
		(self.withdraw_proofs == Self::PROOF_BATCH_SIZE >> 1)
			| (self.deposit_proofs == Self::PROOF_BATCH_SIZE >> 1)
	}

	fn is_empty(&self) -> bool {
		self.withdraw_proofs == 0 && self.deposit_proofs == 0
	}

	fn common_act_root(&self) -> anyhow::Result<HashOutput> {
		self.common_act_root
			.ok_or_else(|| anyhow::anyhow!("batch is not finalized"))
	}

	fn common_main_config_root(&self) -> anyhow::Result<HashOutput> {
		self.common_main_config_root
			.ok_or_else(|| anyhow::anyhow!("batch is not finalized"))
	}

	fn is_finalized(&self) -> bool {
		self.batch_poseidon_root.is_some()
	}

	fn commitments_subtree_root(&self) -> anyhow::Result<HashOutput> {
		self.batch_poseidon_root
			.ok_or_else(|| anyhow::anyhow!("batch is not finalized"))
	}

	fn proofs(&self) -> &[TxProof] {
		&self.proofs
	}

	/// Pad each half with dummy proofs sharing the same common PIs, then
	/// compute the Poseidon subtree root over all `output_commitments()` in slot order.
	///
	/// Withdrawal half `[0..HALF)` is padded with dummy withdraw proofs;
	/// deposit half `[HALF..BATCH_SIZE)` is padded with dummy deposit proofs.
	fn finalize(&mut self) -> anyhow::Result<()> {
		anyhow::ensure!(!self.is_empty(), "batch is empty");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");

		let act_root = self.common_act_root()?;
		let mainpool_config_root = self.common_main_config_root()?;
		let half = Self::PROOF_BATCH_SIZE >> 1;

		// Pad the withdrawal half [0..HALF).
		let n_withdraw_padding = half - self.withdraw_proofs;
		if n_withdraw_padding > 0 {
			let padding = self
				.withdraw_circuit
				.prove_padding(act_root, mainpool_config_root);
			for i in self.withdraw_proofs..half {
				self.proofs[i] = TxProof::Withdraw(WithdrawProof {
					proof: padding.clone(),
				});
			}
		}

		// Pad the deposit half [HALF..BATCH_SIZE).
		let n_deposit_padding = half - self.deposit_proofs;
		if n_deposit_padding > 0 {
			let padding = self
				.deposit_circuit
				.prove_padding(act_root, mainpool_config_root);
			for i in self.deposit_proofs..half {
				self.proofs[half + i] = TxProof::Deposit(DepositProof {
					proof: padding.clone(),
				});
			}
		}

		// Update counters so that is_full() returns true and batch_poseidon_root() can run.
		self.withdraw_proofs = half;
		self.deposit_proofs = half;

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
	use tessera_client::{
		build_deposit_tx_circuit, build_withdraw_tx_circuit, DepositProof, PIHelper as _,
		WithdrawProof, BRIDGE_TX_BATCH_SIZE,
	};
	use tessera_utils::{hasher::HashOutput, F};

	use super::*;
	use crate::batch_helper::{BatchHelper, SolidityKeccak256, TxProof};

	const HALF: usize = BRIDGE_TX_BATCH_SIZE >> 1;

	// ── Helpers ──────────────────────────────────────────────────────────────

	fn zero_hash() -> HashOutput {
		HashOutput([F::ZERO; 4])
	}

	fn alt_hash() -> HashOutput {
		HashOutput([F::ONE, F::ZERO, F::ZERO, F::ZERO])
	}

	fn make_withdraw_proof(act_root: HashOutput, config_root: HashOutput) -> TxProof {
		let circuit = build_withdraw_tx_circuit();
		TxProof::Withdraw(WithdrawProof {
			proof: circuit.prove_padding(act_root, config_root),
		})
	}

	fn make_deposit_proof(act_root: HashOutput, config_root: HashOutput) -> TxProof {
		let circuit = build_deposit_tx_circuit();
		TxProof::Deposit(DepositProof {
			proof: circuit.prove_padding(act_root, config_root),
		})
	}

	// ── Cheap tests (no ZK proving) ──────────────────────────────────────────

	/// `finalize` on a freshly-created empty batch must return an error.
	#[test]
	fn finalize_empty_fails() {
		let mut batch = BridgeTxBatch::new();
		assert!(
			batch.finalize().is_err(),
			"finalize on empty batch must fail"
		);
	}

	/// Adding a `TxProof::None` (wrong type) must return an error immediately.
	#[test]
	fn add_wrong_type_fails() {
		let mut batch = BridgeTxBatch::new();
		assert!(
			batch.add_proof(TxProof::None()).is_err(),
			"TxProof::None must be rejected by BridgeTxBatch"
		);
	}

	// ── Slow tests (ZK proving required — run with: cargo test -- --include-ignored) ─

	/// A second `finalize` call on an already-finalized batch must fail.
	#[test]
	#[ignore]
	fn double_finalize_fails() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch.finalize().unwrap();
		assert!(
			batch.finalize().is_err(),
			"second finalize must be rejected"
		);
	}

	/// A deposit after a withdraw with a different `act_root` must be rejected.
	#[test]
	#[ignore]
	fn add_mismatched_act_root_fails() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			batch
				.add_proof(make_deposit_proof(alt_hash(), zero_hash()))
				.is_err(),
			"deposit with mismatched act_root must be rejected"
		);
	}

	/// A deposit after a withdraw with a different `mainpool_config_root` must be rejected.
	#[test]
	#[ignore]
	fn add_mismatched_config_root_fails() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			batch
				.add_proof(make_deposit_proof(zero_hash(), alt_hash()))
				.is_err(),
			"deposit with mismatched config_root must be rejected"
		);
	}

	/// Withdraw proofs land in slots `[0..HALF)`, not in the deposit half.
	#[test]
	#[ignore]
	fn withdraw_proof_lands_in_lower_half() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			matches!(batch.proofs()[0], TxProof::Withdraw(_)),
			"slot 0 must be Withdraw"
		);
		assert!(
			matches!(batch.proofs()[HALF], TxProof::None()),
			"first deposit slot must still be None"
		);
	}

	/// Deposit proofs land in slots `[HALF..BATCH_SIZE)`, not in the withdraw half.
	#[test]
	#[ignore]
	fn deposit_proof_lands_in_upper_half() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_deposit_proof(zero_hash(), zero_hash()))
			.unwrap();
		assert!(
			matches!(batch.proofs()[HALF], TxProof::Deposit(_)),
			"slot HALF must be Deposit"
		);
		assert!(
			matches!(batch.proofs()[0], TxProof::None()),
			"first withdraw slot must still be None"
		);
	}

	/// Filling the withdraw half alone is enough to trigger `is_full()`.
	#[test]
	#[ignore]
	fn withdraw_half_full_triggers_is_full() {
		let mut batch = BridgeTxBatch::new();
		for _ in 0..HALF {
			let p = make_withdraw_proof(zero_hash(), zero_hash());
			if batch.add_proof(p).unwrap() {
				break;
			}
		}
		assert!(
			batch.is_full(),
			"batch must be full after HALF withdraw proofs"
		);
	}

	/// Filling the deposit half alone is enough to trigger `is_full()`.
	#[test]
	#[ignore]
	fn deposit_half_full_triggers_is_full() {
		let mut batch = BridgeTxBatch::new();
		for _ in 0..HALF {
			let p = make_deposit_proof(zero_hash(), zero_hash());
			if batch.add_proof(p).unwrap() {
				break;
			}
		}
		assert!(
			batch.is_full(),
			"batch must be full after HALF deposit proofs"
		);
	}

	/// After `finalize`, every slot in `[0..HALF)` is a Withdraw proof and every
	/// slot in `[HALF..BATCH_SIZE)` is a Deposit proof.
	#[test]
	#[ignore]
	fn finalize_pads_both_halves() {
		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch
			.add_proof(make_deposit_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch.finalize().unwrap();

		for i in 0..HALF {
			assert!(
				matches!(batch.proofs()[i], TxProof::Withdraw(_)),
				"slot {i} in lower half must be Withdraw after finalize"
			);
		}
		for i in HALF..BRIDGE_TX_BATCH_SIZE {
			assert!(
				matches!(batch.proofs()[i], TxProof::Deposit(_)),
				"slot {i} in upper half must be Deposit after finalize"
			);
		}
	}

	/// All proofs in a finalized batch share the same `act_root` and
	/// `mainpool_config_root` as the real proof.
	#[test]
	#[ignore]
	fn finalize_padding_shares_common_roots() {
		let act_root = alt_hash();
		let config_root = HashOutput([F::from_canonical_u64(77), F::ZERO, F::ZERO, F::ZERO]);

		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(act_root, config_root))
			.unwrap();
		batch
			.add_proof(make_deposit_proof(act_root, config_root))
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

	/// `pi_commitment` is deterministic: same inputs → same 32-byte commitment.
	#[test]
	#[ignore]
	fn pi_commitment_is_deterministic() {
		fn finalized_batch() -> BridgeTxBatch {
			let mut b = BridgeTxBatch::new();
			b.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
				.unwrap();
			b.add_proof(make_deposit_proof(zero_hash(), zero_hash()))
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

	/// `MockDepositAggregator::prove` returns `ProveOutcome::Success` with the
	/// correct Poseidon root.
	#[test]
	#[ignore]
	fn mock_aggregator_returns_success() {
		use crate::{
			prover_service::{Aggregator, MockBridgeTxAggregator},
			types::ProveOutcome,
		};

		let mut batch = BridgeTxBatch::new();
		batch
			.add_proof(make_withdraw_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch
			.add_proof(make_deposit_proof(zero_hash(), zero_hash()))
			.unwrap();
		batch.finalize().unwrap();

		let outcome = MockBridgeTxAggregator.prove(&batch, 7).unwrap();
		match outcome {
			ProveOutcome::Success {
				batch_id,
				batch_poseidon_root,
				..
			} => {
				assert_eq!(batch_id, 7, "batch_id must be echoed");
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
