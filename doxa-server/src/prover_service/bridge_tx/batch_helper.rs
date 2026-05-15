use plonky2::plonk::proof::ProofWithPublicInputs;
use doxa_client::{
	build_deposit_tx_circuit, build_withdraw_tx_circuit, DepositProof, DepositTxCircuit,
	FakeDepositTxBuilder, FakeWithdrawTxBuilder, PIHelper, WithdrawProof, WithdrawTxCircuit,
	BRIDGE_TX_BATCH_SIZE,
};
use doxa_utils::{hasher::HashOutput, ConfigNative, D, F};

use crate::batch_helper::BatchHelper;

// ---------------------------------------------------------------------------
// BridgeTxProof — unified proof type for bridge transactions
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum BridgeTxProof {
	WithdrawTxProof(WithdrawProof),
	DepositTxProof(DepositProof),
}

impl PIHelper for BridgeTxProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		match self {
			Self::WithdrawTxProof(p) => p.proof(),
			Self::DepositTxProof(p) => p.proof(),
		}
	}

	fn output_commitments(&self) -> Vec<HashOutput> {
		match self {
			Self::WithdrawTxProof(p) => p.output_commitments(),
			Self::DepositTxProof(p) => p.output_commitments(),
		}
	}
}

impl From<WithdrawProof> for BridgeTxProof {
	fn from(p: WithdrawProof) -> Self {
		Self::WithdrawTxProof(p)
	}
}

impl From<DepositProof> for BridgeTxProof {
	fn from(p: DepositProof) -> Self {
		Self::DepositTxProof(p)
	}
}

// ---------------------------------------------------------------------------
// BridgeTxBatch
// ---------------------------------------------------------------------------

pub struct BridgeTxBatch {
	withdraw_half: Vec<BridgeTxProof>,
	deposit_half: Vec<BridgeTxProof>,
	common_act_root: Option<HashOutput>,
	common_main_config_root: Option<HashOutput>,
	batch_poseidon_root: Option<HashOutput>,
	finalized_proofs: Vec<BridgeTxProof>,
	withdraw_circuit: WithdrawTxCircuit,
	deposit_circuit: DepositTxCircuit,
}

impl BridgeTxBatch {
	pub fn new() -> Self {
		Self {
			withdraw_half: Vec::new(),
			deposit_half: Vec::new(),
			common_act_root: None,
			common_main_config_root: None,
			batch_poseidon_root: None,
			finalized_proofs: Vec::new(),
			withdraw_circuit: build_withdraw_tx_circuit(),
			deposit_circuit: build_deposit_tx_circuit(),
		}
	}

	pub fn is_withdraw_full(&self) -> bool {
		self.withdraw_half.len() == Self::PROOF_BATCH_SIZE >> 1
	}

	pub fn is_deposit_full(&self) -> bool {
		self.deposit_half.len() == Self::PROOF_BATCH_SIZE >> 1
	}
}

impl Default for BridgeTxBatch {
	fn default() -> Self {
		Self::new()
	}
}

impl BatchHelper for BridgeTxBatch {
	type Proof = BridgeTxProof;

	const PROOF_BATCH_SIZE: usize = BRIDGE_TX_BATCH_SIZE;

	fn add_proof(&mut self, proof: BridgeTxProof) -> anyhow::Result<bool> {
		anyhow::ensure!(!self.is_full(), "batch is full");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");

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

		match proof {
			BridgeTxProof::WithdrawTxProof(_) => {
				anyhow::ensure!(!self.is_withdraw_full(), "withdraw half is full");
				self.withdraw_half.push(proof);
			},
			BridgeTxProof::DepositTxProof(_) => {
				anyhow::ensure!(!self.is_deposit_full(), "deposit half is full");
				self.deposit_half.push(proof);
			},
		}

		Ok(self.is_full())
	}

	fn is_full(&self) -> bool {
		self.is_withdraw_full() && self.is_deposit_full()
	}

	fn is_empty(&self) -> bool {
		self.withdraw_half.is_empty() && self.deposit_half.is_empty()
	}

	fn common_act_root(&self) -> anyhow::Result<HashOutput> {
		self.common_act_root
			.ok_or_else(|| anyhow::anyhow!("no proofs added yet"))
	}

	fn common_main_config_root(&self) -> anyhow::Result<HashOutput> {
		self.common_main_config_root
			.ok_or_else(|| anyhow::anyhow!("no proofs added yet"))
	}

	fn is_finalized(&self) -> bool {
		self.batch_poseidon_root.is_some()
	}

	fn commitments_subtree_root(&self) -> anyhow::Result<HashOutput> {
		self.batch_poseidon_root
			.ok_or_else(|| anyhow::anyhow!("batch is not finalized"))
	}

	fn proofs(&self) -> &[BridgeTxProof] {
		&self.finalized_proofs
	}

	/// Pad each half with fake proofs sharing the same common PIs, merge halves,
	/// then compute the Poseidon subtree root over all `output_commitments()`.
	///
	/// Withdrawal half `[0..HALF)` is padded with fake withdraw proofs;
	/// deposit half `[HALF..BATCH_SIZE)` is padded with fake deposit proofs.
	fn finalize(&mut self) -> anyhow::Result<()> {
		anyhow::ensure!(!self.is_empty(), "batch is empty");
		anyhow::ensure!(!self.is_finalized(), "batch is already finalized");

		let act_root = self.common_act_root()?;
		let mainpool_config_root = self.common_main_config_root()?;
		let half = Self::PROOF_BATCH_SIZE >> 1;

		// Pad the withdrawal half.
		let n_withdraw_padding = half - self.withdraw_half.len();
		if n_withdraw_padding > 0 {
			let padding = FakeWithdrawTxBuilder::new(act_root, mainpool_config_root)
				.build()
				.into_withdraw_tx()
				.prove(&self.withdraw_circuit)?;
			for _ in 0..n_withdraw_padding {
				self.withdraw_half
					.push(BridgeTxProof::from(padding.clone()));
			}
		}

		// Pad the deposit half.
		let n_deposit_padding = half - self.deposit_half.len();
		if n_deposit_padding > 0 {
			let padding = FakeDepositTxBuilder::new(act_root, mainpool_config_root)
				.build()
				.into_deposit_tx()
				.prove(&self.deposit_circuit)?;
			for _ in 0..n_deposit_padding {
				self.deposit_half.push(BridgeTxProof::from(padding.clone()));
			}
		}

		// Merge halves in slot order: withdrawals first, deposits second.
		self.finalized_proofs = self
			.withdraw_half
			.iter()
			.cloned()
			.chain(self.deposit_half.iter().cloned())
			.collect();

		self.batch_poseidon_root = Some(self.batch_poseidon_root()?);
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use plonky2::field::types::Field;
	use doxa_client::{
		build_deposit_tx_circuit, build_withdraw_tx_circuit, FakeDepositTxBuilder,
		FakeWithdrawTxBuilder, BRIDGE_TX_BATCH_SIZE,
	};
	use doxa_utils::{hasher::HashOutput, F};

	use super::*;
	use crate::batch_helper::{BatchHelper, SolidityKeccak256};

	const HALF: usize = BRIDGE_TX_BATCH_SIZE >> 1;

	// ── Helpers ──────────────────────────────────────────────────────────────

	fn zero_hash() -> HashOutput {
		HashOutput([F::ZERO; 4])
	}

	fn alt_hash() -> HashOutput {
		HashOutput([F::ONE, F::ZERO, F::ZERO, F::ZERO])
	}

	fn make_withdraw_proof(act_root: HashOutput, config_root: HashOutput) -> BridgeTxProof {
		let circuit = build_withdraw_tx_circuit();
		BridgeTxProof::from(
			FakeWithdrawTxBuilder::new(act_root, config_root)
				.build()
				.into_withdraw_tx()
				.prove(&circuit)
				.expect("withdraw prove failed"),
		)
	}

	fn make_deposit_proof(st_root: HashOutput, config_root: HashOutput) -> BridgeTxProof {
		let circuit = build_deposit_tx_circuit();
		BridgeTxProof::from(
			FakeDepositTxBuilder::new(st_root, config_root)
				.build()
				.into_deposit_tx()
				.prove(&circuit)
				.expect("deposit prove failed"),
		)
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
	fn add_mismatched_st_root_fails() {
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

	/// Filling the withdraw half alone triggers `is_withdraw_full()` but not `is_full()`.
	#[test]
	#[ignore]
	fn withdraw_half_full_triggers_is_withdraw_full() {
		let mut batch = BridgeTxBatch::new();
		let proof = make_withdraw_proof(zero_hash(), zero_hash());
		for _ in 0..HALF {
			batch.add_proof(proof.clone()).unwrap();
		}
		assert!(
			batch.is_withdraw_full(),
			"batch must be withdraw-full after HALF withdraw proofs"
		);
		assert!(
			!batch.is_full(),
			"is_full must be false when only withdraw half is full"
		);
	}

	/// Filling the deposit half alone triggers `is_deposit_full()` but not `is_full()`.
	#[test]
	#[ignore]
	fn deposit_half_full_triggers_is_deposit_full() {
		let mut batch = BridgeTxBatch::new();
		let proof = make_deposit_proof(zero_hash(), zero_hash());
		for _ in 0..HALF {
			batch.add_proof(proof.clone()).unwrap();
		}
		assert!(
			batch.is_deposit_full(),
			"batch must be deposit-full after HALF deposit proofs"
		);
		assert!(
			!batch.is_full(),
			"is_full must be false when only deposit half is full"
		);
	}

	/// Filling both halves triggers `is_full()`.
	#[test]
	#[ignore]
	fn both_halves_full_triggers_is_full() {
		let mut batch = BridgeTxBatch::new();
		let proof = make_withdraw_proof(zero_hash(), zero_hash());
		for _ in 0..HALF {
			batch.add_proof(proof.clone()).unwrap();
		}
		let proof = make_deposit_proof(zero_hash(), zero_hash());
		for _ in 0..HALF {
			batch.add_proof(proof.clone()).unwrap();
		}
		assert!(
			batch.is_full(),
			"batch must be full when both halves are full"
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
				matches!(batch.proofs()[i], BridgeTxProof::WithdrawTxProof(_)),
				"slot {i} in lower half must be WithdrawTxProof after finalize"
			);
		}
		for i in HALF..BRIDGE_TX_BATCH_SIZE {
			assert!(
				matches!(batch.proofs()[i], BridgeTxProof::DepositTxProof(_)),
				"slot {i} in upper half must be DepositTxProof after finalize"
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

	/// `MockBridgeTxAggregator::prove` returns `ProveOutcome::Success` with the
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
