use std::path::Path;

use anyhow::{anyhow, Result};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::util::serialization::GateSerializer;
use tessera_client::{PIHelper, BRIDGE_TX_BATCH_SIZE, SUBTREE_BATCHSIZE};
use tessera_utils::{hasher::HashOutput, CircuitDataNative, ConfigNative, ProofNative, D, F};

use super::{
	circuit::BridgeTxSuperCircuit,
	targets::BridgeTxSuperCircuitData,
};
use crate::{
	aggregator_service::generic_aggregator::{GenericAggregator, GenericAggregatorConfig},
	batch_helper::BatchHelper,
	prover_service::SubtreeRootCircuit,
};

const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

const W_AGG_DIR: &str = "withdraw-agg";
const D_AGG_DIR: &str = "deposit-agg";
const SUBTREE_ROOT_DIR: &str = "subtree-root";
const SUPER_CIRCUIT_DIR: &str = "super-circuit";

/// Aggregates a finalized [`BridgeTxBatch`] (256 Withdraw + 256 Deposit proofs)
/// into a single Plonky2 proof carrying `super_pi_commitment` as its only
/// public output.
///
/// # Artifact lifecycle
///
/// ```text
/// let agg = BridgeTxAggregator::build(
///     w_leaf_common, w_leaf_verifier,
///     d_leaf_common, d_leaf_verifier,
/// )?;
/// agg.store_artifacts(
///     Path::new("artifacts/bridge-tx-agg"),
///     &w_gate_ser, &d_gate_ser,
/// )?;
///
/// let agg = BridgeTxAggregator::from_artifacts(
///     Path::new("artifacts/bridge-tx-agg"),
///     &w_gate_ser, &d_gate_ser,
/// )?;
/// let proof = agg.prove(&finalized_batch)?;
/// ```
pub struct BridgeTxAggregator {
	w_aggregator: GenericAggregator<F, ConfigNative, D>,
	d_aggregator: GenericAggregator<F, ConfigNative, D>,
	subtree_root: SubtreeRootCircuit,
	super_circuit: BridgeTxSuperCircuit,
}

impl BridgeTxAggregator {
	/// Build all circuits from scratch.
	///
	/// `withdraw_leaf_*` / `deposit_leaf_*` describe the per-slot circuits
	/// (obtained from `build_withdraw_tx_circuit()` / `build_deposit_tx_circuit()`).
	pub fn build(
		withdraw_leaf_common: CommonCircuitData<F, D>,
		withdraw_leaf_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
		deposit_leaf_common: CommonCircuitData<F, D>,
		deposit_leaf_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	) -> Result<Self> {
		// arity=4, depth=4 → 4^4 = 256 slots each.
		let w_aggregator = GenericAggregator::new(
			GenericAggregatorConfig {
				arity: 4,
				depth: 4,
			},
			withdraw_leaf_common,
			withdraw_leaf_verifier,
		)?;
		let d_aggregator = GenericAggregator::new(
			GenericAggregatorConfig {
				arity: 4,
				depth: 4,
			},
			deposit_leaf_common,
			deposit_leaf_verifier,
		)?;

		let subtree_root = SubtreeRootCircuit::build(SUBTREE_BATCHSIZE)?;

		let w_root = w_aggregator
			.levels
			.last()
			.ok_or_else(|| anyhow!("w_aggregator has no levels"))?;
		let d_root = d_aggregator
			.levels
			.last()
			.ok_or_else(|| anyhow!("d_aggregator has no levels"))?;

		let inner = BridgeTxSuperCircuitData {
			withdraw_common: w_root.circuit_data.common.clone(),
			withdraw_verifier: w_root.circuit_data.verifier_only.clone(),
			deposit_common: d_root.circuit_data.common.clone(),
			deposit_verifier: d_root.circuit_data.verifier_only.clone(),
			poseidon_root_common: subtree_root.circuit_data.common.clone(),
			poseidon_root_verifier: subtree_root.circuit_data.verifier_only.clone(),
		};

		let super_circuit = BridgeTxSuperCircuit::build(inner)?;

		Ok(Self {
			w_aggregator,
			d_aggregator,
			subtree_root,
			super_circuit,
		})
	}

	/// Prove a finalized batch, returning the super-aggregated proof.
	///
	/// Batch layout (set by [`BridgeTxBatch`]):
	/// - `batch.proofs()[0..HALF)` → Withdraw proofs
	/// - `batch.proofs()[HALF..2*HALF)` → Deposit proofs
	pub fn prove<B: BatchHelper>(&self, batch: &B) -> Result<ProofNative> {
		let proofs = batch.proofs();
		let w_proofs: Vec<ProofNative> =
			proofs[..HALF].iter().map(|p| p.proof().clone()).collect();
		let d_proofs: Vec<ProofNative> =
			proofs[HALF..].iter().map(|p| p.proof().clone()).collect();

		let w_agg = self.w_aggregator.aggregate(w_proofs)?;
		let d_agg = self.d_aggregator.aggregate(d_proofs)?;

		// SR leaves: all output_commitments in slot order (withdraw first, then deposit).
		let leaves: Vec<HashOutput> =
			proofs.iter().flat_map(|p| p.output_commitments()).collect();
		assert_eq!(
			leaves.len(),
			SUBTREE_BATCHSIZE,
			"leaf count mismatch: got {}, expected {}",
			leaves.len(),
			SUBTREE_BATCHSIZE
		);

		let sr_proof = self.subtree_root.prove(&leaves)?;

		self.super_circuit.prove(w_agg.proof, d_agg.proof, sr_proof)
	}

	/// Persist all artifacts to `path/`.
	///
	/// Directory layout:
	/// ```text
	/// path/
	/// ├── withdraw-agg/       ← GenericAggregator (arity=4, depth=4)
	/// ├── deposit-agg/        ← GenericAggregator (arity=4, depth=4)
	/// ├── subtree-root/       ← SubtreeRootCircuit
	/// └── super-circuit/      ← BridgeTxSuperCircuit
	/// ```
	pub fn store_artifacts(
		&self,
		path: &Path,
		w_gate_ser: &dyn GateSerializer<F, D>,
		d_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<()> {
		self.w_aggregator
			.store_artifacts(&path.join(W_AGG_DIR), w_gate_ser)?;
		self.d_aggregator
			.store_artifacts(&path.join(D_AGG_DIR), d_gate_ser)?;
		self.subtree_root
			.store_artifacts(&path.join(SUBTREE_ROOT_DIR))?;
		self.super_circuit
			.store_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling any circuit.
	pub fn from_artifacts(
		path: &Path,
		w_gate_ser: &dyn GateSerializer<F, D>,
		d_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<Self> {
		let w_aggregator =
			GenericAggregator::from_artifacts(&path.join(W_AGG_DIR), w_gate_ser)?;
		let d_aggregator =
			GenericAggregator::from_artifacts(&path.join(D_AGG_DIR), d_gate_ser)?;
		let subtree_root =
			SubtreeRootCircuit::from_artifacts(&path.join(SUBTREE_ROOT_DIR), SUBTREE_BATCHSIZE)?;
		let super_circuit = BridgeTxSuperCircuit::from_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(Self {
			w_aggregator,
			d_aggregator,
			subtree_root,
			super_circuit,
		})
	}

	/// Returns the super circuit's compiled [`CircuitDataNative`], needed by
	/// [`tessera_utils::groth::BN128Wrapper::new`].
	pub fn super_circuit_data(&self) -> &CircuitDataNative {
		&self.super_circuit.circuit_data
	}

	/// Generate a dummy super proof (zero witness) to seed
	/// [`tessera_utils::groth::BN128Wrapper::new`].
	///
	/// Generates one withdraw leaf and one deposit leaf proof, aggregates each
	/// by cloning at every level (`depth` proves instead of `arity^depth`),
	/// then proves the super-circuit with SR leaves derived from those two
	/// leaves' `output_commitments` repeated across all slots.
	pub fn prove_dummy(&self) -> Result<ProofNative> {
		use plonky2::field::types::Field;
		use tessera_client::{DepositProof, PIHelper, WithdrawProof, build_deposit_tx_circuit, build_withdraw_tx_circuit};

		let zero = HashOutput([F::ZERO; 4]);
		let w_circuit = build_withdraw_tx_circuit();
		let d_circuit = build_deposit_tx_circuit();
		let w_leaf = w_circuit.prove_padding(zero, zero);
		let d_leaf = d_circuit.prove_padding(zero, zero);

		// Derive SR leaves from each single leaf before moving them.
		let w_single = WithdrawProof { proof: w_leaf.clone() }.output_commitments();
		let d_single = DepositProof { proof: d_leaf.clone() }.output_commitments();
		let sr_leaves: Vec<HashOutput> = w_single
			.iter()
			.cloned()
			.cycle()
			.take(HALF)
			.chain(d_single.iter().cloned().cycle().take(HALF))
			.collect();

		let w_agg = self.w_aggregator.aggregate_dummy(w_leaf)?;
		let d_agg = self.d_aggregator.aggregate_dummy(d_leaf)?;
		let sr_proof = self.subtree_root.prove(&sr_leaves)?;

		self.super_circuit.prove(w_agg.proof, d_agg.proof, sr_proof)
	}

	/// Returns `Ok(true)` if the full artifact set is present under `path`.
	pub fn has_full_artifacts(path: &Path) -> Result<bool> {
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(&path.join(W_AGG_DIR))? {
			return Ok(false);
		}
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(&path.join(D_AGG_DIR))? {
			return Ok(false);
		}
		if !SubtreeRootCircuit::has_artifacts(&path.join(SUBTREE_ROOT_DIR)) {
			return Ok(false);
		}
		if !BridgeTxSuperCircuit::has_artifacts(&path.join(SUPER_CIRCUIT_DIR)) {
			return Ok(false);
		}
		Ok(true)
	}
}
