use std::path::Path;

use anyhow::{anyhow, Result};
use plonky2::{
	plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
	util::serialization::GateSerializer,
};
use tessera_client::{PIHelper, SUBTREE_BATCHSIZE};
use tessera_utils::{hasher::HashOutput, CircuitDataNative, ConfigNative, ProofNative, D, F};

use super::{circuit::PrivTxSuperCircuit, targets::PrivTxSuperCircuitData};
use crate::{
	aggregator_service::generic_aggregator::{GenericAggregator, GenericAggregatorConfig},
	batch_helper::BatchHelper,
	prover_service::SubtreeRootCircuit,
};

const GENERIC_AGG_DIR: &str = "generic-agg";
const SUBTREE_ROOT_DIR: &str = "subtree-root";
const SUPER_CIRCUIT_DIR: &str = "super-circuit";

/// Aggregates a finalized [`PrivateTxBatch`] (64 proofs) into a single Plonky2
/// proof carrying `super_pi_commitment` as its only public output.
///
/// # Artifact lifecycle
///
/// ```text
/// let agg = PrivTxAggregator::build(leaf_common, leaf_verifier)?;
/// agg.store_artifacts(Path::new("artifacts/priv-tx-agg"), &TesseraGateSerializer)?;
///
/// let agg = PrivTxAggregator::from_artifacts(
///     Path::new("artifacts/priv-tx-agg"), &TesseraGateSerializer,
/// )?;
/// let proof = agg.prove(&finalized_batch)?;
/// ```
pub struct PrivTxAggregator {
	tx_aggregator: GenericAggregator<F, ConfigNative, D>,
	subtree_root: SubtreeRootCircuit,
	super_circuit: PrivTxSuperCircuit,
}

impl PrivTxAggregator {
	/// Build all circuits from scratch.
	///
	/// `priv_tx_leaf_common` / `priv_tx_leaf_verifier` describe the per-slot
	/// PrivTx circuit (obtained from `build_priv_tx_circuit()`).
	pub fn build(
		priv_tx_leaf_common: CommonCircuitData<F, D>,
		priv_tx_leaf_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	) -> Result<Self> {
		let tx_aggregator = GenericAggregator::new(
			GenericAggregatorConfig {
				arity: 8,
				depth: 2,
			},
			priv_tx_leaf_common,
			priv_tx_leaf_verifier,
		)?;

		let subtree_root = SubtreeRootCircuit::build(SUBTREE_BATCHSIZE)?;

		let root_level = tx_aggregator
			.levels
			.last()
			.ok_or_else(|| anyhow!("GenericAggregator has no levels"))?;

		let inner = PrivTxSuperCircuitData {
			tx_common: root_level.circuit_data.common.clone(),
			tx_verifier: root_level.circuit_data.verifier_only.clone(),
			sr_common: subtree_root.circuit_data.common.clone(),
			sr_verifier: subtree_root.circuit_data.verifier_only.clone(),
		};

		let super_circuit = PrivTxSuperCircuit::build(inner)?;

		Ok(Self {
			tx_aggregator,
			subtree_root,
			super_circuit,
		})
	}

	/// Prove a finalized batch, returning the super-aggregated proof.
	///
	/// The batch must be finalized (`batch.is_finalized() == true`).
	/// Each of the 64 slots must be a `TxProof::Private` variant.
	pub fn prove<B: BatchHelper>(&self, batch: &B) -> Result<ProofNative> {
		let leaf_proofs: Vec<ProofNative> =
			batch.proofs().iter().map(|p| p.proof().clone()).collect();

		let tx_agg = self.tx_aggregator.aggregate(leaf_proofs)?;

		let leaves: Vec<HashOutput> = batch
			.proofs()
			.iter()
			.flat_map(|p| p.output_commitments())
			.collect();
		assert_eq!(
			leaves.len(),
			SUBTREE_BATCHSIZE,
			"leaf count mismatch: got {}, expected {}",
			leaves.len(),
			SUBTREE_BATCHSIZE
		);

		let sr_proof = self.subtree_root.prove(&leaves)?;

		self.super_circuit.prove(tx_agg.proof, sr_proof)
	}

	/// Persist all artifacts to `path/`.
	///
	/// Directory layout:
	/// ```text
	/// path/
	/// ├── generic-agg/        ← GenericAggregator (arity=8, depth=2)
	/// ├── subtree-root/       ← SubtreeRootCircuit
	/// └── super-circuit/      ← PrivTxSuperCircuit
	/// ```
	pub fn store_artifacts(
		&self,
		path: &Path,
		leaf_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<()> {
		self.tx_aggregator
			.store_artifacts(&path.join(GENERIC_AGG_DIR), leaf_gate_ser)?;
		self.subtree_root
			.store_artifacts(&path.join(SUBTREE_ROOT_DIR))?;
		self.super_circuit
			.store_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling any circuit.
	pub fn from_artifacts(path: &Path, leaf_gate_ser: &dyn GateSerializer<F, D>) -> Result<Self> {
		let tx_aggregator =
			GenericAggregator::from_artifacts(&path.join(GENERIC_AGG_DIR), leaf_gate_ser)?;
		let subtree_root =
			SubtreeRootCircuit::from_artifacts(&path.join(SUBTREE_ROOT_DIR), SUBTREE_BATCHSIZE)?;
		let super_circuit = PrivTxSuperCircuit::from_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(Self {
			tx_aggregator,
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
	/// Generates a single priv_tx leaf proof, aggregates it by cloning at each
	/// level (`depth` proves instead of `arity^depth`), then proves the
	/// super-circuit with SR leaves derived from that single leaf's
	/// `output_commitments` repeated across all slots.
	pub fn prove_dummy(&self) -> Result<ProofNative> {
		use plonky2::field::types::Field;
		use tessera_client::{
			build_priv_tx_circuit, prove_priv_tx, FakeTxInputs, PIHelper, PrivTxInputs,
			PrivateTransactionProof, NOTE_BATCH,
		};
		use tessera_utils::hasher::HashOutput;

		let zero = HashOutput([F::ZERO; 4]);
		let zero4 = [F::ZERO; 4];
		let (cd, tgts) = build_priv_tx_circuit();
		let leaf = prove_priv_tx(
			&cd,
			&tgts,
			PrivTxInputs::Fake(FakeTxInputs {
				state_root: zero,
				mainpool_config_root: zero,
				override_an: zero4,
				override_ac: zero4,
				override_nn: [zero4; NOTE_BATCH],
				override_nc: [zero4; NOTE_BATCH],
			}),
		);

		// Derive SR leaves from the single leaf before moving it.
		let single_leaves = PrivateTransactionProof(leaf.clone()).output_commitments();
		let sr_leaves: Vec<HashOutput> = single_leaves
			.iter()
			.cloned()
			.cycle()
			.take(SUBTREE_BATCHSIZE)
			.collect();

		let tx_agg = self.tx_aggregator.aggregate_dummy(leaf)?;
		let sr_proof = self.subtree_root.prove(&sr_leaves)?;
		self.super_circuit.prove(tx_agg.proof, sr_proof)
	}

	/// Returns `Ok(true)` if the full artifact set is present under `path`.
	pub fn has_full_artifacts(path: &Path) -> Result<bool> {
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(
			&path.join(GENERIC_AGG_DIR),
		)? {
			return Ok(false);
		}
		if !SubtreeRootCircuit::has_artifacts(&path.join(SUBTREE_ROOT_DIR)) {
			return Ok(false);
		}
		if !PrivTxSuperCircuit::has_artifacts(&path.join(SUPER_CIRCUIT_DIR)) {
			return Ok(false);
		}
		Ok(true)
	}
}
