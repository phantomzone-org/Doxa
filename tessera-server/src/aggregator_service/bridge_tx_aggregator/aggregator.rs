use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
		proof::ProofWithPublicInputsTarget,
	},
	util::serialization::{DefaultGateSerializer, GateSerializer},
};
use tessera_client::{PIHelper, BRIDGE_TX_BATCH_SIZE, SUBTREE_BATCHSIZE};
use tessera_utils::{
	groth::TesseraGeneratorSerializer, hasher::HashOutput, CircuitDataNative, ConfigNative,
	ProofNative, D, F,
};

use super::{
	circuit::BridgeTxSuperCircuit,
	circuit_builder::build_pair_leaf,
	targets::{BridgeTxPairLeafData, BridgeTxSuperCircuitData},
};
use crate::{
	aggregator_service::generic_aggregator::{GenericAggregator, GenericAggregatorConfig},
	batch_helper::BatchHelper,
	prover_service::SubtreeRootCircuit,
};

const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

// Artifact subdirectory layout under the root path.
const PAIR_AGG_DIR: &str = "pair-agg";
const PAIR_LEAF_DIR: &str = "pair-agg/pair-leaf";
const SUBTREE_ROOT_DIR: &str = "subtree-root";
const SUPER_CIRCUIT_DIR: &str = "super-circuit";

// Files written into `pair-agg/pair-leaf/` by PairLeaf::store_artifacts.
const PAIR_LEAF_CD_PATH: &str = "circuit_data.bin";
const PAIR_LEAF_W_COMMON_PATH: &str = "w_common.bin";
const PAIR_LEAF_W_VERIFIER_PATH: &str = "w_verifier.bin";
const PAIR_LEAF_D_COMMON_PATH: &str = "d_common.bin";
const PAIR_LEAF_D_VERIFIER_PATH: &str = "d_verifier.bin";

// ---------------------------------------------------------------------------
// PairLeaf — the (W, D) pair leaf circuit used as leaf of the pair aggregator.
// ---------------------------------------------------------------------------

/// The pair leaf circuit: verifies one (Withdraw, Deposit) proof pair and emits
/// combined public inputs `[act_root(4) | mainpool(4) | w_unique | d_unique]`.
struct PairLeaf {
	circuit_data: CircuitDataNative,
	w_proof: ProofWithPublicInputsTarget<D>,
	d_proof: ProofWithPublicInputsTarget<D>,
	/// Inner W/D circuit data retained for artifact storage and size derivation.
	inner: BridgeTxPairLeafData, // TODO: why isn't this Arced?
}

impl PairLeaf {
	/// Build the pair leaf circuit from the two inner leaf circuit descriptors.
	fn build(inner: BridgeTxPairLeafData) -> Result<Self> {
		let (builder, w_proof, d_proof) = build_pair_leaf(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			w_proof,
			d_proof,
			inner,
		})
	}

	/// Prove a single (Withdraw, Deposit) pair → pair proof.
	fn prove(&self, w: ProofNative, d: ProofNative) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_proof_with_pis_target(&self.w_proof, &w)
			.map_err(|e| anyhow!("PairLeaf: set w_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.d_proof, &d)
			.map_err(|e| anyhow!("PairLeaf: set d_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("PairLeaf::prove: {e}"))
	}

	/// Number of W-unique PI fields (= W total PI count − 8 common PIs).
	fn w_unique_size(&self) -> usize {
		self.inner.withdraw_common.num_public_inputs - 8
	}

	/// Number of D-unique PI fields (= D total PI count − 8 common PIs).
	fn d_unique_size(&self) -> usize {
		self.inner.deposit_common.num_public_inputs - 8
	}

	/// Persist artifacts to `path/`:
	/// - `circuit_data.bin`   — full pair-leaf circuit (needed by `prove()`).
	/// - `w_common.bin` / `w_verifier.bin` — W inner data (for target reconstruction).
	/// - `d_common.bin` / `d_verifier.bin` — D inner data.
	fn store_artifacts(
		&self,
		path: &Path,
		w_gate_ser: &dyn GateSerializer<F, D>,
		d_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize PairLeaf circuit_data failed"))?;
		fs::write(path.join(PAIR_LEAF_CD_PATH), cd_bytes)?;

		write_common(
			path.join(PAIR_LEAF_W_COMMON_PATH),
			&self.inner.withdraw_common,
			w_gate_ser,
		)?;
		write_verifier(
			path.join(PAIR_LEAF_W_VERIFIER_PATH),
			&self.inner.withdraw_verifier,
		)?;
		write_common(
			path.join(PAIR_LEAF_D_COMMON_PATH),
			&self.inner.deposit_common,
			d_gate_ser,
		)?;
		write_verifier(
			path.join(PAIR_LEAF_D_VERIFIER_PATH),
			&self.inner.deposit_verifier,
		)?;
		Ok(())
	}

	/// Reconstruct from `path/`.
	fn from_artifacts(
		path: &Path,
		w_gate_ser: &dyn GateSerializer<F, D>,
		d_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let w_common = read_common(
			path.join(PAIR_LEAF_W_COMMON_PATH),
			w_gate_ser,
			"pair_leaf/w_common",
		)?;
		let w_verifier =
			read_verifier(path.join(PAIR_LEAF_W_VERIFIER_PATH), "pair_leaf/w_verifier")?;
		let d_common = read_common(
			path.join(PAIR_LEAF_D_COMMON_PATH),
			d_gate_ser,
			"pair_leaf/d_common",
		)?;
		let d_verifier =
			read_verifier(path.join(PAIR_LEAF_D_VERIFIER_PATH), "pair_leaf/d_verifier")?;

		let inner = BridgeTxPairLeafData {
			withdraw_common: w_common,
			withdraw_verifier: w_verifier,
			deposit_common: d_common,
			deposit_verifier: d_verifier,
		};
		let (_, w_proof, d_proof) = build_pair_leaf(&inner);

		let cd_bytes = fs::read(path.join(PAIR_LEAF_CD_PATH))
			.map_err(|e| anyhow!("failed to read pair_leaf/circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize PairLeaf circuit_data failed. \
					 Delete the artifacts directory and rebuild."
				)
			})?;

		Ok(Self {
			circuit_data,
			w_proof,
			d_proof,
			inner,
		})
	}

	/// Returns `true` if all pair-leaf artifact files are present under `path`.
	fn has_artifacts(path: &Path) -> bool {
		[
			PAIR_LEAF_CD_PATH,
			PAIR_LEAF_W_COMMON_PATH,
			PAIR_LEAF_W_VERIFIER_PATH,
			PAIR_LEAF_D_COMMON_PATH,
			PAIR_LEAF_D_VERIFIER_PATH,
		]
		.iter()
		.all(|f| path.join(f).is_file())
	}
}

// ---------------------------------------------------------------------------
// BridgeTxAggregator
// ---------------------------------------------------------------------------

/// Aggregates a finalized [`BridgeTxBatch`] (256 Withdraw + 256 Deposit proofs)
/// into a single Plonky2 proof carrying `super_pi_commitment` as its only
/// public output.
///
/// # Circuit pipeline
///
/// ```text
/// 256 (W, D) pairs
///     └─ PairLeaf (verify W+D, connect common PIs)  ×256  →  256 pair proofs
///        └─ GenericAggregator (arity=4, depth=4)            →  pair_agg_proof
/// 512 leaves (W accout_comm × 256, then D accout_comm × 256)
///     └─ SubtreeRootCircuit (512 leaves)                    →  sr_proof
///                       ↓
///            BridgeTxSuperCircuit
/// (verify pair_agg + sr, cross-check, uniform-PI check, Keccak)
///                       ↓
///            final_proof  [8 u32 public inputs = super_pi_commitment]
/// ```
///
/// # Artifact layout
///
/// ```text
/// path/
/// ├── pair-agg/               ← GenericAggregator (arity=4, depth=4)
/// │   └── pair-leaf/          ← PairLeaf circuit_data + inner W/D data
/// ├── subtree-root/           ← SubtreeRootCircuit
/// └── super-circuit/          ← BridgeTxSuperCircuit
/// ```
pub struct BridgeTxAggregator {
	pair_leaf: PairLeaf,
	pair_aggregator: GenericAggregator<F, ConfigNative, D>,
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
		let pair_leaf = PairLeaf::build(BridgeTxPairLeafData {
			withdraw_common: withdraw_leaf_common,
			withdraw_verifier: withdraw_leaf_verifier,
			deposit_common: deposit_leaf_common,
			deposit_verifier: deposit_leaf_verifier,
		})?;

		// arity=4, depth=4 → 4^4 = 256 pair slots.
		let pair_aggregator = GenericAggregator::new(
			GenericAggregatorConfig {
				arity: 4,
				depth: 4,
			},
			pair_leaf.circuit_data.common.clone(),
			pair_leaf.circuit_data.verifier_only.clone(),
		)?;

		let subtree_root = SubtreeRootCircuit::build(SUBTREE_BATCHSIZE)?;

		let pair_root = pair_aggregator
			.levels
			.last()
			.ok_or_else(|| anyhow!("pair_aggregator has no levels"))?;

		let inner = BridgeTxSuperCircuitData {
			pair_common: pair_root.circuit_data.common.clone(),
			pair_verifier: pair_root.circuit_data.verifier_only.clone(),
			poseidon_root_common: subtree_root.circuit_data.common.clone(),
			poseidon_root_verifier: subtree_root.circuit_data.verifier_only.clone(),
			w_unique_size: pair_leaf.w_unique_size(),
			d_unique_size: pair_leaf.d_unique_size(),
		};
		let super_circuit = BridgeTxSuperCircuit::build(inner)?;

		Ok(Self {
			pair_leaf,
			pair_aggregator,
			subtree_root,
			super_circuit,
		})
	}

	/// Prove a finalized batch, returning the super-aggregated proof.
	///
	/// Batch layout (set by [`BridgeTxBatch`]):
	/// - `batch.proofs()[0..HALF)`       → Withdraw proofs
	/// - `batch.proofs()[HALF..2*HALF)`  → Deposit proofs
	pub fn prove<B: BatchHelper>(&self, batch: &B) -> Result<ProofNative> {
		let proofs = batch.proofs();
		let w_proofs: Vec<ProofNative> = proofs[..HALF].iter().map(|p| p.proof().clone()).collect();
		let d_proofs: Vec<ProofNative> = proofs[HALF..].iter().map(|p| p.proof().clone()).collect();

		// Prove all 256 (W, D) pairs in slot order.
		let pair_proofs: Vec<ProofNative> = w_proofs
			.into_iter()
			.zip(d_proofs)
			.map(|(w, d)| self.pair_leaf.prove(w, d))
			.collect::<Result<_>>()?;

		let pair_agg = self.pair_aggregator.aggregate(pair_proofs)?;

		// SR leaves: all output_commitments in slot order (W half first, D half second).
		let leaves: Vec<HashOutput> = proofs.iter().flat_map(|p| p.output_commitments()).collect();
		assert_eq!(
			leaves.len(),
			SUBTREE_BATCHSIZE,
			"leaf count mismatch: got {}, expected {}",
			leaves.len(),
			SUBTREE_BATCHSIZE,
		);

		let sr_proof = self.subtree_root.prove(&leaves)?;

		self.super_circuit.prove(pair_agg.proof, sr_proof)
	}

	/// Persist all artifacts to `path/`.
	pub fn store_artifacts(
		&self,
		path: &Path,
		w_gate_ser: &dyn GateSerializer<F, D>,
		d_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<()> {
		// The pair aggregator's leaf = pair leaf circuit.  Uses DefaultGateSerializer
		// because the pair leaf only has standard Plonky2 recursion gates.
		self.pair_aggregator
			.store_artifacts(&path.join(PAIR_AGG_DIR), &DefaultGateSerializer)?;
		self.pair_leaf
			.store_artifacts(&path.join(PAIR_LEAF_DIR), w_gate_ser, d_gate_ser)?;
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
		let pair_aggregator =
			GenericAggregator::from_artifacts(&path.join(PAIR_AGG_DIR), &DefaultGateSerializer)?;
		let pair_leaf =
			PairLeaf::from_artifacts(&path.join(PAIR_LEAF_DIR), w_gate_ser, d_gate_ser)?;
		let subtree_root =
			SubtreeRootCircuit::from_artifacts(&path.join(SUBTREE_ROOT_DIR), SUBTREE_BATCHSIZE)?;
		let super_circuit = BridgeTxSuperCircuit::from_artifacts(
			&path.join(SUPER_CIRCUIT_DIR),
			pair_leaf.w_unique_size(),
			pair_leaf.d_unique_size(),
		)?;

		Ok(Self {
			pair_leaf,
			pair_aggregator,
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
	/// Proves one pair, aggregates with `aggregate_dummy` (depth proves instead
	/// of arity^depth), computes SR from repeated dummy leaves, then runs the
	/// super circuit.
	pub fn prove_dummy(&self) -> Result<ProofNative> {
		use plonky2::field::types::Field;
		use tessera_client::{
			build_deposit_tx_circuit, build_withdraw_tx_circuit, FakeDepositTxBuilder,
			FakeWithdrawTxBuilder, PIHelper,
		};

		let zero = HashOutput([F::ZERO; 4]);
		let w_circuit = build_withdraw_tx_circuit();
		let d_circuit = build_deposit_tx_circuit();
		let w_proof = FakeWithdrawTxBuilder::new(zero, zero)
			.build()
			.into_withdraw_tx()
			.prove(&w_circuit);
		let d_proof = FakeDepositTxBuilder::new(zero, zero)
			.build()
			.into_deposit_tx()
			.prove(&d_circuit);

		// Derive SR leaves from a single pair before consuming the proofs.
		let w_single = w_proof.output_commitments();
		let d_single = d_proof.output_commitments();
		let sr_leaves: Vec<HashOutput> = w_single
			.iter()
			.cloned()
			.cycle()
			.take(HALF)
			.chain(d_single.iter().cloned().cycle().take(HALF))
			.collect();

		let pair_proof = self.pair_leaf.prove(w_proof.proof, d_proof.proof)?;
		let pair_agg = self.pair_aggregator.aggregate_dummy(pair_proof)?;
		let sr_proof = self.subtree_root.prove(&sr_leaves)?;

		self.super_circuit.prove(pair_agg.proof, sr_proof)
	}

	/// Returns `Ok(true)` if the full artifact set is present under `path`.
	pub fn has_full_artifacts(path: &Path) -> Result<bool> {
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(&path.join(PAIR_AGG_DIR))? {
			return Ok(false);
		}
		if !PairLeaf::has_artifacts(&path.join(PAIR_LEAF_DIR)) {
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

// ---------------------------------------------------------------------------
// Artifact I/O helpers (shared with PairLeaf)
// ---------------------------------------------------------------------------

fn write_common(
	path: impl AsRef<Path>,
	data: &CommonCircuitData<F, D>,
	gate_ser: &dyn GateSerializer<F, D>,
) -> Result<()> {
	let bytes = data.to_bytes(gate_ser).map_err(|_| {
		anyhow!(
			"serialize CommonCircuitData to '{}' failed",
			path.as_ref().display()
		)
	})?;
	fs::write(path, bytes)?;
	Ok(())
}

fn write_verifier(
	path: impl AsRef<Path>,
	data: &VerifierOnlyCircuitData<ConfigNative, D>,
) -> Result<()> {
	let bytes = data.to_bytes().map_err(|_| {
		anyhow!(
			"serialize VerifierOnlyCircuitData to '{}' failed",
			path.as_ref().display()
		)
	})?;
	fs::write(path, bytes)?;
	Ok(())
}

fn read_common(
	path: impl AsRef<Path>,
	gate_ser: &dyn GateSerializer<F, D>,
	label: &str,
) -> Result<CommonCircuitData<F, D>> {
	let bytes = fs::read(&path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	CommonCircuitData::from_bytes(&bytes, gate_ser)
		.map_err(|_| anyhow!("deserialize {label} failed"))
}

fn read_verifier(
	path: impl AsRef<Path>,
	label: &str,
) -> Result<VerifierOnlyCircuitData<ConfigNative, D>> {
	let bytes = fs::read(&path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	VerifierOnlyCircuitData::from_bytes(&bytes).map_err(|_| anyhow!("deserialize {label} failed"))
}
