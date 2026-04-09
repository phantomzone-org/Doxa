//! `PrivTxAggregator` — reduces a finalized [`PrivateTxBatch`] of 64 proofs to a
//! single Plonky2 proof whose only public output is `super_pi_commitment`.
//!
//! # Circuit pipeline
//!
//! ```text
//! 64 PrivTx proofs
//!     └─ GenericAggregator (arity=8, depth=2)  →  tx_agg_proof
//! 512 leaves from output_commitments
//!     └─ SubtreeRootCircuit (512 leaves)        →  sr_proof
//!                       ↓
//!            PrivTxSuperCircuit
//!  (verify both, cross-check, common-PI check, Keccak)
//!                       ↓
//!            final_proof  [8 u32 public inputs = super_pi_commitment]
//! ```
//!
//! # super_pi_commitment preimage (matches [`BatchHelper::pi_commitment`])
//!
//! ```text
//! sr_root[4 GL] | act_root[4 GL] | mainpool_config_root[4 GL]
//! | unique_pis_slot_0 | ... | unique_pis_slot_63
//! ```
//!
//! Each GL field → `[lo_u32, hi_u32]` (matching `BatchHelper::push_fields`).

use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
		proof::ProofWithPublicInputsTarget,
	},
	util::serialization::{DefaultGateSerializer, GateSerializer},
};
use tessera_client::{
	NOTE_BATCH, PIHelper, PRIV_TX_BATCH_SIZE, SUBTREE_BATCHSIZE,
	plonky2_gadgets::priv_tx::targets::TxCircuitPublicTargets,
};
use tessera_utils::{
	groth::TesseraGeneratorSerializer,
	hasher::HashOutput,
	plonky2_gadgets::{
		keccak256::{builder::BuilderKeccak256, field_decompose::decompose_field_to_u32_pair},
		u32::gadgets::add_u8_range_check_lookup_table,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

use crate::{
	aggregator_service::generic_aggregator::{GenericAggregator, GenericAggregatorConfig},
	batch_helper::BatchHelper,
	prover_service::SubtreeRootCircuit,
};

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
const TX_COMMON_PATH: &str = "tx_common.bin";
const TX_VERIFIER_PATH: &str = "tx_verifier.bin";
const SR_COMMON_PATH: &str = "sr_common.bin";
const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const SUPER_CIRCUIT_ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	TX_COMMON_PATH,
	TX_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

const GENERIC_AGG_DIR: &str = "generic-agg";
const SUBTREE_ROOT_DIR: &str = "subtree-root";
const SUPER_CIRCUIT_DIR: &str = "super-circuit";

// ---------------------------------------------------------------------------
// Shared circuit helpers
// ---------------------------------------------------------------------------

/// SR proof PI accessor — no raw indices outside this struct.
struct SrTargets<'a> {
	pis: &'a [F],
}

impl<'a> SrTargets<'a> {
	fn root(&self) -> [F; 4] {
		self.pis[..4].try_into().unwrap()
	}

	fn leaf(&self, idx: usize) -> [F; 4] {
		self.pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap()
	}
}

/// SR *target* accessor used during circuit construction.
struct SrTargetRefs<'a> {
	pis: &'a [plonky2::iop::target::Target],
}

impl<'a> SrTargetRefs<'a> {
	fn root(&self) -> [plonky2::iop::target::Target; 4] {
		self.pis[..4].try_into().unwrap()
	}

	fn leaf(&self, idx: usize) -> [plonky2::iop::target::Target; 4] {
		self.pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap()
	}
}

/// Encode one Goldilocks field target as `[lo_u32, hi_u32]`, matching the
/// `push_fields` encoding used by [`BatchHelper::pi_commitment`].
fn field_to_u32_pair(
	builder: &mut CircuitBuilder<F, D>,
	f: plonky2::iop::target::Target,
	lut: usize,
) -> [plonky2::iop::target::Target; 2] {
	let [hi, lo] = decompose_field_to_u32_pair(builder, f, lut);
	[lo.0, hi.0]
}

/// Encode a slice of Goldilocks field targets as flat `[lo, hi, lo, hi, …]` u32 words.
fn fields_to_u32_words(
	builder: &mut CircuitBuilder<F, D>,
	fields: &[plonky2::iop::target::Target],
	lut: usize,
) -> Vec<plonky2::iop::target::Target> {
	fields
		.iter()
		.flat_map(|&f| field_to_u32_pair(builder, f, lut))
		.collect()
}

// ---------------------------------------------------------------------------
// PrivTxSuperCircuit
// ---------------------------------------------------------------------------

/// Inner circuit data required to build [`PrivTxSuperCircuit`].
pub struct PrivTxSuperCircuitData {
	pub tx_common: CommonCircuitData<F, D>,
	pub tx_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub sr_common: CommonCircuitData<F, D>,
	pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

struct PrivTxSuperTargets {
	tx_proof: ProofWithPublicInputsTarget<D>,
	sr_proof: ProofWithPublicInputsTarget<D>,
}

/// Recursion circuit that:
/// 1. Verifies a TX aggregation proof and a SubtreeRoot proof.
/// 2. Cross-checks SR leaves against TX output commitments.
/// 3. Asserts uniform `act_root` / `mainpool_config_root` across all TX slots.
/// 4. Emits `super_pi_commitment = Keccak256(preimage)` as 8 u32 public inputs.
pub struct PrivTxSuperCircuit {
	pub circuit_data: CircuitDataNative,
	targets: PrivTxSuperTargets,
	inner: PrivTxSuperCircuitData,
}

impl PrivTxSuperCircuit {
	/// Build the circuit from the two inner [`CircuitData`] objects.
	pub fn build(inner: PrivTxSuperCircuitData) -> Result<Self> {
		let (builder, targets) = setup_super_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Prove: verify both inner proofs and emit the 8-word `super_pi_commitment`.
	pub fn prove(&self, tx: ProofNative, sr: ProofNative) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)
			.map_err(|e| anyhow!("set tx_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("PrivTxSuperCircuit::prove: {e}"))
	}

	/// Persist all artifacts to `path/`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize PrivTxSuperCircuit circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(path.join(TX_COMMON_PATH), &self.inner.tx_common, &gate_ser)?;
		write_verifier(path.join(TX_VERIFIER_PATH), &self.inner.tx_verifier)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.sr_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.sr_verifier)?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let tx_common = read_common(path.join(TX_COMMON_PATH), &gate_ser, "tx_common")?;
		let tx_verifier = read_verifier(path.join(TX_VERIFIER_PATH), "tx_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = PrivTxSuperCircuitData {
			tx_common,
			tx_verifier,
			sr_common,
			sr_verifier,
		};
		let (_, targets) = setup_super_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize PrivTxSuperCircuit circuit_data failed. \
					 Delete the artifacts directory and rebuild."
				)
			})?;

		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Returns `true` if all artifact files are present under `path`.
	pub fn has_artifacts(path: &Path) -> bool {
		SUPER_CIRCUIT_ARTIFACT_FILES
			.iter()
			.all(|f| path.join(f).is_file())
	}
}

// ---------------------------------------------------------------------------
// PrivTxSuperCircuit — internal circuit builder
// ---------------------------------------------------------------------------

fn setup_super_builder(
	inner: &PrivTxSuperCircuitData,
) -> (CircuitBuilder<F, D>, PrivTxSuperTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets, constant-fold verifier data.
	let tx_proof = builder.add_virtual_proof_with_pis(&inner.tx_common);
	let tx_vd = builder.constant_verifier_data(&inner.tx_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
	let sr_vd = builder.constant_verifier_data(&inner.sr_verifier);

	// 2. Verify both proofs in-circuit.
	builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

	// 3. Derive pi_size from actual circuit data — no hardcoded constants.
	let pi_size = inner.tx_common.num_public_inputs / PRIV_TX_BATCH_SIZE;
	assert_eq!(
		pi_size * PRIV_TX_BATCH_SIZE,
		inner.tx_common.num_public_inputs,
		"TX PI count ({}) must be divisible by PRIV_TX_BATCH_SIZE ({})",
		inner.tx_common.num_public_inputs,
		PRIV_TX_BATCH_SIZE
	);
	assert_eq!(
		inner.sr_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4,
		"SR PI count ({}) must equal (1+SUBTREE_BATCHSIZE)*4 = {}",
		inner.sr_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4
	);

	// 4. Build named target wrappers — all PI access via named fields from here.
	let sr = SrTargetRefs {
		pis: &sr_proof.public_inputs,
	};
	let slots: Vec<TxCircuitPublicTargets> = (0..PRIV_TX_BATCH_SIZE)
		.map(|s| {
			TxCircuitPublicTargets::from_pis(
				&tx_proof.public_inputs[s * pi_size..(s + 1) * pi_size],
			)
		})
		.collect();

	// 5. Cross-check: SR leaves == TX output_commitments (unconditional — SR is
	//    built from ALL proofs, including padding).
	//    SR leaf order per slot: [AC, NC0..NC6] (8 leaves, 1 + NOTE_BATCH).
	let leaves_per_slot = 1 + NOTE_BATCH;
	for (s, slot) in slots.iter().enumerate() {
		for (j, tx_comm) in slot.output_commitments().iter().enumerate() {
			let sr_leaf = sr.leaf(s * leaves_per_slot + j);
			for k in 0..4 {
				builder.connect(tx_comm[k], sr_leaf[k]);
			}
		}
	}

	// 6. Assert uniform common PIs across all slots.
	//    Connect every slot's root / mainpool_config_root to slot 0.
	for slot in slots.iter().skip(1) {
		builder.connect_hashes(slot.root.0, slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			slots[0].mainpool_config_root.0,
		);
	}

	// 7. Build Keccak preimage (all via named fields — no raw indices).
	let lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_words: Vec<plonky2::iop::target::Target> = Vec::new();

	// batch_poseidon_root (SR proof PI[0..4])
	u32_words.extend(fields_to_u32_words(&mut builder, &sr.root(), lut));
	// common PIs once — taken from slot 0 (all slots asserted equal above)
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&slots[0].root.0.elements,
		lut,
	));
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&slots[0].mainpool_config_root.0.elements,
		lut,
	));
	// unique_pis per slot (via named accessor — no raw indices)
	for slot in &slots {
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&slot.unique_pi_targets(),
			lut,
		));
	}

	// 8. Keccak-256 → 8 u32 public inputs.
	let keccak_out = builder.keccak256::<ConfigNative>(&u32_words);
	for &w in &keccak_out {
		builder.register_public_input(w);
	}

	let targets = PrivTxSuperTargets { tx_proof, sr_proof };
	(builder, targets)
}

// ---------------------------------------------------------------------------
// PrivTxAggregator
// ---------------------------------------------------------------------------

/// Aggregates a finalized [`PrivateTxBatch`] (64 proofs) into a single Plonky2
/// proof carrying `super_pi_commitment` as its only public output.
///
/// # Artifact lifecycle
///
/// ```ignore
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
		let leaf_proofs: Vec<ProofNative> = batch
			.proofs()
			.iter()
			.map(|p| p.proof().clone())
			.collect();

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
	pub fn store_artifacts(&self, path: &Path, leaf_gate_ser: &dyn GateSerializer<F, D>) -> Result<()> {
		self.tx_aggregator
			.store_artifacts(&path.join(GENERIC_AGG_DIR), leaf_gate_ser)?;
		self.subtree_root
			.store_artifacts(&path.join(SUBTREE_ROOT_DIR))?;
		self.super_circuit
			.store_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling any circuit.
	pub fn from_artifacts(
		path: &Path,
		leaf_gate_ser: &dyn GateSerializer<F, D>,
	) -> Result<Self> {
		let tx_aggregator =
			GenericAggregator::from_artifacts(&path.join(GENERIC_AGG_DIR), leaf_gate_ser)?;
		let subtree_root =
			SubtreeRootCircuit::from_artifacts(&path.join(SUBTREE_ROOT_DIR), SUBTREE_BATCHSIZE)?;
		let super_circuit =
			PrivTxSuperCircuit::from_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(Self {
			tx_aggregator,
			subtree_root,
			super_circuit,
		})
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

// ---------------------------------------------------------------------------
// Artifact I/O helpers (private)
// ---------------------------------------------------------------------------

fn write_common(
	path: impl AsRef<Path>,
	data: &CommonCircuitData<F, D>,
	gate_ser: &DefaultGateSerializer,
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
	gate_ser: &DefaultGateSerializer,
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
	VerifierOnlyCircuitData::from_bytes(&bytes)
		.map_err(|_| anyhow!("deserialize {label} failed"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	/// `GenericAggregatorConfig{arity=8, depth=2}` must be valid (`8^2 = 64 slots`).
	#[test]
	fn priv_tx_agg_config_is_valid() {
		let cfg = GenericAggregatorConfig {
			arity: 8,
			depth: 2,
		};
		assert!(cfg.validate().is_ok(), "config must be valid");
		assert_eq!(
			cfg.arity.pow(cfg.depth as u32),
			PRIV_TX_BATCH_SIZE,
			"8^2 must equal PRIV_TX_BATCH_SIZE"
		);
	}

	/// Each PrivTx slot produces `1 + NOTE_BATCH` SR leaves; total must equal
	/// `SUBTREE_BATCHSIZE`.
	#[test]
	fn priv_tx_sr_leaf_count_matches() {
		let leaves_per_slot = 1 + NOTE_BATCH;
		assert_eq!(
			PRIV_TX_BATCH_SIZE * leaves_per_slot,
			SUBTREE_BATCHSIZE,
			"PRIV_TX_BATCH_SIZE * (1+NOTE_BATCH) must equal SUBTREE_BATCHSIZE"
		);
	}

	/// Verify the expected Keccak preimage word count matches `BatchHelper::pi_commitment`.
	///
	/// Preimage = sr_root[4] + act_root[4] + mcr[4] + 64 * unique_pis_per_slot
	/// unique_pis_per_slot = not_fake_tx[1] + accin_null[4] + accout_comm[4]
	///   + inotes_null[7×4=28] + onotes_comm[7×4=28] = 65 fields
	/// Total fields = 12 + 64×65 = 4172 → u32 words = 4172×2 = 8344.
	#[test]
	fn priv_tx_preimage_word_count() {
		let unique_per_slot = 1 + 4 + 4 + NOTE_BATCH * 4 + NOTE_BATCH * 4; // = 65
		let total_fields = 4 + 4 + 4 + PRIV_TX_BATCH_SIZE * unique_per_slot;
		assert_eq!(total_fields, 4172, "total preimage fields");
		assert_eq!(total_fields * 2, 8344, "total preimage u32 words");
	}
}
