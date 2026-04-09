//! `BridgeTxAggregator` — reduces a finalized [`BridgeTxBatch`] of
//! 256 Withdraw + 256 Deposit proofs into a single Plonky2 proof whose only
//! public output is `super_pi_commitment`.
//!
//! # Circuit pipeline
//!
//! ```text
//! 256 Withdraw proofs
//!     └─ GenericAggregator (arity=4, depth=4)  →  w_agg_proof
//! 256 Deposit proofs
//!     └─ GenericAggregator (arity=4, depth=4)  →  d_agg_proof
//! 512 leaves from output_commitments
//!     └─ SubtreeRootCircuit (512 leaves)        →  sr_proof
//!                       ↓
//!            BridgeTxSuperCircuit
//! (verify all three, cross-check, common-PI check, Keccak)
//!                       ↓
//!            final_proof  [8 u32 public inputs = super_pi_commitment]
//! ```
//!
//! # SR leaf layout
//!
//! Withdraw slots → SR[0..256), one leaf = accout_comm per slot.
//! Deposit slots  → SR[256..512), one leaf = accout_comm per slot.
//!
//! # super_pi_commitment preimage (matches [`BatchHelper::pi_commitment`])
//!
//! ```text
//! sr_root[4 GL] | act_root[4 GL] | mainpool_config_root[4 GL]
//! | unique_pis_w_slot_0 | … | unique_pis_w_slot_255
//! | unique_pis_d_slot_0 | … | unique_pis_d_slot_255
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
	BRIDGE_TX_BATCH_SIZE, PIHelper, SUBTREE_BATCHSIZE,
	plonky2_gadgets::{
		deposit_tx::targets::DepositTxPublicTargets,
		withdraw_tx::targets::WithdrawTxPublicTargets,
	},
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
const W_COMMON_PATH: &str = "w_common.bin";
const W_VERIFIER_PATH: &str = "w_verifier.bin";
const D_COMMON_PATH: &str = "d_common.bin";
const D_VERIFIER_PATH: &str = "d_verifier.bin";
const SR_COMMON_PATH: &str = "sr_common.bin";
const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const SUPER_CIRCUIT_ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	W_COMMON_PATH,
	W_VERIFIER_PATH,
	D_COMMON_PATH,
	D_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

const W_AGG_DIR: &str = "withdraw-agg";
const D_AGG_DIR: &str = "deposit-agg";
const SUBTREE_ROOT_DIR: &str = "subtree-root";
const SUPER_CIRCUIT_DIR: &str = "super-circuit";

/// Half of `BRIDGE_TX_BATCH_SIZE` — number of withdraw slots = number of deposit slots.
const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

// ---------------------------------------------------------------------------
// Shared circuit helpers
// ---------------------------------------------------------------------------

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

/// Encode one Goldilocks field target as `[lo_u32, hi_u32]`, matching
/// `BatchHelper::push_fields` encoding.
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
// BridgeTxSuperCircuit
// ---------------------------------------------------------------------------

/// Inner circuit data required to build [`BridgeTxSuperCircuit`].
pub struct BridgeTxSuperCircuitData {
	pub w_common: CommonCircuitData<F, D>,
	pub w_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub d_common: CommonCircuitData<F, D>,
	pub d_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub sr_common: CommonCircuitData<F, D>,
	pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

struct BridgeTxSuperTargets {
	w_proof: ProofWithPublicInputsTarget<D>,
	d_proof: ProofWithPublicInputsTarget<D>,
	sr_proof: ProofWithPublicInputsTarget<D>,
}

/// Recursion circuit that:
/// 1. Verifies withdraw, deposit, and SubtreeRoot aggregation proofs.
/// 2. Cross-checks SR leaves against TX output commitments.
/// 3. Asserts uniform `act_root` / `mainpool_config_root` across all slots.
/// 4. Emits `super_pi_commitment = Keccak256(preimage)` as 8 u32 public inputs.
pub struct BridgeTxSuperCircuit {
	pub circuit_data: CircuitDataNative,
	targets: BridgeTxSuperTargets,
	inner: BridgeTxSuperCircuitData,
}

impl BridgeTxSuperCircuit {
	/// Build the circuit from the three inner [`CircuitData`] objects.
	pub fn build(inner: BridgeTxSuperCircuitData) -> Result<Self> {
		let (builder, targets) = setup_super_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Prove: verify all three inner proofs and emit the 8-word `super_pi_commitment`.
	pub fn prove(
		&self,
		w_agg: ProofNative,
		d_agg: ProofNative,
		sr: ProofNative,
	) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_proof_with_pis_target(&self.targets.w_proof, &w_agg)
			.map_err(|e| anyhow!("set w_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.d_proof, &d_agg)
			.map_err(|e| anyhow!("set d_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("BridgeTxSuperCircuit::prove: {e}"))
	}

	/// Persist all artifacts to `path/`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize BridgeTxSuperCircuit circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(path.join(W_COMMON_PATH), &self.inner.w_common, &gate_ser)?;
		write_verifier(path.join(W_VERIFIER_PATH), &self.inner.w_verifier)?;
		write_common(path.join(D_COMMON_PATH), &self.inner.d_common, &gate_ser)?;
		write_verifier(path.join(D_VERIFIER_PATH), &self.inner.d_verifier)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.sr_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.sr_verifier)?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let w_common = read_common(path.join(W_COMMON_PATH), &gate_ser, "w_common")?;
		let w_verifier = read_verifier(path.join(W_VERIFIER_PATH), "w_verifier")?;
		let d_common = read_common(path.join(D_COMMON_PATH), &gate_ser, "d_common")?;
		let d_verifier = read_verifier(path.join(D_VERIFIER_PATH), "d_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = BridgeTxSuperCircuitData {
			w_common,
			w_verifier,
			d_common,
			d_verifier,
			sr_common,
			sr_verifier,
		};
		let (_, targets) = setup_super_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize BridgeTxSuperCircuit circuit_data failed. \
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
// BridgeTxSuperCircuit — internal circuit builder
// ---------------------------------------------------------------------------

fn setup_super_builder(
	inner: &BridgeTxSuperCircuitData,
) -> (CircuitBuilder<F, D>, BridgeTxSuperTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets, constant-fold verifier data.
	let w_proof = builder.add_virtual_proof_with_pis(&inner.w_common);
	let w_vd = builder.constant_verifier_data(&inner.w_verifier);
	let d_proof = builder.add_virtual_proof_with_pis(&inner.d_common);
	let d_vd = builder.constant_verifier_data(&inner.d_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
	let sr_vd = builder.constant_verifier_data(&inner.sr_verifier);

	// 2. Verify all three proofs in-circuit.
	builder.verify_proof::<ConfigNative>(&w_proof, &w_vd, &inner.w_common);
	builder.verify_proof::<ConfigNative>(&d_proof, &d_vd, &inner.d_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

	// 3. Derive pi_sizes — no hardcoded constants.
	let w_pi_size = inner.w_common.num_public_inputs / HALF;
	assert_eq!(
		w_pi_size * HALF,
		inner.w_common.num_public_inputs,
		"W PI count ({}) must be divisible by HALF ({})",
		inner.w_common.num_public_inputs,
		HALF
	);
	let d_pi_size = inner.d_common.num_public_inputs / HALF;
	assert_eq!(
		d_pi_size * HALF,
		inner.d_common.num_public_inputs,
		"D PI count ({}) must be divisible by HALF ({})",
		inner.d_common.num_public_inputs,
		HALF
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
	let w_slots: Vec<WithdrawTxPublicTargets> = (0..HALF)
		.map(|s| {
			WithdrawTxPublicTargets::from_pis(
				&w_proof.public_inputs[s * w_pi_size..(s + 1) * w_pi_size],
			)
		})
		.collect();
	let d_slots: Vec<DepositTxPublicTargets> = (0..HALF)
		.map(|s| {
			DepositTxPublicTargets::from_pis(
				&d_proof.public_inputs[s * d_pi_size..(s + 1) * d_pi_size],
			)
		})
		.collect();

	// 5. Cross-check: SR leaves == TX output_commitments (unconditional).
	//    Withdraw slots → SR[0..HALF), deposit slots → SR[HALF..2*HALF).
	//    Each bridge slot has exactly 1 output commitment (accout_comm).
	for (s, slot) in w_slots.iter().enumerate() {
		let sr_leaf = sr.leaf(s);
		let oc = slot.output_commitment();
		for k in 0..4 {
			builder.connect(oc[k], sr_leaf[k]);
		}
	}
	for (s, slot) in d_slots.iter().enumerate() {
		let sr_leaf = sr.leaf(HALF + s);
		let oc = slot.output_commitment();
		for k in 0..4 {
			builder.connect(oc[k], sr_leaf[k]);
		}
	}

	// 6. Assert uniform common PIs across all slots.
	//    Reference: w_slots[0].  Connect all other withdraw + all deposit slots.
	for slot in w_slots.iter().skip(1) {
		builder.connect_hashes(slot.root.0, w_slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			w_slots[0].mainpool_config_root.0,
		);
	}
	for slot in &d_slots {
		// DepositTxPublicTargets uses `comm_root` for the ACT root.
		builder.connect_hashes(slot.comm_root.0, w_slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			w_slots[0].mainpool_config_root.0,
		);
	}

	// 7. Build Keccak preimage (all via named fields).
	//    Preimage matches BatchHelper::pi_commitment order exactly:
	//    sr_root | common_pis_once | unique_pis_per_slot (withdraw first, deposit second).
	let lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_words: Vec<plonky2::iop::target::Target> = Vec::new();

	// batch_poseidon_root (SR proof PI[0..4])
	u32_words.extend(fields_to_u32_words(&mut builder, &sr.root(), lut));
	// common PIs once — from w_slots[0] (all slots asserted equal above)
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&w_slots[0].root.0.elements,
		lut,
	));
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&w_slots[0].mainpool_config_root.0.elements,
		lut,
	));
	// unique_pis per withdraw slot
	for slot in &w_slots {
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&slot.unique_pi_targets(),
			lut,
		));
	}
	// unique_pis per deposit slot
	for slot in &d_slots {
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

	let targets = BridgeTxSuperTargets {
		w_proof,
		d_proof,
		sr_proof,
	};
	(builder, targets)
}

// ---------------------------------------------------------------------------
// BridgeTxAggregator
// ---------------------------------------------------------------------------

/// Aggregates a finalized [`BridgeTxBatch`] (256 Withdraw + 256 Deposit proofs)
/// into a single Plonky2 proof carrying `super_pi_commitment` as its only
/// public output.
///
/// # Artifact lifecycle
///
/// ```ignore
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
			w_common: w_root.circuit_data.common.clone(),
			w_verifier: w_root.circuit_data.verifier_only.clone(),
			d_common: d_root.circuit_data.common.clone(),
			d_verifier: d_root.circuit_data.verifier_only.clone(),
			sr_common: subtree_root.circuit_data.common.clone(),
			sr_verifier: subtree_root.circuit_data.verifier_only.clone(),
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
		let w_proofs: Vec<ProofNative> = proofs[..HALF]
			.iter()
			.map(|p| p.proof().clone())
			.collect();
		let d_proofs: Vec<ProofNative> = proofs[HALF..]
			.iter()
			.map(|p| p.proof().clone())
			.collect();

		let w_agg = self.w_aggregator.aggregate(w_proofs)?;
		let d_agg = self.d_aggregator.aggregate(d_proofs)?;

		// SR leaves: all output_commitments in slot order (withdraw first, then deposit).
		let leaves: Vec<HashOutput> = proofs
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
		let super_circuit =
			BridgeTxSuperCircuit::from_artifacts(&path.join(SUPER_CIRCUIT_DIR))?;
		Ok(Self {
			w_aggregator,
			d_aggregator,
			subtree_root,
			super_circuit,
		})
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

	/// `GenericAggregatorConfig{arity=4, depth=4}` must be valid (`4^4 = 256 slots`).
	#[test]
	fn bridge_tx_w_agg_config_is_valid() {
		let cfg = GenericAggregatorConfig {
			arity: 4,
			depth: 4,
		};
		assert!(cfg.validate().is_ok(), "withdraw agg config must be valid");
		assert_eq!(
			cfg.arity.pow(cfg.depth as u32),
			HALF,
			"4^4 must equal HALF (256)"
		);
	}

	/// The deposit aggregator config is identical — same validation.
	#[test]
	fn bridge_tx_d_agg_config_is_valid() {
		let cfg = GenericAggregatorConfig {
			arity: 4,
			depth: 4,
		};
		assert!(cfg.validate().is_ok(), "deposit agg config must be valid");
	}

	/// `HALF == 4^4 == 256` — each aggregator handles exactly one half of the batch.
	#[test]
	fn bridge_tx_half_is_arity_power() {
		assert_eq!(HALF, 4_usize.pow(4), "HALF must equal 4^4");
		assert_eq!(
			HALF * 2,
			BRIDGE_TX_BATCH_SIZE,
			"2*HALF must equal BRIDGE_TX_BATCH_SIZE"
		);
	}

	/// SR leaf count: withdraw(256) + deposit(256) = 512 == SUBTREE_BATCHSIZE.
	#[test]
	fn bridge_tx_sr_leaf_count_matches() {
		assert_eq!(
			HALF + HALF,
			SUBTREE_BATCHSIZE,
			"2*HALF must equal SUBTREE_BATCHSIZE"
		);
	}

	/// Verify the expected Keccak preimage word count.
	///
	/// Preimage = sr_root[4] + act_root[4] + mcr[4]
	///   + 256 × w_unique_pis + 256 × d_unique_pis
	///
	/// w_unique = not_fake_tx[1] + accin_null[4] + accout_comm[4] + asset_ids[7]
	///          + withdrawal_amts[7*8=56] + w_acc_addr[5] = 77
	/// d_unique = not_fake_tx[1] + accin_null[4] + accout_comm[4] + note_comm[4]
	///          + eth_address[5] + amount[8] + asset_id[1] = 27
	///
	/// Total fields = 12 + 256×77 + 256×27 = 12 + 19712 + 6912 = 26636
	/// Total u32 words = 26636 × 2 = 53272.
	#[test]
	fn bridge_tx_preimage_word_count() {
		use tessera_client::NOTE_BATCH;
		let w_unique = 1 + 4 + 4 + NOTE_BATCH + NOTE_BATCH * 8 + 5; // = 77
		let d_unique = 1 + 4 + 4 + 4 + 5 + 8 + 1; // = 27
		let total_fields = 4 + 4 + 4 + HALF * w_unique + HALF * d_unique;
		assert_eq!(w_unique, 77, "w_unique mismatch");
		assert_eq!(d_unique, 27, "d_unique mismatch");
		assert_eq!(total_fields, 26636, "total preimage fields");
		assert_eq!(total_fields * 2, 53272, "total preimage u32 words");
	}
}
