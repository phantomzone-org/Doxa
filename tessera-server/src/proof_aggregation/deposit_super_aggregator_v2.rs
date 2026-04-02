//! DepositSuperAggregatorV2 circuit: merges a deposit-TX aggregation proof and
//! a SubtreeRoot proof into a single Keccak-256 piCommitment, compatible with
//! the `TesseraContract.proveDepositBatch()` on-chain function.
//!
//! # Circuit structure
//!
//! 1. Verify deposit aggregation proof (`n_deposit_slots × DEPOSIT_LEAF_PI_SIZE` PIs).
//! 2. Verify SubtreeRoot proof (`(1 + n_deposit_slots) × 4` PIs).
//! 3. Cross-check: for each real deposit slot `s`, assert `sr_leaf[s][k] ==
//!    deposit_note_comm[s][k]` for `k ∈ 0..4`. Gated by `not_fake_tx` so dummy slots are
//!    unconstrained.
//! 4. Private witnesses: `act_root[4]` (Goldilocks, used for both acRoot and ncRoot),
//!    `main_pool_cfg_root_u32s[8]` (raw bytes32).
//! 5. Keccak-256 of the deposit piCommitment preimage.
//! 6. Register 8 `u32` output words as public inputs.
//!
//! # Keccak preimage field order
//!
//! ```text
//! root(uint256) | mainPoolConfigRoot(bytes32) |
//! batchPoseidonRoot(uint256) | ethAddresses[0..N](5×u32 LE-packed each)
//! ```
//!
//! `root` is the on-chain IMT root (private witness `act_root`).
//! `batchPoseidonRoot` is the SubtreeRootCircuit output (SR proof PI[0..4]).
//! `ethAddresses[i]` is `deposit_proof.PI[i*DEPOSIT_LEAF_PI_SIZE + ETH_ADDR_OFFSET ..
//! ETH_ADDR_OFFSET+5]`, encoding the depositor's ETH address as 5 × u32 little-endian limbs (via
//! `map_h160_to_f`).
//!
//! # Deposit TX public inputs layout (37 total)
//!
//! ```text
//! PI[0]       subpool_id_in
//! PI[1]       subpool_id_out
//! PI[2]       not_fake_tx
//! PI[3..7]    mainpool_config_root (4 fields)
//! PI[7..11]   act_root             (4 fields)
//! PI[11..15]  accin_null           (4 fields)
//! PI[15..19]  accout_comm          (4 fields)
//! PI[19..23]  deposit_note_comm    (4 fields)   ← cross-checked against SR
//! PI[23..28]  eth_address          (5 fields)
//! PI[28..36]  amount               (8 fields)
//! PI[36]      asset_id             (1 field)
//! ```

use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	hash::poseidon::PoseidonHash,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{
			CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
		},
		proof::ProofWithPublicInputsTarget,
	},
	util::serialization::DefaultGateSerializer,
};
use tessera_utils::{
	hasher::HashOutput,
	plonky2_gadgets::{
		keccak256::{builder::BuilderKeccak256, field_decompose::decompose_field_to_u32_pair},
		u32::gadgets::add_u8_range_check_lookup_table,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

// ---------------------------------------------------------------------------
// PI layout constants
// ---------------------------------------------------------------------------

/// Number of public inputs per deposit_tx leaf.
/// Layout (37 total):
///   [0]     subpool_id_in
///   [1]     subpool_id_out
///   [2]     not_fake_tx          ← DEPOSIT_IS_REAL_OFFSET
///   [3-6]   mainpool_config_root (4 fields)
///   [7-10]  act_root             (4 fields)
///   [11-14] accin_null           (4 fields)
///   [15-18] accout_comm          (4 fields)
///   [19-22] deposit_note_comm    (4 fields) ← DEPOSIT_NOTE_COMM_OFFSET
///   [23-27] eth_address          (5 fields) ← ETH_ADDR_OFFSET
///   [28-35] amount               (8 fields)
///   [36]    asset_id
pub const DEPOSIT_LEAF_PI_SIZE: usize = 37;
/// Offset of `not_fake_tx` within a deposit leaf's public inputs.
pub const DEPOSIT_IS_REAL_OFFSET: usize = 2;
/// Offset of `deposit_note_comm` within a deposit leaf's public inputs.
pub const DEPOSIT_NOTE_COMM_OFFSET: usize = 19;
/// Offset of `eth_address` within a deposit leaf's public inputs.
pub const ETH_ADDR_OFFSET: usize = 23;
/// Number of field elements in an Ethereum address (5 × u32 LE limbs).
pub const ETH_ADDR_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
const DEPOSIT_COMMON_PATH: &str = "deposit_common.bin";
const DEPOSIT_VERIFIER_PATH: &str = "deposit_verifier.bin";
const SR_COMMON_PATH: &str = "sr_common.bin";
const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const ALL_ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	DEPOSIT_COMMON_PATH,
	DEPOSIT_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Inner circuit data for the two proofs verified by [`DepositSuperAggregatorV2`].
pub struct DepositSuperAggregatorV2CircuitData {
	pub deposit_common: CommonCircuitData<F, D>,
	pub deposit_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub sr_common: CommonCircuitData<F, D>,
	pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

// ---------------------------------------------------------------------------
// Internal targets
// ---------------------------------------------------------------------------

struct DepositSuperAggregatorV2Targets {
	deposit_proof: ProofWithPublicInputsTarget<D>,
	deposit_vd: VerifierCircuitTarget,
	sr_proof: ProofWithPublicInputsTarget<D>,
	sr_vd: VerifierCircuitTarget,
	/// On-chain IMT root as 4 Goldilocks field targets (private witness).
	act_root: [Target; 4],
	/// `mainPoolConfigRoot` as 8 u32 targets (bytes32 big-endian, private witness).
	main_pool_cfg_root_u32s: [Target; 8],
}

// ---------------------------------------------------------------------------
// DepositSuperAggregatorV2
// ---------------------------------------------------------------------------

/// Recursion circuit that verifies a deposit-TX aggregation proof and a
/// SubtreeRoot proof, cross-checks `deposit_note_comm` values against SR
/// leaves, and commits to all deposit batch public inputs via Keccak-256.
pub struct DepositSuperAggregatorV2 {
	/// Compiled circuit data (needed by `BN128Wrapper::new`).
	pub circuit_data: CircuitDataNative,
	targets: DepositSuperAggregatorV2Targets,
	inner: DepositSuperAggregatorV2CircuitData,
}

impl DepositSuperAggregatorV2 {
	/// Build the circuit from the two inner `CircuitData` objects.
	pub fn build(inner: DepositSuperAggregatorV2CircuitData) -> Result<Self> {
		let (builder, targets) = setup_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Prove: verifies both inner proofs in-circuit and returns the root proof.
	///
	/// Public inputs of the root proof: 8 Goldilocks field elements holding
	/// the big-endian u32 words of `Keccak256(deposit piCommitment preimage)`.
	pub fn prove(
		&self,
		deposit_agg: ProofNative,
		sr: ProofNative,
		act_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> Result<ProofNative> {
		use plonky2::field::types::Field;

		let mut pw = PartialWitness::new();

		pw.set_verifier_data_target(&self.targets.deposit_vd, &self.inner.deposit_verifier)
			.map_err(|e| anyhow!("set deposit_vd: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.deposit_proof, &deposit_agg)
			.map_err(|e| anyhow!("set deposit_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.sr_vd, &self.inner.sr_verifier)
			.map_err(|e| anyhow!("set sr_vd: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;

		// Private witnesses — act_root as Goldilocks fields.
		for (k, &t) in self.targets.act_root.iter().enumerate() {
			pw.set_target(t, act_root.0[k])
				.map_err(|e| anyhow!("set act_root[{k}]: {e}"))?;
		}

		// mainPoolConfigRoot as 8 big-endian u32 words.
		for (i, &t) in self.targets.main_pool_cfg_root_u32s.iter().enumerate() {
			let word = u32::from_be_bytes(main_pool_cfg_root[i * 4..i * 4 + 4].try_into().unwrap());
			pw.set_target(t, F::from_canonical_u32(word))
				.map_err(|e| anyhow!("set main_pool_cfg_root_u32s[{i}]: {e}"))?;
		}

		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("DepositSuperAggregatorV2::prove: {e}"))
	}

	/// Persist all artifacts to `path`.

	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		use tessera_utils::groth::TesseraGeneratorSerializer;
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(
			path.join(DEPOSIT_COMMON_PATH),
			&self.inner.deposit_common,
			&gate_ser,
		)?;
		write_verifier(
			path.join(DEPOSIT_VERIFIER_PATH),
			&self.inner.deposit_verifier,
		)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.sr_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.sr_verifier)?;
		Ok(())
	}

	/// Reconstruct the circuit from pre-generated artifacts without recompiling.

	pub fn from_artifacts(path: &Path) -> Result<Self> {
		use tessera_utils::groth::TesseraGeneratorSerializer;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let deposit_common =
			read_common(path.join(DEPOSIT_COMMON_PATH), &gate_ser, "deposit_common")?;
		let deposit_verifier = read_verifier(path.join(DEPOSIT_VERIFIER_PATH), "deposit_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = DepositSuperAggregatorV2CircuitData {
			deposit_common,
			deposit_verifier,
			sr_common,
			sr_verifier,
		};
		let (_, targets) = setup_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data = CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser)
			.map_err(|_| anyhow!("deserialize DepositSuperAggregatorV2 circuit_data failed"))?;

		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Returns `true` if all artifact files are present under `path`.
	pub fn has_artifacts(path: &Path) -> bool {
		ALL_ARTIFACT_FILES.iter().all(|f| path.join(f).is_file())
	}

	/// Number of deposit-TX slots the circuit was built for.
	pub fn deposit_batch_size(&self) -> usize {
		self.inner.deposit_common.num_public_inputs / DEPOSIT_LEAF_PI_SIZE
	}
}

// ---------------------------------------------------------------------------
// Internal circuit builder
// ---------------------------------------------------------------------------

fn setup_builder(
	inner: &DepositSuperAggregatorV2CircuitData,
) -> (CircuitBuilder<F, D>, DepositSuperAggregatorV2Targets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// --- Proof targets ---
	let deposit_proof = builder.add_virtual_proof_with_pis(&inner.deposit_common);
	let deposit_vd = builder.constant_verifier_data(&inner.deposit_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
	let sr_vd = builder.constant_verifier_data(&inner.sr_verifier);

	// --- Derive batch sizes ---
	let deposit_total_pi = inner.deposit_common.num_public_inputs;
	assert_eq!(
		deposit_total_pi % DEPOSIT_LEAF_PI_SIZE,
		0,
		"deposit PI count ({deposit_total_pi}) must be a multiple of DEPOSIT_LEAF_PI_SIZE ({DEPOSIT_LEAF_PI_SIZE})"
	);
	let n_deposit_slots = deposit_total_pi / DEPOSIT_LEAF_PI_SIZE;

	// SR PI layout: root[4] | leaves[N×4] → total = (1+N)*4
	let sr_total_pi = inner.sr_common.num_public_inputs;
	assert_eq!(
		sr_total_pi % 4,
		0,
		"SR PI count ({sr_total_pi}) must be a multiple of 4"
	);
	let sr_batch_size = sr_total_pi / 4 - 1;
	assert_eq!(
		sr_batch_size, n_deposit_slots,
		"SR batch_size ({sr_batch_size}) must equal n_deposit_slots ({n_deposit_slots})"
	);

	// --- Verify both proofs in-circuit ---
	builder.verify_proof::<ConfigNative>(&deposit_proof, &deposit_vd, &inner.deposit_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

	// --- Assert not_fake_tx is boolean for each slot ---
	for s in 0..n_deposit_slots {
		let is_real = BoolTarget::new_unsafe(
			deposit_proof.public_inputs[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_IS_REAL_OFFSET],
		);
		builder.assert_bool(is_real);
	}

	// --- Cross-check SR leaves vs deposit_note_comm (gated by not_fake_tx) ---
	wire_sr_to_deposit(
		&mut builder,
		&sr_proof.public_inputs,
		&deposit_proof.public_inputs,
		n_deposit_slots,
	);

	// --- Allocate private witness targets ---
	let act_root: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
	let main_pool_cfg_root_u32s: [Target; 8] =
		core::array::from_fn(|_| builder.add_virtual_target());

	// --- Build Keccak preimage ---
	let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_targets: Vec<Target> = Vec::new();

	// 1. root (uint256 LE-packed) — private witness act_root
	let root_words = pack_hash_le_to_u32s(&mut builder, act_root, byte_range_lut);
	u32_targets.extend_from_slice(&root_words);

	// 2. mainPoolConfigRoot (bytes32 — 8 raw u32 words)
	u32_targets.extend_from_slice(&main_pool_cfg_root_u32s);

	// 4. batchPoseidonRoot (uint256 LE-packed) — SR proof PI[0..4]
	// batchPoseidonRoot commits to all NC leaves via Poseidon.
	let sr_root: [Target; 4] = core::array::from_fn(|k| sr_proof.public_inputs[k]);
	let sr_root_words = pack_hash_le_to_u32s(&mut builder, sr_root, byte_range_lut);
	u32_targets.extend_from_slice(&sr_root_words);

	// 5. ethAddresses[0..N] — 5 u32 targets per slot, taken directly from deposit PIs.
	// Each field element fits in u32 (produced by map_h160_to_f with 32-bit limbs).
	for s in 0..n_deposit_slots {
		let base = s * DEPOSIT_LEAF_PI_SIZE + ETH_ADDR_OFFSET;
		for k in 0..ETH_ADDR_LEN {
			u32_targets.push(deposit_proof.public_inputs[base + k]);
		}
	}

	// --- Keccak-256 → 8 output words → public inputs ---
	let hash = builder.keccak256::<ConfigNative>(&u32_targets);
	for &word in &hash {
		builder.register_public_input(word);
	}

	let targets = DepositSuperAggregatorV2Targets {
		deposit_proof,
		deposit_vd,
		sr_proof,
		sr_vd,
		act_root,
		main_pool_cfg_root_u32s,
	};

	(builder, targets)
}

// ---------------------------------------------------------------------------
// Internal helpers (mirrored from super_aggregator_v2)
// ---------------------------------------------------------------------------

/// LE-packed `uint256` encoding of a 4-element Goldilocks hash as 8 u32 targets.
fn pack_hash_le_to_u32s(
	builder: &mut CircuitBuilder<F, D>,
	elements: [Target; 4],
	byte_range_lut: usize,
) -> [Target; 8] {
	let [e0, e1, e2, e3] = elements;
	let [h3, l3] = decompose_field_to_u32_pair(builder, e3, byte_range_lut);
	let [h2, l2] = decompose_field_to_u32_pair(builder, e2, byte_range_lut);
	let [h1, l1] = decompose_field_to_u32_pair(builder, e1, byte_range_lut);
	let [h0, l0] = decompose_field_to_u32_pair(builder, e0, byte_range_lut);
	[h3.0, l3.0, h2.0, l2.0, h1.0, l1.0, h0.0, l0.0]
}

/// Cross-check SubtreeRoot leaves against deposit_note_comm PI values.
///
/// For each real deposit slot (`not_fake_tx=1`), asserts
/// `sr_leaf[s][k] == deposit_note_comm[s][k]` for `k ∈ 0..4`.
fn wire_sr_to_deposit(
	builder: &mut CircuitBuilder<F, D>,
	sr_pis: &[Target],
	deposit_pis: &[Target],
	n_deposit_slots: usize,
) {
	let mut constraints = Vec::with_capacity(n_deposit_slots * 4);
	for s in 0..n_deposit_slots {
		let deposit_base = s * DEPOSIT_LEAF_PI_SIZE;
		let is_real = deposit_pis[deposit_base + DEPOSIT_IS_REAL_OFFSET];
		for k in 0..4 {
			let deposit_nc = deposit_pis[deposit_base + DEPOSIT_NOTE_COMM_OFFSET + k];
			// SR leaf i: PI[4 + i*4 + k]
			let sr_leaf = sr_pis[4 + s * 4 + k];
			let diff = builder.sub(deposit_nc, sr_leaf);
			let gated = builder.mul(is_real, diff);
			constraints.push(gated);
		}
	}
	// Fiat-Shamir seed: SR root (first 4 PIs).
	batch_assert_zero(builder, &constraints, &sr_pis[..4]);
}

/// Random-linear-combination zero check.
fn batch_assert_zero(
	builder: &mut CircuitBuilder<F, D>,
	constraints: &[Target],
	fiat_shamir_seed: &[Target],
) {
	if constraints.is_empty() {
		return;
	}
	let zero = builder.zero();
	if constraints.len() == 1 {
		builder.connect(constraints[0], zero);
		return;
	}
	let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fiat_shamir_seed.to_vec());
	let r = hash.elements[0];
	let mut acc = constraints[0];
	let mut r_pow = r;
	for &c in &constraints[1..] {
		let term = builder.mul(r_pow, c);
		acc = builder.add(acc, term);
		r_pow = builder.mul(r_pow, r);
	}
	builder.connect(acc, zero);
}

// ---------------------------------------------------------------------------
// Artifact I/O helpers
// ---------------------------------------------------------------------------

fn write_common(
	path: impl AsRef<Path>,
	data: &CommonCircuitData<F, D>,
	gate_ser: &DefaultGateSerializer,
) -> Result<()> {
	let bytes = data
		.to_bytes(gate_ser)
		.map_err(|_| anyhow!("serialize CommonCircuitData failed"))?;
	fs::write(path, bytes)?;
	Ok(())
}

fn write_verifier(
	path: impl AsRef<Path>,
	data: &VerifierOnlyCircuitData<ConfigNative, D>,
) -> Result<()> {
	let bytes = data
		.to_bytes()
		.map_err(|_| anyhow!("serialize VerifierOnlyCircuitData failed"))?;
	fs::write(path, bytes)?;
	Ok(())
}

fn read_common(
	path: impl AsRef<Path>,
	gate_ser: &DefaultGateSerializer,
	label: &str,
) -> Result<CommonCircuitData<F, D>> {
	let bytes = fs::read(path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	CommonCircuitData::from_bytes(&bytes, gate_ser)
		.map_err(|_| anyhow!("deserialize {label} failed"))
}

fn read_verifier(
	path: impl AsRef<Path>,
	label: &str,
) -> Result<VerifierOnlyCircuitData<ConfigNative, D>> {
	let bytes = fs::read(path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	VerifierOnlyCircuitData::from_bytes(&bytes).map_err(|_| anyhow!("deserialize {label} failed"))
}

// ---------------------------------------------------------------------------
// Off-circuit PI validation
// ---------------------------------------------------------------------------

/// Validate SubtreeRoot leaf ↔ deposit_note_comm mapping off-circuit.
///
/// For each real deposit slot (`not_fake_tx == F::ONE`), asserts
/// `sr_pis[4 + s*4 + k] == deposit_pis[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_NOTE_COMM_OFFSET + k]`.
pub fn validate_deposit_subtree_nc_offcircuit(
	sr_pis: &[F],
	deposit_pis: &[F],
	n_deposit_slots: usize,
) -> Result<()> {
	use plonky2::field::types::{Field, PrimeField64};
	for s in 0..n_deposit_slots {
		let deposit_base = s * DEPOSIT_LEAF_PI_SIZE;
		let is_real = deposit_pis[deposit_base + DEPOSIT_IS_REAL_OFFSET];
		if is_real == F::ONE {
			for k in 0..4 {
				let deposit_nc = deposit_pis[deposit_base + DEPOSIT_NOTE_COMM_OFFSET + k];
				let sr_leaf = sr_pis[4 + s * 4 + k];
				if deposit_nc != sr_leaf {
					return Err(anyhow!(
						"SR/deposit NC mismatch: slot {s} field {k}: deposit={} sr={}",
						deposit_nc.to_canonical_u64(),
						sr_leaf.to_canonical_u64()
					));
				}
			}
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use plonky2::{
		field::types::{Field, PrimeField64},
		iop::{target::Target, witness::PartialWitness},
		plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	};
	use rand::SeedableRng;

	use super::*;
	use crate::proof_aggregation::SubtreeRootCircuit;

	/// Build a minimal synthetic deposit-aggregation leaf circuit with exactly
	/// `n_deposit_slots * DEPOSIT_LEAF_PI_SIZE` public inputs.
	fn build_deposit_agg(n_slots: usize) -> (tessera_utils::CircuitDataNative, Vec<Target>) {
		let n_pi = n_slots * DEPOSIT_LEAF_PI_SIZE;
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

	/// Prove the synthetic deposit aggregation with given PI values.
	fn prove_deposit_agg(
		cd: &tessera_utils::CircuitDataNative,
		targets: &[Target],
		slot_values: &[Vec<u64>],
	) -> ProofNative {
		let flat: Vec<u64> = slot_values.iter().flat_map(|s| s.clone()).collect();
		assert_eq!(flat.len(), targets.len());
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(flat.iter()) {
			pw.set_target(t, F::from_canonical_u64(v)).unwrap();
		}
		cd.prove(pw).unwrap()
	}

	/// Build slot values for one deposit_tx slot.
	fn make_deposit_slot(is_real: u64, deposit_note_comm: [u64; 4]) -> Vec<u64> {
		let mut v = vec![0u64; DEPOSIT_LEAF_PI_SIZE];
		v[DEPOSIT_IS_REAL_OFFSET] = is_real;
		// deposit_note_comm at PI[15..19]
		for k in 0..4 {
			v[DEPOSIT_NOTE_COMM_OFFSET + k] = deposit_note_comm[k];
		}
		v
	}

	#[test]
	fn test_build_deposit_pi_count() -> Result<()> {
		let (deposit_cd, _) = build_deposit_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(2)?; // 2 leaves

		let inner = DepositSuperAggregatorV2CircuitData {
			deposit_common: deposit_cd.common.clone(),
			deposit_verifier: deposit_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = DepositSuperAggregatorV2::build(inner)?;
		assert_eq!(agg.circuit_data.common.num_public_inputs, 8);
		Ok(())
	}

	#[test]
	fn test_prove_and_deposit_pi_commitment_matches_native() -> Result<()> {
		use tessera_utils::hasher::HashOutput;

		let (deposit_cd, deposit_targets) = build_deposit_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(2)?;

		// Slot 0: real, with a known deposit_note_comm.
		let dnc0 = [0x1000u64, 0, 0, 0];
		let slot0 = make_deposit_slot(1, dnc0);
		// Slot 1: dummy (not_fake_tx = 0).
		let slot1 = make_deposit_slot(0, [0; 4]);

		let deposit_proof = prove_deposit_agg(&deposit_cd, &deposit_targets, &[slot0, slot1]);

		// SR leaves: slot0's deposit_note_comm, then zero for slot1.
		let sr_leaves = vec![
			HashOutput::new([F::from_canonical_u64(0x1000), F::ZERO, F::ZERO, F::ZERO]),
			HashOutput::new([F::ZERO; 4]),
		];
		let sr_proof = sr_circuit.prove(&sr_leaves)?;

		let inner = DepositSuperAggregatorV2CircuitData {
			deposit_common: deposit_cd.common.clone(),
			deposit_verifier: deposit_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = DepositSuperAggregatorV2::build(inner)?;

		let act_root = HashOutput::new([F::from_canonical_u64(0xAC00), F::ZERO, F::ZERO, F::ZERO]);
		let main_pool_cfg_root = [0x02u8; 32];

		let proof = agg.prove(
			deposit_proof.clone(),
			sr_proof.clone(),
			act_root,
			main_pool_cfg_root,
		)?;
		agg.circuit_data.verify(proof.clone())?;

		// Compare circuit PIs against native computation.
		let batch_poseidon_root = SubtreeRootCircuit::root_from_proof(&sr_proof);

		let expected = DepositSuperAggregatorV2::compute_deposit_pi_commitment_native(
			act_root,
			main_pool_cfg_root,
			batch_poseidon_root,
			&deposit_proof.public_inputs,
			2,
		);

		let actual: Vec<u64> = proof
			.public_inputs
			.iter()
			.map(|f| f.to_canonical_u64())
			.collect();
		let expected_u64: Vec<u64> = expected.iter().map(|&w| w as u64).collect();
		assert_eq!(
			actual, expected_u64,
			"circuit PIs do not match native piCommitment"
		);
		Ok(())
	}

	#[test]
	fn test_cross_check_rejects_nc_mismatch() -> Result<()> {
		use tessera_utils::hasher::{HashOutput, NewRandom};

		let (deposit_cd, deposit_targets) = build_deposit_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(2)?;

		let dnc0 = [0x4000u64, 0, 0, 0];
		let slot0 = make_deposit_slot(1, dnc0);
		let slot1 = make_deposit_slot(0, [0; 4]);
		let deposit_proof = prove_deposit_agg(&deposit_cd, &deposit_targets, &[slot0, slot1]);

		// SR leaves intentionally wrong.
		let mut rng = rand::rngs::StdRng::seed_from_u64(42);
		let wrong_leaves: Vec<HashOutput> =
			(0..2).map(|_| HashOutput::new_random(&mut rng)).collect();
		let sr_proof = sr_circuit.prove(&wrong_leaves)?;

		let inner = DepositSuperAggregatorV2CircuitData {
			deposit_common: deposit_cd.common.clone(),
			deposit_verifier: deposit_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = DepositSuperAggregatorV2::build(inner)?;

		let result = agg.prove(
			deposit_proof,
			sr_proof,
			HashOutput::new([F::ZERO; 4]),
			[0u8; 32],
		);
		assert!(
			result.is_err(),
			"prove should fail when SR leaves != deposit_note_comm"
		);
		Ok(())
	}

	#[test]
	fn test_validate_deposit_subtree_nc_offcircuit_ok() -> Result<()> {
		use tessera_utils::hasher::HashOutput;

		let (deposit_cd, deposit_targets) = build_deposit_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(2)?;

		let dnc0 = [0x5000u64, 0, 0, 0];
		let slot0 = make_deposit_slot(1, dnc0);
		let slot1 = make_deposit_slot(0, [0; 4]);
		let deposit_proof = prove_deposit_agg(&deposit_cd, &deposit_targets, &[slot0, slot1]);

		let sr_leaves = vec![
			HashOutput::new([F::from_canonical_u64(0x5000), F::ZERO, F::ZERO, F::ZERO]),
			HashOutput::new([F::ZERO; 4]),
		];
		let sr_proof = sr_circuit.prove(&sr_leaves)?;

		validate_deposit_subtree_nc_offcircuit(
			&sr_proof.public_inputs,
			&deposit_proof.public_inputs,
			2,
		)
	}

	/// Reproduce the piCommitment mismatch between `compute_deposit_pi_commitment_native`
	/// (Rust, u32 words → solidity_keccak256) and the Solidity-style encoding
	/// (raw byte preimage → standard keccak256), without running the full circuit.
	///
	/// Prints a labeled byte-by-byte breakdown of both preimages so we can
	/// visually inspect ordering and padding.
	#[test]
	fn test_deposit_pi_commitment_native_vs_solidity_encoding() {
		use alloy::primitives::Address;
		use plonky2::field::types::PrimeField64;
		use sha3::{Digest, Keccak256};

		// --- Inputs ---
		let act_root = HashOutput::new([
			F::from_canonical_u64(0x1111_2222_3333_4444),
			F::from_canonical_u64(0x5555_6666_7777_8888),
			F::from_canonical_u64(0xAAAA_BBBB_CCCC_DDDD),
			F::from_canonical_u64(0x0001_0002_0003_0004),
		]);
		let main_pool_cfg_root = [0xABu8; 32];
		let batch_poseidon_root = HashOutput::new([
			F::from_canonical_u64(0xDEAD),
			F::from_canonical_u64(0xBEEF),
			F::ZERO,
			F::ZERO,
		]);

		// Two deposit slots: one real with a known ETH address, one dummy.
		let n_slots = 2;
		let eth_addr = Address::from([
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
			0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
		]);
		let zero_addr = Address::ZERO;

		// Build fake deposit PIs with ETH address fields set.
		let mut deposit_pis = vec![F::ZERO; n_slots * DEPOSIT_LEAF_PI_SIZE];
		// Slot 0: real deposit with eth_addr
		deposit_pis[DEPOSIT_IS_REAL_OFFSET] = F::ONE;
		{
			let addr_bytes = eth_addr.as_slice();
			for k in 0..ETH_ADDR_LEN {
				let chunk = &addr_bytes[4 * k..4 * k + 4];
				let limb = u32::from_le_bytes(chunk.try_into().unwrap());
				deposit_pis[ETH_ADDR_OFFSET + k] = F::from_canonical_u32(limb);
			}
		}
		// Slot 1: dummy (all zeros, including eth_address)

		// =====================================================================
		// PATH A: Rust native (u32 words → solidity_keccak256)
		// Mirrors the circuit's keccak gadget preimage.
		// =====================================================================
		eprintln!("\n========== PATH A: NATIVE (solidity_keccak256) ==========");

		// Reconstruct the u32 words vector the same way compute_deposit_pi_commitment_native does,
		// but print each section.
		let mut native_words: Vec<u32> = Vec::new();

		// Helper: push_hash and return the words
		let push_hash = |w: &mut Vec<u32>, label: &str, h: &HashOutput| {
			let start = w.len();
			for &field in &[h.0[3], h.0[2], h.0[1], h.0[0]] {
				let v = field.to_canonical_u64();
				w.push((v >> 32) as u32);
				w.push(v as u32);
			}
			// Print the u32 words and their effective BE bytes
			eprint!("  {:<24} u32s: [", label);
			for i in start..w.len() {
				if i > start {
					eprint!(", ");
				}
				eprint!("0x{:08x}", w[i]);
			}
			eprintln!("]");
			// Effective byte stream (each u32 → BE bytes, as solidity_keccak256 emits)
			let mut bytes = Vec::new();
			for i in start..w.len() {
				bytes.extend_from_slice(&w[i].to_be_bytes());
			}
			eprintln!("  {:<24} bytes: {}", "", hex::encode(&bytes));
		};

		push_hash(&mut native_words, "root", &act_root);

		// mainPoolConfigRoot
		let start = native_words.len();
		for i in 0..8 {
			native_words.push(u32::from_be_bytes(
				main_pool_cfg_root[i * 4..i * 4 + 4].try_into().unwrap(),
			));
		}
		eprint!("  {:<24} u32s: [", "mainPoolConfigRoot");
		for i in start..native_words.len() {
			if i > start {
				eprint!(", ");
			}
			eprint!("0x{:08x}", native_words[i]);
		}
		eprintln!("]");
		{
			let mut bytes = Vec::new();
			for i in start..native_words.len() {
				bytes.extend_from_slice(&native_words[i].to_be_bytes());
			}
			eprintln!("  {:<24} bytes: {}", "", hex::encode(&bytes));
		}

		push_hash(&mut native_words, "batchPoseidonRoot", &batch_poseidon_root);

		// eth addresses
		for s in 0..n_slots {
			let base = s * DEPOSIT_LEAF_PI_SIZE + ETH_ADDR_OFFSET;
			let start = native_words.len();
			for k in 0..ETH_ADDR_LEN {
				native_words.push(deposit_pis[base + k].to_canonical_u64() as u32);
			}
			let label = format!("ethAddr[{}]", s);
			eprint!("  {:<24} u32s: [", label);
			for i in start..native_words.len() {
				if i > start {
					eprint!(", ");
				}
				eprint!("0x{:08x}", native_words[i]);
			}
			eprintln!("]");
			let mut bytes = Vec::new();
			for i in start..native_words.len() {
				bytes.extend_from_slice(&native_words[i].to_be_bytes());
			}
			eprintln!("  {:<24} bytes: {}", "", hex::encode(&bytes));
		}

		let native_u32s = solidity_keccak256(&native_words);
		let mut native_bytes = [0u8; 32];
		for (i, &w) in native_u32s.iter().enumerate() {
			native_bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
		}

		eprintln!("  total u32 words: {}", native_words.len());
		eprintln!("  total bytes:     {}", native_words.len() * 4);
		eprintln!("  hash:            {}", hex::encode(native_bytes));

		// Also run the actual function and confirm our reconstruction matches
		let native_check = DepositSuperAggregatorV2::compute_deposit_pi_commitment_native(
			act_root,
			main_pool_cfg_root,
			batch_poseidon_root,
			&deposit_pis,
			n_slots,
		);
		assert_eq!(native_u32s, native_check, "reconstruction mismatch");

		// =====================================================================
		// PATH B: Solidity-style (raw bytes → standard keccak256)
		// Mirrors _computeDepositPiCommitment in TesseraContract.sol.
		// =====================================================================
		eprintln!("\n========== PATH B: SOLIDITY (standard keccak256) ==========");

		let root_u256 = crate::contract::hash_to_u256_le(&act_root);
		let bpr_u256 = crate::contract::hash_to_u256_le(&batch_poseidon_root);

		let mut preimage: Vec<u8> = Vec::new();

		let root_bytes = root_u256.to_be_bytes::<32>();
		preimage.extend_from_slice(&root_bytes);
		eprintln!(
			"  {:<24} bytes: {}",
			"root (U256 BE)",
			hex::encode(&root_bytes)
		);

		preimage.extend_from_slice(&main_pool_cfg_root);
		eprintln!(
			"  {:<24} bytes: {}",
			"mainPoolConfigRoot",
			hex::encode(&main_pool_cfg_root)
		);

		let bpr_bytes = bpr_u256.to_be_bytes::<32>();
		preimage.extend_from_slice(&bpr_bytes);
		eprintln!(
			"  {:<24} bytes: {}",
			"batchPoseidonRoot (U256 BE)",
			hex::encode(&bpr_bytes)
		);

		// ETH addresses: Solidity's _addressToLE20 byte-reverses each 4-byte chunk.
		for (s, addr) in [eth_addr, zero_addr].iter().enumerate() {
			let be = addr.as_slice();
			let mut addr_bytes = Vec::new();
			for c in 0..5 {
				addr_bytes.push(be[4 * c + 3]);
				addr_bytes.push(be[4 * c + 2]);
				addr_bytes.push(be[4 * c + 1]);
				addr_bytes.push(be[4 * c]);
			}
			preimage.extend_from_slice(&addr_bytes);
			let label = format!("ethAddr[{}] (LE20)", s);
			eprintln!("  {:<24} bytes: {}", label, hex::encode(&addr_bytes));
		}

		let solidity_bytes: [u8; 32] = Keccak256::digest(&preimage).into();

		eprintln!("  total bytes:     {}", preimage.len());
		eprintln!("  hash:            {}", hex::encode(solidity_bytes));

		// =====================================================================
		// COMPARE
		// =====================================================================
		eprintln!("\n========== COMPARISON ==========");
		eprintln!("  native  hash: {}", hex::encode(native_bytes));
		eprintln!("  solidity hash: {}", hex::encode(solidity_bytes));

		// Reconstruct effective native byte preimage for diff
		let mut native_eff: Vec<u8> = Vec::new();
		for &w in &native_words {
			native_eff.extend_from_slice(&w.to_be_bytes());
		}
		if native_eff != preimage {
			eprintln!("\n  !!! PREIMAGE DIFFERS !!!");
			eprintln!("  native  preimage len: {}", native_eff.len());
			eprintln!("  solidity preimage len: {}", preimage.len());
			let min_len = native_eff.len().min(preimage.len());
			for i in 0..min_len {
				if native_eff[i] != preimage[i] {
					eprintln!(
						"    byte {:4}: native=0x{:02x}  solidity=0x{:02x}",
						i, native_eff[i], preimage[i]
					);
				}
			}
			if native_eff.len() != preimage.len() {
				eprintln!(
					"    LENGTH DIFF: native={} solidity={}",
					native_eff.len(),
					preimage.len()
				);
			}
		} else {
			eprintln!("  preimages match byte-for-byte");
		}
		eprintln!();

		assert_eq!(
			hex::encode(native_bytes),
			hex::encode(solidity_bytes),
			"native (solidity_keccak256) and Solidity-style (standard keccak256) commitments differ"
		);
	}
}
