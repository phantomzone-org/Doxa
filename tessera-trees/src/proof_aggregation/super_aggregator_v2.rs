//! SuperAggregatorV2 circuit: merges a TX aggregation proof and a
//! SubtreeRoot proof into a single Keccak-256 piCommitment, compatible
//! with the `TesseraRollupV2` on-chain contract.
//!
//! # V2 design vs V1
//!
//! V1 verified 5 inner proofs (4 off-chain Merkle trees + TX aggregator).
//! V2 removes the 4 off-chain trees (the contract holds the Poseidon IMT)
//! and replaces them with a single `SubtreeRootCircuit` proof that proves
//! `batch_poseidon_root = PoseidonMerkle(note_commitments[0..N])`.
//!
//! # Circuit structure
//!
//! 1. Verify TX aggregation proof (`n_tx_slots × TX_LEAF_PI_SIZE` PIs).
//! 2. Verify SubtreeRoot proof (`(1 + batch_size) × 4` PIs).
//! 3. Cross-check: for each real TX slot `s` and note index `j`, assert `sr_leaf[s * notes_per_slot
//!    + j] == tx_nc[s][j]`.
//! 4. Allocate private witnesses: `ac_root[4]`, `nc_root[4]` (Goldilocks),
//!    `main_pool_cfg_root_u32s[8]` (raw bytes32).
//! 5. Collect all piCommitment fields, encode as EVM `abi.encodePacked` bytes, and hash with
//!    Keccak-256.
//! 6. Register 8 `u32` output words as the circuit's public inputs.
//!
//! # Keccak preimage field order
//!
//! Matches `TesseraRollupV2._computeTxPiCommitment` exactly:
//! ```text
//! acRoot(uint256) | ncRoot(uint256) | mainPoolConfigRoot(bytes32) |
//! batchPoseidonRoot(uint256) | accountCommitment(uint256) | accountNullifier(uint256) |
//! noteCommitments[0..N](uint256[]) | noteNullifiers[0..N](uint256[])
//! ```
//!
//! Each `uint256` HashOutput uses **LE packing**:
//! `uint256 = e0 | (e1<<64) | (e2<<128) | (e3<<192)`
//! which in big-endian EVM bytes maps to `[e3_be8, e2_be8, e1_be8, e0_be8]`.
//!
//! # Account fields
//!
//! `accountCommitment` and `accountNullifier` are extracted from TX slot 0's
//! AC and AN public inputs. The design assumes one canonical account per batch.
//!
//! # Serializer
//!
//! Uses `TesseraGeneratorSerializer` (contains Keccak-256 generators).

use std::{fs, path::Path};

use anyhow::{Result, anyhow};
use plonky2::{
	field::types::PrimeField64,
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

use super::{IS_REAL_OFFSET, TX_DATA_OFFSET, TX_LEAF_PI_SIZE};
use crate::{
	CircuitDataNative, ConfigNative, D, F, ProofNative,
	groth::serializer::TesseraGeneratorSerializer,
	plonky2_gadgets::{
		keccak256::{builder::BuilderKeccak256, utils::solidity_keccak256},
		sha256::circuit::decompose_field_to_u32_pair,
		u32::add_u8_range_check_lookup_table,
	},
	tree::hasher::HashOutput,
};

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
const TX_COMMON_PATH: &str = "tx_common.bin";
const TX_VERIFIER_PATH: &str = "tx_verifier.bin";
const SR_COMMON_PATH: &str = "sr_common.bin";
const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const ALL_ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	TX_COMMON_PATH,
	TX_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Inner circuit data for the 2 proofs verified by [`SuperAggregatorV2`].
pub struct SuperAggregatorV2CircuitData {
	pub tx_common: CommonCircuitData<F, D>,
	pub tx_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub sr_common: CommonCircuitData<F, D>,
	pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

// ---------------------------------------------------------------------------
// Internal targets
// ---------------------------------------------------------------------------

struct SuperAggregatorV2Targets {
	tx_proof: ProofWithPublicInputsTarget<D>,
	tx_vd: VerifierCircuitTarget,
	sr_proof: ProofWithPublicInputsTarget<D>,
	sr_vd: VerifierCircuitTarget,
	/// `acRoot` as 4 Goldilocks field-element targets (private witness).
	ac_root: [Target; 4],
	/// `ncRoot` as 4 Goldilocks field-element targets (private witness).
	nc_root: [Target; 4],
	/// `mainPoolConfigRoot` as 8 u32 targets (raw bytes32 big-endian, private witness).
	main_pool_cfg_root_u32s: [Target; 8],
}

// ---------------------------------------------------------------------------
// SuperAggregatorV2
// ---------------------------------------------------------------------------

/// Recursion circuit that verifies a TX aggregation proof and a SubtreeRoot
/// proof, cross-checks note commitments in-circuit, and commits to all batch
/// public inputs via Keccak-256.
///
/// # Artifact lifecycle
///
/// ```ignore
/// let agg = SuperAggregatorV2::build(inner)?;
/// agg.store_artifacts(Path::new("artifacts/super-aggregator-v2"))?;
///
/// let agg = SuperAggregatorV2::from_artifacts(Path::new("artifacts/super-aggregator-v2"))?;
/// let proof = agg.prove(tx, sr, ac_root, nc_root, main_pool_cfg_root)?;
/// ```
pub struct SuperAggregatorV2 {
	/// Compiled circuit data (needed by `BN128Wrapper::new`).
	pub circuit_data: CircuitDataNative,
	targets: SuperAggregatorV2Targets,
	inner: SuperAggregatorV2CircuitData,
}

impl SuperAggregatorV2 {
	/// Build the circuit from the two inner `CircuitData` objects.
	pub fn build(inner: SuperAggregatorV2CircuitData) -> Result<Self> {
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
	/// the big-endian u32 words of `Keccak256(V2 piCommitment preimage)`.
	///
	/// `ac_root` and `nc_root` are the on-chain Poseidon IMT roots before this
	/// batch. `main_pool_cfg_root` is the bytes32 pool config root.
	///
	/// `accountCommitment` / `accountNullifier` are derived from TX slot 0.
	pub fn prove(
		&self,
		tx: ProofNative,
		sr: ProofNative,
		ac_root: HashOutput,
		nc_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> Result<ProofNative> {
		use plonky2::field::types::Field;

		let mut pw = PartialWitness::new();

		pw.set_verifier_data_target(&self.targets.tx_vd, &self.inner.tx_verifier)
			.map_err(|e| anyhow!("set tx_vd: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)
			.map_err(|e| anyhow!("set tx_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.sr_vd, &self.inner.sr_verifier)
			.map_err(|e| anyhow!("set sr_vd: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;

		// Private witnesses — acRoot and ncRoot as Goldilocks fields.
		for (k, &t) in self.targets.ac_root.iter().enumerate() {
			pw.set_target(t, ac_root.0[k])
				.map_err(|e| anyhow!("set ac_root[{k}]: {e}"))?;
		}
		for (k, &t) in self.targets.nc_root.iter().enumerate() {
			pw.set_target(t, nc_root.0[k])
				.map_err(|e| anyhow!("set nc_root[{k}]: {e}"))?;
		}

		// mainPoolConfigRoot as 8 big-endian u32 words.
		for (i, &t) in self.targets.main_pool_cfg_root_u32s.iter().enumerate() {
			let word = u32::from_be_bytes(main_pool_cfg_root[i * 4..i * 4 + 4].try_into().unwrap());
			pw.set_target(t, F::from_canonical_u32(word))
				.map_err(|e| anyhow!("set main_pool_cfg_root_u32s[{i}]: {e}"))?;
		}

		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("SuperAggregatorV2::prove: {e}"))
	}

	/// Compute the V2 piCommitment natively, matching `_computeTxPiCommitment`
	/// in Solidity.
	///
	/// Returns 8 big-endian `u32` words — identical to `keccakToPublicInputs`
	/// applied to the keccak256 of `abi.encodePacked(all batch fields)`.
	///
	/// All `HashOutput` values are encoded as LE-packed `uint256`:
	/// `e0 | (e1<<64) | (e2<<128) | (e3<<192)` → big-endian bytes =
	/// `[e3_be8, e2_be8, e1_be8, e0_be8]`.
	#[allow(clippy::too_many_arguments)]
	pub fn compute_pi_commitment_native(
		ac_root: HashOutput,
		nc_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
		batch_poseidon_root: HashOutput,
		account_commitment: HashOutput,
		account_nullifier: HashOutput,
		note_commitments: &[HashOutput],
		note_nullifiers: &[HashOutput],
	) -> [u32; 8] {
		let mut words: Vec<u32> = Vec::new();

		// Push a HashOutput as 8 u32 words in LE-packed uint256 big-endian order.
		let push_hash = |w: &mut Vec<u32>, h: &HashOutput| {
			for &field in &[h.0[3], h.0[2], h.0[1], h.0[0]] {
				let v = field.to_canonical_u64();
				w.push((v >> 32) as u32);
				w.push(v as u32);
			}
		};

		push_hash(&mut words, &ac_root);
		push_hash(&mut words, &nc_root);

		// mainPoolConfigRoot: raw bytes32 big-endian.
		for i in 0..8 {
			words.push(u32::from_be_bytes(
				main_pool_cfg_root[i * 4..i * 4 + 4].try_into().unwrap(),
			));
		}

		push_hash(&mut words, &batch_poseidon_root);
		push_hash(&mut words, &account_commitment);
		push_hash(&mut words, &account_nullifier);

		for nc in note_commitments {
			push_hash(&mut words, nc);
		}
		for nn in note_nullifiers {
			push_hash(&mut words, nn);
		}

		solidity_keccak256(&words)
	}

	/// Extract the `accountCommitment` (AC) from a TX aggregation proof's
	/// slot-0 public inputs.
	pub fn ac_from_tx_proof(tx: &ProofNative) -> HashOutput {
		HashOutput::new(core::array::from_fn(|k| {
			tx.public_inputs[TX_DATA_OFFSET + 4 + k]
		}))
	}

	/// Extract the `accountNullifier` (AN) from a TX aggregation proof's
	/// slot-0 public inputs.
	pub fn an_from_tx_proof(tx: &ProofNative) -> HashOutput {
		HashOutput::new(core::array::from_fn(|k| {
			tx.public_inputs[TX_DATA_OFFSET + k]
		}))
	}

	/// Extract all note nullifiers (NN) from a TX aggregation proof.
	///
	/// Returns a flat `Vec` of length `n_tx_slots × notes_per_slot` ordered
	/// `(slot, note)`.
	pub fn nn_from_tx_proof(
		tx: &ProofNative,
		n_tx_slots: usize,
		notes_per_slot: usize,
	) -> Vec<HashOutput> {
		let mut out = Vec::with_capacity(n_tx_slots * notes_per_slot);
		for s in 0..n_tx_slots {
			let base = s * TX_LEAF_PI_SIZE;
			for j in 0..notes_per_slot {
				out.push(HashOutput::new(core::array::from_fn(|k| {
					tx.public_inputs[base + TX_DATA_OFFSET + 8 + j * 4 + k]
				})));
			}
		}
		out
	}

	/// Persist all artifacts to `path`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(path.join(TX_COMMON_PATH), &self.inner.tx_common, &gate_ser)?;
		write_verifier(path.join(TX_VERIFIER_PATH), &self.inner.tx_verifier)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.sr_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.sr_verifier)?;
		Ok(())
	}

	/// Reconstruct the circuit from pre-generated artifacts without recompiling.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let tx_common = read_common(path.join(TX_COMMON_PATH), &gate_ser, "tx_common")?;
		let tx_verifier = read_verifier(path.join(TX_VERIFIER_PATH), "tx_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = SuperAggregatorV2CircuitData {
			tx_common,
			tx_verifier,
			sr_common,
			sr_verifier,
		};
		let (_, targets) = setup_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize SuperAggregatorV2 circuit_data failed. \
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
		ALL_ARTIFACT_FILES.iter().all(|f| path.join(f).is_file())
	}
}

// ---------------------------------------------------------------------------
// Internal circuit helpers
// ---------------------------------------------------------------------------

/// Encode a 4-element Goldilocks hash as 8 u32 circuit targets using the
/// LE-packed `uint256` representation:
///   `uint256 = e0|(e1<<64)|(e2<<128)|(e3<<192)`
///   big-endian bytes → `[e3_be8, e2_be8, e1_be8, e0_be8]`
///   u32 words → `[e3_hi, e3_lo, e2_hi, e2_lo, e1_hi, e1_lo, e0_hi, e0_lo]`
///
/// This is the **reverse** of the V1 natural-order encoding.
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

/// Cross-check SubtreeRoot leaves against TX note commitments.
///
/// For each real TX slot (`is_real=1`), asserts `sr_leaf[s*nps + j] == tx_nc[s][j]`
/// for all `j ∈ 0..notes_per_slot`. Gated by `is_real` so dummy slots are free.
fn wire_sr_to_tx(
	builder: &mut CircuitBuilder<F, D>,
	sr_pis: &[Target],
	tx_pis: &[Target],
	n_tx_slots: usize,
	notes_per_slot: usize,
) {
	let mut constraints = Vec::with_capacity(n_tx_slots * notes_per_slot * 4);
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
		for j in 0..notes_per_slot {
			for k in 0..4 {
				// NC field: after LUT meta + subpool_in + subpool_out + is_real + AN[4] + AC[4] +
				// NN[nps×4]
				let tx_nc = tx_pis[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
				// SR leaf: PI[4 + leaf_idx*4 + k], where leaf_idx = s*nps + j.
				let sr_leaf = sr_pis[4 + (s * notes_per_slot + j) * 4 + k];
				let diff = builder.sub(tx_nc, sr_leaf);
				let gated = builder.mul(is_real, diff);
				constraints.push(gated);
			}
		}
	}
	// Fiat-Shamir seed: SR root (first 4 PIs).
	batch_assert_zero(builder, &constraints, &sr_pis[..4]);
}

/// Random-linear-combination zero check (same as V1 `batch_assert_zero`).
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
// Internal circuit builder
// ---------------------------------------------------------------------------

fn setup_builder(
	inner: &SuperAggregatorV2CircuitData,
) -> (CircuitBuilder<F, D>, SuperAggregatorV2Targets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// --- Proof targets ---
	let tx_proof = builder.add_virtual_proof_with_pis(&inner.tx_common);
	let tx_vd = builder.constant_verifier_data(&inner.tx_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
	let sr_vd = builder.constant_verifier_data(&inner.sr_verifier);

	// --- Derive batch sizes ---
	let tx_total_pi = inner.tx_common.num_public_inputs;
	assert_eq!(
		tx_total_pi % TX_LEAF_PI_SIZE,
		0,
		"TX root PI count ({tx_total_pi}) must be a multiple of TX_LEAF_PI_SIZE ({TX_LEAF_PI_SIZE})"
	);
	let n_tx_slots = tx_total_pi / TX_LEAF_PI_SIZE;

	// SR PI layout: root[4] | leaves[N×4] → total = (1+N)*4
	let sr_total_pi = inner.sr_common.num_public_inputs;
	assert_eq!(
		sr_total_pi % 4,
		0,
		"SR PI count ({sr_total_pi}) must be a multiple of 4"
	);
	let sr_batch_size = sr_total_pi / 4 - 1;
	assert_eq!(
		sr_batch_size % n_tx_slots,
		0,
		"SR batch_size ({sr_batch_size}) must be divisible by n_tx_slots ({n_tx_slots})"
	);
	let notes_per_slot = sr_batch_size / n_tx_slots;

	// --- Verify both proofs in-circuit ---
	builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

	// --- Assert is_real is boolean for each TX slot ---
	for s in 0..n_tx_slots {
		let is_real =
			BoolTarget::new_unsafe(tx_proof.public_inputs[s * TX_LEAF_PI_SIZE + IS_REAL_OFFSET]);
		builder.assert_bool(is_real);
	}

	// --- Cross-check: SR leaves == TX NC values (gated by is_real) ---
	wire_sr_to_tx(
		&mut builder,
		&sr_proof.public_inputs,
		&tx_proof.public_inputs,
		n_tx_slots,
		notes_per_slot,
	);

	// --- Allocate private witness targets ---
	let ac_root: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
	let nc_root: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
	// mainPoolConfigRoot: 8 u32 targets (raw bytes32 big-endian words, no decompose needed).
	let main_pool_cfg_root_u32s: [Target; 8] =
		core::array::from_fn(|_| builder.add_virtual_target());

	// --- Build Keccak preimage ---
	let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);

	let mut u32_targets: Vec<Target> = Vec::new();

	// 1. acRoot (uint256 LE-packed HashOutput)
	let ac_words = pack_hash_le_to_u32s(&mut builder, ac_root, byte_range_lut);
	u32_targets.extend_from_slice(&ac_words);

	// 2. ncRoot (uint256 LE-packed HashOutput)
	let nc_words = pack_hash_le_to_u32s(&mut builder, nc_root, byte_range_lut);
	u32_targets.extend_from_slice(&nc_words);

	// 3. mainPoolConfigRoot (bytes32 — 8 raw u32 words passed directly)
	u32_targets.extend_from_slice(&main_pool_cfg_root_u32s);

	// 4. batchPoseidonRoot (uint256 LE-packed) — SR proof PI[0..4]
	let sr_root: [Target; 4] = core::array::from_fn(|k| sr_proof.public_inputs[k]);
	let sr_root_words = pack_hash_le_to_u32s(&mut builder, sr_root, byte_range_lut);
	u32_targets.extend_from_slice(&sr_root_words);

	// 5. accountCommitment — TX slot 0 AC: PI[TX_DATA_OFFSET+4..TX_DATA_OFFSET+8]
	let ac_elem: [Target; 4] =
		core::array::from_fn(|k| tx_proof.public_inputs[TX_DATA_OFFSET + 4 + k]);
	let ac_elem_words = pack_hash_le_to_u32s(&mut builder, ac_elem, byte_range_lut);
	u32_targets.extend_from_slice(&ac_elem_words);

	// 6. accountNullifier — TX slot 0 AN: PI[TX_DATA_OFFSET..TX_DATA_OFFSET+4]
	let an_elem: [Target; 4] = core::array::from_fn(|k| tx_proof.public_inputs[TX_DATA_OFFSET + k]);
	let an_elem_words = pack_hash_le_to_u32s(&mut builder, an_elem, byte_range_lut);
	u32_targets.extend_from_slice(&an_elem_words);

	// 7. noteCommitments[0..N] — SR proof leaves: PI[4..]
	for i in 0..sr_batch_size {
		let leaf: [Target; 4] = core::array::from_fn(|k| sr_proof.public_inputs[4 + i * 4 + k]);
		let leaf_words = pack_hash_le_to_u32s(&mut builder, leaf, byte_range_lut);
		u32_targets.extend_from_slice(&leaf_words);
	}

	// 8. noteNullifiers[0..N] — TX NN values (all slots, all notes) NN[s][j]: PI[s*77 +
	//    TX_DATA_OFFSET + 8 + j*4 .. +4]
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		for j in 0..notes_per_slot {
			let nn: [Target; 4] = core::array::from_fn(|k| {
				tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k]
			});
			let nn_words = pack_hash_le_to_u32s(&mut builder, nn, byte_range_lut);
			u32_targets.extend_from_slice(&nn_words);
		}
	}

	// --- Keccak-256 → 8 output words → public inputs ---
	let hash = builder.keccak256::<ConfigNative>(&u32_targets);
	for &word in &hash {
		builder.register_public_input(word);
	}

	let targets = SuperAggregatorV2Targets {
		tx_proof,
		tx_vd,
		sr_proof,
		sr_vd,
		ac_root,
		nc_root,
		main_pool_cfg_root_u32s,
	};

	(builder, targets)
}

// ---------------------------------------------------------------------------
// Artifact I/O helpers
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

/// Validate SubtreeRoot leaf ↔ TX NC mapping off-circuit.
///
/// For each real TX slot, asserts `sr_pis[4 + (s*nps+j)*4 + k] == tx_nc[s][j][k]`.
///
/// `sr_pis`: SubtreeRoot proof public inputs (`(1+batch_size)*4` elements).
/// `tx_pis`: TX aggregation proof public inputs (`n_tx_slots * 77` elements).
pub fn validate_subtree_nc_offcircuit(
	sr_pis: &[F],
	tx_pis: &[F],
	n_tx_slots: usize,
	notes_per_slot: usize,
) -> Result<()> {
	use plonky2::field::types::{Field, PrimeField64};
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
		if is_real == F::ONE {
			for j in 0..notes_per_slot {
				for k in 0..4 {
					let tx_nc =
						tx_pis[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
					let leaf_idx = s * notes_per_slot + j;
					let sr_leaf = sr_pis[4 + leaf_idx * 4 + k];
					if tx_nc != sr_leaf {
						return Err(anyhow!(
							"SR/TX NC mismatch: slot {s} note {j} field {k}: \
							 tx={} sr={}",
							tx_nc.to_canonical_u64(),
							sr_leaf.to_canonical_u64()
						));
					}
				}
			}
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Tests (Phase D1 — step 20)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use plonky2::{
		field::types::Field,
		iop::{target::Target, witness::PartialWitness},
		plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{
		proof_aggregation::{SubtreeRootCircuit, TX_LEAF_PI_SIZE},
		tree::hasher::{HashOutput, NewRandom},
	};

	// -----------------------------------------------------------------
	// Helpers for synthetic TX aggregation proofs
	// -----------------------------------------------------------------

	/// Build a minimal "TX aggregation" leaf circuit with exactly
	/// `n_tx_slots * TX_LEAF_PI_SIZE` public inputs.
	fn build_tx_agg(n_tx_slots: usize) -> (crate::CircuitDataNative, Vec<Target>) {
		let n_pi = n_tx_slots * TX_LEAF_PI_SIZE;
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<crate::ConfigNative>(), targets)
	}

	/// Set all PI values for a TX agg proof.
	/// `slot_values[s]` is a `Vec<u64>` of exactly `TX_LEAF_PI_SIZE` elements.
	fn prove_tx_agg(
		cd: &crate::CircuitDataNative,
		targets: &[Target],
		slot_values: &[Vec<u64>],
	) -> ProofNative {
		let mut flat = Vec::new();
		for sv in slot_values {
			assert_eq!(sv.len(), TX_LEAF_PI_SIZE);
			flat.extend_from_slice(sv);
		}
		assert_eq!(flat.len(), targets.len());
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(flat.iter()) {
			pw.set_target(t, F::from_canonical_u64(v)).unwrap();
		}
		cd.prove(pw).unwrap()
	}

	/// Build slot values for one TX slot.
	///
	/// `is_real`: 0 or 1.
	/// `an`: 4-element account nullifier.
	/// `ac`: 4-element account commitment.
	/// `nn`: `notes_per_slot × 4` note nullifiers (flat).
	/// `nc`: `notes_per_slot × 4` note commitments (flat).
	fn make_slot(
		is_real: u64,
		an: [u64; 4],
		ac: [u64; 4],
		nn_flat: &[u64],
		nc_flat: &[u64],
	) -> Vec<u64> {
		let mut v = vec![0u64; TX_LEAF_PI_SIZE];
		// PI[0..2] = LUT metadata = 0
		// PI[2] = subpool_id_in = 0
		// PI[3] = subpool_id_out = 0
		v[4] = is_real; // IS_REAL_OFFSET = 4
		v[5] = an[0];
		v[6] = an[1];
		v[7] = an[2];
		v[8] = an[3]; // AN
		v[9] = ac[0];
		v[10] = ac[1];
		v[11] = ac[2];
		v[12] = ac[3]; // AC
		// NN at [13..45] (8×4=32 fields)
		assert_eq!(nn_flat.len(), v[13..45].len());
		v[13..45].copy_from_slice(nn_flat);
		// NC at [45..77] (8×4=32 fields)
		assert_eq!(nc_flat.len(), v[45..77].len());
		v[45..77].copy_from_slice(nc_flat);
		v
	}

	/// Build 8 note commitments where NC[j] = HashOutput(base+j, 0, 0, 0).
	fn make_nc_flat(base: u64) -> [u64; 32] {
		let mut out = [0u64; 32];
		for j in 0..8usize {
			out[j * 4] = base + j as u64;
		}
		out
	}

	/// Build 8 note nullifiers where NN[j] = HashOutput(base+j, 0, 0, 0).
	fn make_nn_flat(base: u64) -> [u64; 32] {
		let mut out = [0u64; 32];
		for j in 0..8usize {
			out[j * 4] = base + j as u64;
		}
		out
	}

	// -----------------------------------------------------------------
	// Test: circuit compiles and produces 8 PIs
	// -----------------------------------------------------------------

	#[test]
	fn test_build_pi_count() -> Result<()> {
		let (tx_cd, _) = build_tx_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(16)?; // 2 slots × 8 notes

		let inner = SuperAggregatorV2CircuitData {
			tx_common: tx_cd.common.clone(),
			tx_verifier: tx_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = SuperAggregatorV2::build(inner)?;
		assert_eq!(agg.circuit_data.common.num_public_inputs, 8);
		Ok(())
	}

	// -----------------------------------------------------------------
	// Test: prove + verify + native piCommitment match
	// -----------------------------------------------------------------

	#[test]
	fn test_prove_and_pi_commitment_matches_native() -> Result<()> {
		// Build inner circuits.
		let (tx_cd, tx_targets) = build_tx_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(16)?; // 2 slots × 8 notes

		// NC values for slot 0 (real) and slot 1 (dummy, is_real=0).
		let nc0 = make_nc_flat(0x4000);
		let nc1 = make_nc_flat(0); // dummy
		let nn0 = make_nn_flat(0x3000);
		let nn1 = make_nn_flat(0);

		let an0 = [0x1000u64, 0, 0, 0];
		let ac0 = [0x2000u64, 0, 0, 0];

		let slot0 = make_slot(1, an0, ac0, &nn0, &nc0);
		let slot1 = make_slot(0, [0; 4], [0; 4], &nn1, &nc1);

		// Build TX agg proof.
		let tx_proof = prove_tx_agg(&tx_cd, &tx_targets, &[slot0, slot1]);

		// SR leaves: slot0 NC[j] for j=0..8, then zeros for slot1.
		let sr_leaves: Vec<HashOutput> = (0..16)
			.map(|i| {
				if i < 8 {
					HashOutput::new([
						F::from_canonical_u64(0x4000 + i as u64),
						F::ZERO,
						F::ZERO,
						F::ZERO,
					])
				} else {
					HashOutput::new([F::ZERO; 4])
				}
			})
			.collect();
		let sr_proof = sr_circuit.prove(&sr_leaves)?;

		// Build SuperAggregatorV2.
		let inner = SuperAggregatorV2CircuitData {
			tx_common: tx_cd.common.clone(),
			tx_verifier: tx_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = SuperAggregatorV2::build(inner)?;

		// Private witnesses.
		let ac_root = HashOutput::new([F::from_canonical_u64(0xAC00), F::ZERO, F::ZERO, F::ZERO]);
		let nc_root = HashOutput::new([F::from_canonical_u64(0xBC00), F::ZERO, F::ZERO, F::ZERO]);
		let main_pool_cfg_root = [0x01u8; 32];

		let proof = agg.prove(
			tx_proof.clone(),
			sr_proof.clone(),
			ac_root,
			nc_root,
			main_pool_cfg_root,
		)?;
		agg.circuit_data.verify(proof.clone())?;

		// Compare circuit output against native computation.
		let batch_poseidon_root = SubtreeRootCircuit::root_from_proof(&sr_proof);
		let account_commitment = SuperAggregatorV2::ac_from_tx_proof(&tx_proof);
		let account_nullifier = SuperAggregatorV2::an_from_tx_proof(&tx_proof);
		let note_commitments = SubtreeRootCircuit::leaves_from_proof(&sr_proof, 16);
		let note_nullifiers = SuperAggregatorV2::nn_from_tx_proof(&tx_proof, 2, 8);

		let expected = SuperAggregatorV2::compute_pi_commitment_native(
			ac_root,
			nc_root,
			main_pool_cfg_root,
			batch_poseidon_root,
			account_commitment,
			account_nullifier,
			&note_commitments,
			&note_nullifiers,
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

	// -----------------------------------------------------------------
	// Test: cross-check detects SR/TX NC mismatch
	// -----------------------------------------------------------------

	#[test]
	fn test_cross_check_rejects_nc_mismatch() -> Result<()> {
		let (tx_cd, tx_targets) = build_tx_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(16)?;

		let nc0 = make_nc_flat(0x4000);
		let nn0 = make_nn_flat(0x3000);
		let slot0 = make_slot(1, [0x1000, 0, 0, 0], [0x2000, 0, 0, 0], &nn0, &nc0);
		let slot1 = make_slot(0, [0; 4], [0; 4], &make_nn_flat(0), &make_nc_flat(0));
		let tx_proof = prove_tx_agg(&tx_cd, &tx_targets, &[slot0, slot1]);

		// SR leaves intentionally WRONG for slot 0 (different values).
		let mut rng = StdRng::from_seed([99u8; 32]);
		let wrong_leaves: Vec<HashOutput> =
			(0..16).map(|_| HashOutput::new_random(&mut rng)).collect();
		let sr_proof = sr_circuit.prove(&wrong_leaves)?;

		let inner = SuperAggregatorV2CircuitData {
			tx_common: tx_cd.common.clone(),
			tx_verifier: tx_cd.verifier_only.clone(),
			sr_common: sr_circuit.circuit_data.common.clone(),
			sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
		};
		let agg = SuperAggregatorV2::build(inner)?;

		let result = agg.prove(
			tx_proof,
			sr_proof,
			HashOutput::new([F::ZERO; 4]),
			HashOutput::new([F::ZERO; 4]),
			[0u8; 32],
		);
		assert!(result.is_err(), "prove should fail when SR leaves != TX NC");
		Ok(())
	}

	// -----------------------------------------------------------------
	// Test: validate_subtree_nc_offcircuit
	// -----------------------------------------------------------------

	#[test]
	fn test_validate_subtree_nc_offcircuit_ok() -> Result<()> {
		// Build a TX agg proof and SR proof with matching NC/leaves.
		let (tx_cd, tx_targets) = build_tx_agg(2);
		let sr_circuit = SubtreeRootCircuit::build(16)?;

		let nc0 = make_nc_flat(0x5000);
		let nn0 = make_nn_flat(0x6000);
		let slot0 = make_slot(1, [0, 0, 0, 0], [0, 0, 0, 0], &nn0, &nc0);
		let slot1 = make_slot(0, [0; 4], [0; 4], &make_nn_flat(0), &make_nc_flat(0));
		let tx_proof = prove_tx_agg(&tx_cd, &tx_targets, &[slot0, slot1]);

		let sr_leaves: Vec<HashOutput> = (0..16)
			.map(|i| {
				if i < 8 {
					HashOutput::new([
						F::from_canonical_u64(0x5000 + i as u64),
						F::ZERO,
						F::ZERO,
						F::ZERO,
					])
				} else {
					HashOutput::new([F::ZERO; 4])
				}
			})
			.collect();
		let sr_proof = sr_circuit.prove(&sr_leaves)?;

		validate_subtree_nc_offcircuit(&sr_proof.public_inputs, &tx_proof.public_inputs, 2, 8)
	}

	#[test]
	fn test_validate_subtree_nc_offcircuit_mismatch() {
		let (tx_cd, tx_targets) = build_tx_agg(2);

		let nc0 = make_nc_flat(0x5000);
		let nn0 = make_nn_flat(0x6000);
		let slot0 = make_slot(1, [0; 4], [0; 4], &nn0, &nc0);
		let slot1 = make_slot(0, [0; 4], [0; 4], &make_nn_flat(0), &make_nc_flat(0));
		let tx_proof = prove_tx_agg(&tx_cd, &tx_targets, &[slot0, slot1]);

		// SR PIs with wrong leaf 0.
		let sr_circuit = SubtreeRootCircuit::build(16).unwrap();
		let mut rng = StdRng::from_seed([7u8; 32]);
		let wrong_leaves: Vec<HashOutput> =
			(0..16).map(|_| HashOutput::new_random(&mut rng)).collect();
		let sr_proof = sr_circuit.prove(&wrong_leaves).unwrap();

		let result =
			validate_subtree_nc_offcircuit(&sr_proof.public_inputs, &tx_proof.public_inputs, 2, 8);
		assert!(result.is_err(), "should detect mismatch for real slot");
	}
}
