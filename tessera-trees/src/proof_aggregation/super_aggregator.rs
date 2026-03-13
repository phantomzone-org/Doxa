//! SuperAggregator circuit: merges 5 independent Plonky2 proofs into one
//! Keccak-256 commitment, suitable for a single BN128/Groth16 wrapping step.
//!
//! The 5 inner proofs are:
//! - Notes commitment tree (NC)
//! - Notes nullifier tree (NN)
//! - Accounts commitment tree (AC)
//! - Accounts nullifier tree (AN)
//! - TX aggregator root (TX)
//!
//! # Circuit design
//!
//! Each inner proof's verifier data is baked into the circuit as constants
//! (`builder.constant_verifier_data`), so the SuperAggregator circuit is
//! fully determined once the 5 inner `CircuitData` objects are fixed.
//!
//! The circuit:
//! 1. Verifies all 5 inner proofs in-circuit.
//! 2. Decomposes each inner public input into a big-endian `[hi_u32, lo_u32]` pair (matching
//!    `keccak256_field_elements_native`'s encoding).
//! 3. Applies Keccak-256 over the full concatenation.
//! 4. Registers the resulting 8 `u32` words as the circuit's public outputs.
//!
//! # Public-input contract
//!
//! Root proof: **8 Goldilocks field elements** (one u32 word each, big-endian)
//! = `Keccak256(nc_pis || nn_pis || ac_pis || an_pis)`.
//! TX PIs are cross-checked against tree leaf PIs in-circuit (positional for
//! AC/NC commitment trees, multi-set equality over GF(p²) for AN/NN nullifier
//! trees) and are therefore excluded from the Keccak preimage.
//!
//! All four trees use the same PI layout: `old_root[4] || new_root[4] || leaves[N×4]`.
//! The Keccak preimage is a straight concatenation of all four tree PI vectors.
//!
//! | Circuit | PIs (fields) | Notes |
//! |---------|-------------|-------|
//! | NC tree | 4104 | old_root[4] + new_root[4] + leaves[1024×4] |
//! | NN tree | 4104 | old_root[4] + new_root[4] + values[1024×4] |
//! | AC tree |  520 | old_root[4] + new_root[4] + leaves[128×4] |
//! | AN tree |  520 | old_root[4] + new_root[4] + values[128×4] |
//! | TX (in-circuit, not in preimage) | 9344 | 128 × 73 |
//!
//! # Serializer requirement
//!
//! The root circuit contains Keccak-256 gadgets, so `store_artifacts` /
//! `from_artifacts` use [`TesseraGeneratorSerializer`] — not the plonky2
//! default.

use std::{fs, path::Path};

use anyhow::{Result, anyhow};
use plonky2::{
	hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
	iop::{
		ext_target::ExtensionTarget,
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

use crate::{
	CircuitDataNative, ConfigNative, D, F, ProofNative,
	groth::serializer::TesseraGeneratorSerializer,
	plonky2_gadgets::{
		keccak256::builder::BuilderKeccak256, sha256::circuit::decompose_field_to_u32_pair,
		u32::add_u8_range_check_lookup_table,
	},
};

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
const NC_COMMON_PATH: &str = "nc_common.bin";
const NC_VERIFIER_PATH: &str = "nc_verifier.bin";
const NN_COMMON_PATH: &str = "nn_common.bin";
const NN_VERIFIER_PATH: &str = "nn_verifier.bin";
const AC_COMMON_PATH: &str = "ac_common.bin";
const AC_VERIFIER_PATH: &str = "ac_verifier.bin";
const AN_COMMON_PATH: &str = "an_common.bin";
const AN_VERIFIER_PATH: &str = "an_verifier.bin";
const TX_COMMON_PATH: &str = "tx_common.bin";
const TX_VERIFIER_PATH: &str = "tx_verifier.bin";

const ALL_ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	NC_COMMON_PATH,
	NC_VERIFIER_PATH,
	NN_COMMON_PATH,
	NN_VERIFIER_PATH,
	AC_COMMON_PATH,
	AC_VERIFIER_PATH,
	AN_COMMON_PATH,
	AN_VERIFIER_PATH,
	TX_COMMON_PATH,
	TX_VERIFIER_PATH,
];

// ---------------------------------------------------------------------------
// PI layout constants
// ---------------------------------------------------------------------------

/// Fields per TX slot: 75 explicit + 2 plonky2 lookup-table metadata PIs.
pub const TX_LEAF_PI_SIZE: usize = 77;

/// Offset past `old_root[4] || new_root[4]` in tree PI vectors.
pub const LEAF_OFFSET: usize = 8;

/// Number of automatic lookup-table metadata PIs prepended by plonky2.
pub const LUT_PI_COUNT: usize = 2;

/// Offset to TX data fields within each TX slot
/// (after LUT metadata, subpool_in, subpool_out, is_real).
pub const TX_DATA_OFFSET: usize = LUT_PI_COUNT + 3;

/// Offset to is_real (not_fake_tx) within each TX slot (after LUT metadata,
/// subpool_in, subpool_out).
pub const IS_REAL_OFFSET: usize = LUT_PI_COUNT + 2;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Circuit data for the 5 inner proofs verified by [`SuperAggregator`].
///
/// Pass a fully-populated instance to [`SuperAggregator::build`] or construct
/// one from pre-generated artifacts via [`SuperAggregator::from_artifacts`].
pub struct SuperAggregatorCircuitData {
	pub nc_common: CommonCircuitData<F, D>,
	pub nc_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub nn_common: CommonCircuitData<F, D>,
	pub nn_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub ac_common: CommonCircuitData<F, D>,
	pub ac_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub an_common: CommonCircuitData<F, D>,
	pub an_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub tx_common: CommonCircuitData<F, D>,
	pub tx_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

// ---------------------------------------------------------------------------
// Internal targets
// ---------------------------------------------------------------------------

struct SuperAggregatorTargets {
	nc_proof: ProofWithPublicInputsTarget<D>,
	nc_vd: VerifierCircuitTarget,
	nn_proof: ProofWithPublicInputsTarget<D>,
	nn_vd: VerifierCircuitTarget,
	ac_proof: ProofWithPublicInputsTarget<D>,
	ac_vd: VerifierCircuitTarget,
	an_proof: ProofWithPublicInputsTarget<D>,
	an_vd: VerifierCircuitTarget,
	tx_proof: ProofWithPublicInputsTarget<D>,
	tx_vd: VerifierCircuitTarget,
}

// ---------------------------------------------------------------------------
// SuperAggregator
// ---------------------------------------------------------------------------

/// Single-level recursion circuit that verifies 5 independent inner proofs
/// and commits to their combined public inputs via Keccak-256.
///
/// # Artifact lifecycle
///
/// ```ignore
/// // Fresh build (compiles the circuit — may be slow).
/// let agg = SuperAggregator::build(inner)?;
/// agg.store_artifacts(Path::new("artifacts/super-aggregator"))?;
///
/// // Fast reload from disk (no recompilation).
/// let agg = SuperAggregator::from_artifacts(Path::new("artifacts/super-aggregator"))?;
/// let proof = agg.prove(nc, nn, ac, an, tx)?;
/// ```
pub struct SuperAggregator {
	/// The SuperAggregator circuit data (needed by [`BN128Wrapper::new`]).
	pub circuit_data: CircuitDataNative,
	targets: SuperAggregatorTargets,
	/// Inner circuit data — kept for witness population and artifact replay.
	inner: SuperAggregatorCircuitData,
}

impl SuperAggregator {
	/// Build the SuperAggregator circuit from scratch.
	///
	/// Each inner verifier's data is baked into the circuit as constants.
	/// This operation compiles the circuit; it may take several seconds.
	pub fn build(inner: SuperAggregatorCircuitData) -> Result<Self> {
		let (builder, targets) = setup_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Prove: verifies all 5 inner proofs in-circuit and returns the root proof.
	///
	/// Public inputs of the root proof: 8 Goldilocks field elements (Keccak-256
	/// digest over all concatenated inner tree PIs). TX slot liveness is encoded
	/// in the TX proof's own public inputs (`is_real` at `PI[s * 77 + 2]` for slot `s`).
	pub fn prove(
		&self,
		nc: ProofNative,
		nn: ProofNative,
		ac: ProofNative,
		an: ProofNative,
		tx: ProofNative,
	) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&self.targets.nc_vd, &self.inner.nc_verifier)
			.map_err(|e| anyhow!("set nc_vd (verifier): {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.nc_proof, &nc)
			.map_err(|e| anyhow!("set nc_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.nn_vd, &self.inner.nn_verifier)
			.map_err(|e| anyhow!("set nn_vd (verifier): {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.nn_proof, &nn)
			.map_err(|e| anyhow!("set nn_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.ac_vd, &self.inner.ac_verifier)
			.map_err(|e| anyhow!("set ac_vd (verifier): {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.ac_proof, &ac)
			.map_err(|e| anyhow!("set ac_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.an_vd, &self.inner.an_verifier)
			.map_err(|e| anyhow!("set an_vd (verifier): {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.an_proof, &an)
			.map_err(|e| anyhow!("set an_proof: {e}"))?;
		pw.set_verifier_data_target(&self.targets.tx_vd, &self.inner.tx_verifier)
			.map_err(|e| anyhow!("set tx_vd (verifier): {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)
			.map_err(|e| anyhow!("set tx_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("SuperAggregator::prove (generate_proof): {e}"))
	}

	/// Persist all artifacts to `path`.
	///
	/// Saves the compiled circuit data and the 5 inner circuits' common/verifier
	/// data so that [`from_artifacts`] can reconstruct everything without
	/// recompiling.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;

		let bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &TesseraGeneratorSerializer)
			.map_err(|_| {
				anyhow!(
					"serialize SuperAggregator circuit_data failed (plonky2 IoError). \
                     If a new custom generator was added, register it in \
                     tessera-trees/src/groth/serializer.rs."
				)
			})?;
		fs::write(path.join(CIRCUIT_DATA_PATH), bytes)?;

		write_common(path.join(NC_COMMON_PATH), &self.inner.nc_common, &gate_ser)?;
		write_verifier(path.join(NC_VERIFIER_PATH), &self.inner.nc_verifier)?;
		write_common(path.join(NN_COMMON_PATH), &self.inner.nn_common, &gate_ser)?;
		write_verifier(path.join(NN_VERIFIER_PATH), &self.inner.nn_verifier)?;
		write_common(path.join(AC_COMMON_PATH), &self.inner.ac_common, &gate_ser)?;
		write_verifier(path.join(AC_VERIFIER_PATH), &self.inner.ac_verifier)?;
		write_common(path.join(AN_COMMON_PATH), &self.inner.an_common, &gate_ser)?;
		write_verifier(path.join(AN_VERIFIER_PATH), &self.inner.an_verifier)?;
		write_common(path.join(TX_COMMON_PATH), &self.inner.tx_common, &gate_ser)?;
		write_verifier(path.join(TX_VERIFIER_PATH), &self.inner.tx_verifier)?;

		Ok(())
	}

	/// Reconstruct a [`SuperAggregator`] from pre-generated artifacts without
	/// recompiling the circuit.
	///
	/// Loads the inner circuit data from disk to replay the deterministic
	/// builder operations and recover target wire indices, then loads the
	/// compiled circuit data binary.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;

		let nc_common = read_common(path.join(NC_COMMON_PATH), &gate_ser, "nc_common")?;
		let nc_verifier = read_verifier(path.join(NC_VERIFIER_PATH), "nc_verifier")?;
		let nn_common = read_common(path.join(NN_COMMON_PATH), &gate_ser, "nn_common")?;
		let nn_verifier = read_verifier(path.join(NN_VERIFIER_PATH), "nn_verifier")?;
		let ac_common = read_common(path.join(AC_COMMON_PATH), &gate_ser, "ac_common")?;
		let ac_verifier = read_verifier(path.join(AC_VERIFIER_PATH), "ac_verifier")?;
		let an_common = read_common(path.join(AN_COMMON_PATH), &gate_ser, "an_common")?;
		let an_verifier = read_verifier(path.join(AN_VERIFIER_PATH), "an_verifier")?;
		let tx_common = read_common(path.join(TX_COMMON_PATH), &gate_ser, "tx_common")?;
		let tx_verifier = read_verifier(path.join(TX_VERIFIER_PATH), "tx_verifier")?;

		let inner = SuperAggregatorCircuitData {
			nc_common,
			nc_verifier,
			nn_common,
			nn_verifier,
			ac_common,
			ac_verifier,
			an_common,
			an_verifier,
			tx_common,
			tx_verifier,
		};

		// Replay builder to recover target wire indices (deterministic by construction).
		// No `build()` or `prove()` call is needed; the builder is discarded.
		let (_, targets) = setup_builder(&inner);

		let bytes = fs::read(path.join(CIRCUIT_DATA_PATH)).map_err(|e| {
			anyhow!(
				"failed to read '{}': {e}",
				path.join(CIRCUIT_DATA_PATH).display()
			)
		})?;
		let circuit_data =
			CircuitDataNative::from_bytes(&bytes, &gate_ser, &TesseraGeneratorSerializer).map_err(
				|_| {
					anyhow!(
						"deserialize SuperAggregator circuit_data from '{}' failed \
                         (plonky2 IoError). Delete the artifacts directory and \
                         re-run super_aggregator_artifacts.",
						path.join(CIRCUIT_DATA_PATH).display()
					)
				},
			)?;

		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Returns `true` if all artifact files required by [`from_artifacts`] are
	/// present under `path`.
	pub fn has_artifacts(path: &Path) -> bool {
		ALL_ARTIFACT_FILES.iter().all(|f| path.join(f).is_file())
	}
}

// ---------------------------------------------------------------------------
// GF(p²) multi-set equality gadget
// ---------------------------------------------------------------------------

/// Assert that two sets of 4-field hashes are equal as multi-sets, using a
/// product argument over GF(p²) (the quadratic extension of the Goldilocks
/// field).
///
/// Each 4-field hash `h = [h0, h1, h2, h3]` is packed into two GF(p²) elements
/// `A = (h0, h1)` and `B = (h2, h3)`, then fingerprinted as
/// `fp(h) = β + A + γ·B`, where `γ, β ∈ GF(p²)` are Fiat-Shamir challenges
/// derived from `fiat_shamir_inputs` via Poseidon.
///
/// We then assert `∏ fp(a_i) == ∏ fp(b_i)` in GF(p²). By Schwartz-Zippel the
/// soundness error is at most `N / p² ≈ 2^{-128}` for N ≤ 1024.
fn assert_multiset_eq(
	builder: &mut CircuitBuilder<F, D>,
	set_a: &[HashOutTarget],
	set_b: &[HashOutTarget],
	fiat_shamir_inputs: &[Target],
) {
	assert_eq!(set_a.len(), set_b.len(), "multi-set sizes must match");

	// 1. Derive γ, β ∈ GF(p²) via Fiat-Shamir (Poseidon hash of public data). γ is the evaluation
	//    point; β is an additive offset that prevents zero fingerprints (fp([0,0,0,0]) = β ≠ 0
	//    w.h.p.).
	let gamma_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fiat_shamir_inputs.to_vec());
	let gamma = ExtensionTarget::<D>([gamma_hash.elements[0], gamma_hash.elements[1]]);
	let beta = ExtensionTarget::<D>([gamma_hash.elements[2], gamma_hash.elements[3]]);

	// 2. Compute running products of fingerprints for both sets.
	let one = builder.one_extension();
	let mut prod_a = one;
	let mut prod_b = one;

	for (a, b) in set_a.iter().zip(set_b.iter()) {
		let fp_a = hash_fingerprint(builder, a, gamma, beta);
		let fp_b = hash_fingerprint(builder, b, gamma, beta);
		prod_a = builder.mul_extension(prod_a, fp_a);
		prod_b = builder.mul_extension(prod_b, fp_b);
	}

	// 3. Assert products are equal in GF(p²).
	builder.connect_extension(prod_a, prod_b);
}

/// Compute the GF(p²) fingerprint of a 4-field hash by packing pairs of
/// base-field elements into GF(p²) elements:
///   `A = (h[0], h[1])`, `B = (h[2], h[3])`, `fp(h) = β + A + γ·B`
///
/// Packing is free (just target indexing). The additive offset `β` ensures
/// that the zero hash `[0,0,0,0]` maps to a non-zero fingerprint.
fn hash_fingerprint(
	builder: &mut CircuitBuilder<F, D>,
	h: &HashOutTarget,
	gamma: ExtensionTarget<D>,
	beta: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
	// Pack [h0,h1] and [h2,h3] directly as GF(p²) elements (zero gates).
	let a = ExtensionTarget::<D>([h.elements[0], h.elements[1]]);
	let b = ExtensionTarget::<D>([h.elements[2], h.elements[3]]);
	// fp(h) = β + A + γ·B
	let gamma_b = builder.mul_extension(gamma, b);
	let sum = builder.add_extension(a, gamma_b);
	builder.add_extension(sum, beta)
}

// ---------------------------------------------------------------------------
// Batch zero-check helper
// ---------------------------------------------------------------------------

/// Assert that all `constraints` are zero.
///
/// Accumulates `∑ rⁱ · cᵢ` with a Poseidon-derived random challenge `r` and
/// connects the sum to zero.
///
/// Soundness: a random linear combination over Goldilocks gives false-positive
/// probability ≤ N / p ≈ 2⁻⁶⁰ for N ≤ 2²⁰.
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
// PI cross-check gadgets
// ---------------------------------------------------------------------------

/// Wire AC tree PIs to TX PIs: conditional positional equality gated by `is_real`.
///
/// For each real TX slot (`is_real=1`), enforces `tx_ac[k] == tree_ac[k]` for
/// `k ∈ 0..4`. For dummy slots (`is_real=0`), the constraint is trivially
/// satisfied (`0 * diff == 0`).
///
/// Uses [`batch_assert_zero`] to accumulate all `is_real * (tx - tree)` values
/// into a single random-linear-combination check, avoiding partition merges
/// with `builder.zero()`.
///
/// **Caller must** call `builder.assert_bool(is_real)` for each slot separately.
fn wire_ac_to_tx(
	builder: &mut CircuitBuilder<F, D>,
	ac_pis: &[Target],
	tx_pis: &[Target],
	n_tx_slots: usize,
) {
	let mut constraints = Vec::with_capacity(n_tx_slots * 4);
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
		for k in 0..4 {
			let tx_t = tx_pis[tx_base + TX_DATA_OFFSET + 4 + k];
			let ac_t = ac_pis[LEAF_OFFSET + s * 4 + k];
			let diff = builder.sub(tx_t, ac_t);
			let gated = builder.mul(is_real, diff);
			constraints.push(gated);
		}
	}
	batch_assert_zero(builder, &constraints, &ac_pis[..LEAF_OFFSET]);
}

/// Wire NC tree PIs to TX PIs: conditional positional equality gated by `is_real`.
///
/// Same pattern as [`wire_ac_to_tx`] but for note commitments (8 notes × 4 fields
/// per slot).
///
/// **Caller must** call `builder.assert_bool(is_real)` for each slot separately.
fn wire_nc_to_tx(
	builder: &mut CircuitBuilder<F, D>,
	nc_pis: &[Target],
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
				let tx_nc = tx_pis[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
				let leaf_idx = s * notes_per_slot + j;
				let tree_nc = nc_pis[LEAF_OFFSET + leaf_idx * 4 + k];
				let diff = builder.sub(tx_nc, tree_nc);
				let gated = builder.mul(is_real, diff);
				constraints.push(gated);
			}
		}
	}
	batch_assert_zero(builder, &constraints, &nc_pis[..LEAF_OFFSET]);
}

/// Wire AN tree PIs to TX PIs: multi-set equality (permutation argument).
///
/// Collects 4-field hashes from TX (account nullifiers) and AN tree leaves,
/// then asserts multi-set equality via a GF(p²) product argument.
fn wire_an_to_tx(
	builder: &mut CircuitBuilder<F, D>,
	an_pis: &[Target],
	tx_pis: &[Target],
	n_tx_slots: usize,
) {
	let mut tx_hashes = Vec::with_capacity(n_tx_slots);
	let mut tree_hashes = Vec::with_capacity(n_tx_slots);
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		tx_hashes.push(HashOutTarget {
			elements: core::array::from_fn(|k| tx_pis[tx_base + TX_DATA_OFFSET + k]),
		});
		tree_hashes.push(HashOutTarget {
			elements: core::array::from_fn(|k| an_pis[LEAF_OFFSET + s * 4 + k]),
		});
	}
	let fiat_shamir: Vec<Target> = an_pis[..8]
		.iter()
		.chain(tx_pis[..8].iter())
		.copied()
		.collect();
	assert_multiset_eq(builder, &tx_hashes, &tree_hashes, &fiat_shamir);
}

/// Wire NN tree PIs to TX PIs: multi-set equality (permutation argument).
///
/// Same pattern as [`wire_an_to_tx`] but for note nullifiers (8 notes per slot).
fn wire_nn_to_tx(
	builder: &mut CircuitBuilder<F, D>,
	nn_pis: &[Target],
	tx_pis: &[Target],
	n_tx_slots: usize,
	notes_per_slot: usize,
) {
	let mut tx_hashes = Vec::with_capacity(n_tx_slots * notes_per_slot);
	let mut tree_hashes = Vec::with_capacity(n_tx_slots * notes_per_slot);
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		for j in 0..notes_per_slot {
			tx_hashes.push(HashOutTarget {
				elements: core::array::from_fn(|k| {
					tx_pis[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k]
				}),
			});
			let leaf_idx = s * notes_per_slot + j;
			tree_hashes.push(HashOutTarget {
				elements: core::array::from_fn(|k| nn_pis[LEAF_OFFSET + leaf_idx * 4 + k]),
			});
		}
	}
	let fiat_shamir: Vec<Target> = nn_pis[..8]
		.iter()
		.chain(tx_pis[..8].iter())
		.copied()
		.collect();
	assert_multiset_eq(builder, &tx_hashes, &tree_hashes, &fiat_shamir);
}

// ---------------------------------------------------------------------------
// Internal circuit builder
// ---------------------------------------------------------------------------

/// Sets up the circuit builder with all wires for the SuperAggregator.
///
/// Performs all wire-allocation operations in a fixed, deterministic order.
/// Called by both [`SuperAggregator::build`] (which then calls `builder.build()`)
/// and [`SuperAggregator::from_artifacts`] (which discards the builder after
/// extracting target wire indices).
fn setup_builder(
	inner: &SuperAggregatorCircuitData,
) -> (CircuitBuilder<F, D>, SuperAggregatorTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// --- Proof targets and constant verifier data for each inner circuit ---
	let nc_proof = builder.add_virtual_proof_with_pis(&inner.nc_common);
	let nc_vd = builder.constant_verifier_data(&inner.nc_verifier);
	let nn_proof = builder.add_virtual_proof_with_pis(&inner.nn_common);
	let nn_vd = builder.constant_verifier_data(&inner.nn_verifier);
	let ac_proof = builder.add_virtual_proof_with_pis(&inner.ac_common);
	let ac_vd = builder.constant_verifier_data(&inner.ac_verifier);
	let an_proof = builder.add_virtual_proof_with_pis(&inner.an_common);
	let an_vd = builder.constant_verifier_data(&inner.an_verifier);
	let tx_proof = builder.add_virtual_proof_with_pis(&inner.tx_common);
	let tx_vd = builder.constant_verifier_data(&inner.tx_verifier);

	// --- Derive batch sizes from inner circuit data ---
	let tx_total_pi = inner.tx_common.num_public_inputs;
	assert_eq!(
		tx_total_pi % TX_LEAF_PI_SIZE,
		0,
		"TX root PI count must be a multiple of TX_LEAF_PI_SIZE (77)"
	);
	let n_tx_slots = tx_total_pi / TX_LEAF_PI_SIZE;

	// note_batch_size = NC PI count / 4 - 2 (subtract 2 roots × 4 fields each)
	let note_batch_size = inner.nc_common.num_public_inputs / 4 - 2;
	let notes_per_slot = note_batch_size / n_tx_slots;
	assert_eq!(notes_per_slot, 8, "notes per TX slot must be 8");

	// NN uses batch insertion: same PI layout as NC (old_root[4] + new_root[4] + leaves[N×4])
	assert_eq!(
		inner.nn_common.num_public_inputs, inner.nc_common.num_public_inputs,
		"NN and NC must have the same PI count with batch insertion"
	);

	// account_batch_size = AC PI count / 4 - 2; must equal n_tx_slots
	let account_batch_size = inner.ac_common.num_public_inputs / 4 - 2;
	assert_eq!(
		account_batch_size, n_tx_slots,
		"account_batch_size must equal n_tx_slots"
	);

	// AN uses batch insertion: same PI layout as AC
	assert_eq!(
		inner.an_common.num_public_inputs, inner.ac_common.num_public_inputs,
		"AN and AC must have the same PI count with batch insertion"
	);

	// --- Verify all 5 inner proofs in-circuit ---
	builder.verify_proof::<ConfigNative>(&nc_proof, &nc_vd, &inner.nc_common);
	builder.verify_proof::<ConfigNative>(&nn_proof, &nn_vd, &inner.nn_common);
	builder.verify_proof::<ConfigNative>(&ac_proof, &ac_vd, &inner.ac_common);
	builder.verify_proof::<ConfigNative>(&an_proof, &an_vd, &inner.an_common);
	builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);

	// --- Cross-check: TX slot PIs must match the corresponding tree leaf PIs ---

	// Assert is_real is boolean for each TX slot.
	for s in 0..n_tx_slots {
		let is_real =
			BoolTarget::new_unsafe(tx_proof.public_inputs[s * TX_LEAF_PI_SIZE + IS_REAL_OFFSET]);
		builder.assert_bool(is_real);
	}

	// Positional equality (conditional on is_real):
	wire_ac_to_tx(
		&mut builder,
		&ac_proof.public_inputs,
		&tx_proof.public_inputs,
		n_tx_slots,
	);

	wire_nc_to_tx(
		&mut builder,
		&nc_proof.public_inputs,
		&tx_proof.public_inputs,
		n_tx_slots,
		notes_per_slot,
	);

	// Multi-set equality (unconditional permutation argument):
	wire_an_to_tx(
		&mut builder,
		&an_proof.public_inputs,
		&tx_proof.public_inputs,
		n_tx_slots,
	);

	wire_nn_to_tx(
		&mut builder,
		&nn_proof.public_inputs,
		&tx_proof.public_inputs,
		n_tx_slots,
		notes_per_slot,
	);

	// --- Collect tree PI targets and decompose each to [hi_u32, lo_u32] ---
	//
	// TX PIs are enforced in-circuit above; only the 4 tree PI vectors are
	// included in the Keccak preimage.
	// The decomposition matches `keccak256_field_elements_native`: each
	// Goldilocks field element is split big-endian into two u32 words so that
	// the on-chain Keccak input is identical to the in-circuit preimage.
	let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);

	// Keccak preimage layout (must match on-chain registerTransactionBatchUpdate formula):
	//   per tree: old_root[4] || new_root[4] || full_batch[batch_size×4]
	//
	// All four trees (NC, NN, AC, AN) use the same PI layout — straight concatenation.
	let all_pi: Vec<_> = nc_proof
		.public_inputs
		.iter()
		.copied()
		.chain(nn_proof.public_inputs.iter().copied())
		.chain(ac_proof.public_inputs.iter().copied())
		.chain(an_proof.public_inputs.iter().copied())
		.collect();

	let mut u32_targets = Vec::with_capacity(all_pi.len() * 2);
	for &pi in &all_pi {
		let [hi, lo] = decompose_field_to_u32_pair(&mut builder, pi, byte_range_lut);
		u32_targets.push(hi.0);
		u32_targets.push(lo.0);
	}

	// --- Keccak-256 over all u32 words → 8 output words ---
	let hash = builder.keccak256::<ConfigNative>(&u32_targets);
	for &word in &hash {
		builder.register_public_input(word);
	}

	let targets = SuperAggregatorTargets {
		nc_proof,
		nc_vd,
		nn_proof,
		nn_vd,
		ac_proof,
		ac_vd,
		an_proof,
		an_vd,
		tx_proof,
		tx_vd,
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
// Off-circuit PI validation (public — usable by prover at runtime)
// ---------------------------------------------------------------------------

/// Validate AC mapping off-circuit: for each real TX slot, the AC fields in
/// the TX aggregated proof must match the corresponding tree leaf.
///
/// Returns an error describing the first mismatch found.
pub fn validate_ac_offcircuit(ac_pis: &[F], tx_pis: &[F], n_tx_slots: usize) -> Result<()> {
	use plonky2::field::types::{Field, PrimeField64};
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
		if is_real == F::ONE {
			for k in 0..4 {
				let tx_v = tx_pis[tx_base + TX_DATA_OFFSET + 4 + k];
				let ac_v = ac_pis[LEAF_OFFSET + s * 4 + k];
				if tx_v != ac_v {
					return Err(anyhow!(
						"AC off-circuit mismatch: slot {s} field {k}: \
						 tx={} tree={} (is_real={})",
						tx_v.to_canonical_u64(),
						ac_v.to_canonical_u64(),
						is_real.to_canonical_u64()
					));
				}
			}
		}
	}
	Ok(())
}

/// Validate NC mapping off-circuit: for each real TX slot, NC note fields
/// must match the corresponding tree leaves.
pub fn validate_nc_offcircuit(
	nc_pis: &[F],
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
					let tx_v =
						tx_pis[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
					let leaf_idx = s * notes_per_slot + j;
					let nc_v = nc_pis[LEAF_OFFSET + leaf_idx * 4 + k];
					if tx_v != nc_v {
						return Err(anyhow!(
							"NC off-circuit mismatch: slot {s} note {j} field {k}: tx={} tree={}",
							tx_v.to_canonical_u64(),
							nc_v.to_canonical_u64()
						));
					}
				}
			}
		}
	}
	Ok(())
}

/// Validate AN mapping off-circuit: TX AN hashes and tree AN leaves must
/// form the same multi-set (order-independent).
pub fn validate_an_offcircuit(an_pis: &[F], tx_pis: &[F], n_tx_slots: usize) -> Result<()> {
	use plonky2::field::types::PrimeField64;
	let mut tx_hashes: Vec<[u64; 4]> = Vec::new();
	let mut tree_hashes: Vec<[u64; 4]> = Vec::new();
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		tx_hashes.push(core::array::from_fn(|k| {
			tx_pis[tx_base + TX_DATA_OFFSET + k].to_canonical_u64()
		}));
		tree_hashes.push(core::array::from_fn(|k| {
			an_pis[LEAF_OFFSET + s * 4 + k].to_canonical_u64()
		}));
	}
	tx_hashes.sort();
	tree_hashes.sort();
	if tx_hashes != tree_hashes {
		// Find first differing index for diagnostics.
		for (i, (t, r)) in tx_hashes.iter().zip(tree_hashes.iter()).enumerate() {
			if t != r {
				return Err(anyhow!(
					"AN off-circuit multiset mismatch at sorted index {i}: tx={t:?} tree={r:?}"
				));
			}
		}
	}
	Ok(())
}

/// Validate NN mapping off-circuit: TX NN hashes and tree NN leaves must
/// form the same multi-set (order-independent).
pub fn validate_nn_offcircuit(
	nn_pis: &[F],
	tx_pis: &[F],
	n_tx_slots: usize,
	notes_per_slot: usize,
) -> Result<()> {
	use plonky2::field::types::PrimeField64;
	let mut tx_hashes: Vec<[u64; 4]> = Vec::new();
	let mut tree_hashes: Vec<[u64; 4]> = Vec::new();
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		for j in 0..notes_per_slot {
			tx_hashes.push(core::array::from_fn(|k| {
				tx_pis[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k].to_canonical_u64()
			}));
			let leaf_idx = s * notes_per_slot + j;
			tree_hashes.push(core::array::from_fn(|k| {
				nn_pis[LEAF_OFFSET + leaf_idx * 4 + k].to_canonical_u64()
			}));
		}
	}
	tx_hashes.sort();
	tree_hashes.sort();
	if tx_hashes != tree_hashes {
		for (i, (t, r)) in tx_hashes.iter().zip(tree_hashes.iter()).enumerate() {
			if t != r {
				return Err(anyhow!(
					"NN off-circuit multiset mismatch at sorted index {i}: tx={t:?} tree={r:?}"
				));
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
		field::types::Field,
		iop::{
			target::Target,
			witness::{PartialWitness, WitnessWrite},
		},
		plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	};

	use super::*;
	use crate::{ConfigNative, D, F};

	/// Builds a minimal leaf circuit with `n_pi` field-element public inputs.
	fn build_leaf(n_pi: usize) -> (CircuitDataNative, Vec<Target>) {
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

	/// Proves a leaf circuit with all-zero witness values.
	fn prove_zeros(cd: &CircuitDataNative, targets: &[Target]) -> ProofNative {
		let mut pw = PartialWitness::new();
		for &t in targets {
			pw.set_target(t, F::ZERO).unwrap();
		}
		cd.prove(pw).unwrap()
	}

	/// Proves a leaf circuit with explicit per-PI u64 values.
	fn prove_with_values(
		cd: &CircuitDataNative,
		targets: &[Target],
		values: &[u64],
	) -> ProofNative {
		assert_eq!(targets.len(), values.len());
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(values.iter()) {
			pw.set_target(t, F::from_canonical_u64(v)).unwrap();
		}
		cd.prove(pw).unwrap()
	}

	/// Build all 5 leaf circuits and return them together with per-PI counts.
	fn build_all_leaves(
		n_tx_slots: usize,
		notes_per_slot: usize,
	) -> (
		(CircuitDataNative, Vec<Target>), // nc
		(CircuitDataNative, Vec<Target>), // nn
		(CircuitDataNative, Vec<Target>), // ac
		(CircuitDataNative, Vec<Target>), // an
		(CircuitDataNative, Vec<Target>), // tx (77 PIs per slot: 75 explicit + 2 lookup metadata)
	) {
		let note_batch_size = notes_per_slot * n_tx_slots;
		let account_batch_size = n_tx_slots;
		let nc = build_leaf((2 + note_batch_size) * 4);
		let nn = build_leaf((2 + note_batch_size) * 4);
		let ac = build_leaf((2 + account_batch_size) * 4);
		let an = build_leaf((2 + account_batch_size) * 4);
		let tx = build_leaf(n_tx_slots * 77);
		(nc, nn, ac, an, tx)
	}

	fn make_super_agg(
		nc_cd: &CircuitDataNative,
		nn_cd: &CircuitDataNative,
		ac_cd: &CircuitDataNative,
		an_cd: &CircuitDataNative,
		tx_cd: &CircuitDataNative,
	) -> SuperAggregator {
		let inner = SuperAggregatorCircuitData {
			nc_common: nc_cd.common.clone(),
			nc_verifier: nc_cd.verifier_only.clone(),
			nn_common: nn_cd.common.clone(),
			nn_verifier: nn_cd.verifier_only.clone(),
			ac_common: ac_cd.common.clone(),
			ac_verifier: ac_cd.verifier_only.clone(),
			an_common: an_cd.common.clone(),
			an_verifier: an_cd.verifier_only.clone(),
			tx_common: tx_cd.common.clone(),
			tx_verifier: tx_cd.verifier_only.clone(),
		};
		SuperAggregator::build(inner).expect("build failed")
	}

	// n_tx_slots=2, notes_per_slot=8 used in all tests for speed.
	const N_TX_SLOTS: usize = 2;
	const NOTES_PER_SLOT: usize = 8;

	#[test]
	fn test_dummy_tx_pis_match_tree_padding() {
		// All slots are padding (is_real=0). TX PIs must match tree leaves
		// (prover aligns dummy proof PIs to tree padding values).
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		// NC leaf PIs: roots zero, leaves non-zero (42).
		let nc_n_pi = nc_t.len();
		let mut nc_vals = vec![0u64; nc_n_pi];
		for i in LEAF_OFFSET..nc_n_pi {
			nc_vals[i] = 42;
		}
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX: is_real=0 for all slots, NC data set to 42 (matching tree padding).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Fill NC fields for all slots to match tree leaves (42).
		for s in 0..N_TX_SLOTS {
			let tx_base = s * 77;
			for j in 0..NOTES_PER_SLOT {
				for k in 0..4 {
					tx_vals[tx_base + 3 + 40 + j * 4 + k] = 42; // TX_DATA_OFFSET + 40
				}
			}
		}
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("dummy-tx-aligned prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_full_private_tx_is_real_all_true() {
		// Full private TX: TX PIs must match tree leaves exactly.
		// is_real=1 for all slots → circuit enforces tx_data == tree_t.
		// All tree values zero, TX data zero, is_real=1 → expected=0==0 ✓.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX: is_real=1 for all slots (PI[s*77+2]=1), all data zero.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		for s in 0..N_TX_SLOTS {
			tx_vals[s * 77 + 2] = 1; // is_real=true for slot s
		}
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("full-tx prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_partial_tx_mixed_is_real() {
		// Partial batch: slot 0 is_real=1, slot 1 is_real=0.
		// All tree values zero; TX data zero → constraints trivially satisfied.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// Slot 0: is_real=1 (PI[2]=1), slot 1: is_real=0 (PI[77]=0). Data all zero.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // slot 0 is_real=1
		// slot 1 is_real=0 (already 0)
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("partial-tx prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_soundness_an_mismatch_should_fail() {
		// TX AN[0] ≠ tree AN → multi-set check fails (regardless of is_real).
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: AN[0] = 99 ≠ tree's 0 → multi-set mismatch → fails.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[3] = 99; // account_nullifier[0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (AN multi-set mismatch)"
		);
	}

	#[test]
	fn test_is_real_false_nonzero_matching_tx_data_should_pass() {
		// is_real=0 for slot 0, TX data matches tree data (both non-zero) → pass.
		// Cross-check is conditional on is_real; matching data passes regardless.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NN leaf[0][0]=99.
		let mut nn_vals = vec![0u64; nn_t.len()];
		nn_vals[8] = 99; // LEAF_OFFSET + 0
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, note_nullifier[0][0]=99 (matches NN).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// tx_vals[2] = 0; // is_real=false
		tx_vals[11] = 99; // note_nullifier[0][0] matches NN (TX_DATA_OFFSET + 8)
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("is_real=false with matching data should pass");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_soundness_nc_mismatch_is_real_should_fail() {
		// TX NC[0][0] ≠ tree NC[0][0] with is_real=1 → conditional connect fails.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NC leaf 0 word 0 = 7.
		let mut nc_vals = vec![0u64; nc_t.len()];
		nc_vals[8] = 7;
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);

		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1, NC[0][0] = 999 ≠ tree's 7 → connect fails.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		tx_vals[43] = 999; // note_commitment[0][0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (NC positional mismatch with is_real=1)"
		);
	}

	// -----------------------------------------------------------------------
	// Non-trivial (non-zero value) pass tests
	// -----------------------------------------------------------------------
	//
	// TX leaf PI layout per slot (tx_base = s × 77):
	//   PI[tx_base + 0..2]           = plonky2 LUT metadata (auto-registered)
	//   PI[tx_base + 2]              = subpool_id_in
	//   PI[tx_base + 3]              = subpool_id_out
	//   PI[tx_base + 4]              = is_real  (IS_REAL_OFFSET)
	//   PI[tx_base + 5 + k]          = account_nullifier[k]   (AN, TX_DATA_OFFSET)
	//   PI[tx_base + 9 + k]          = account_commitment[k]  (AC)
	//   PI[tx_base + 13 + j*4 + k]   = note_nullifier[j][k]   (NN)
	//   PI[tx_base + 45 + j*4 + k]   = note_commitment[j][k]  (NC)
	//
	// All four trees share the same PI layout: old_root[4] + new_root[4] + values[batch_size × 4]
	// LEAF_OFFSET = 8 for all trees (NC, NN, AC, AN).
	//
	// Tree offsets (N_TX_SLOTS=2, NOTES_PER_SLOT=8, note_batch_size=16, account_batch_size=2):
	//   NC/NN: build_leaf(72) → leaves at PI[8 + leaf_idx*4]
	//   AC/AN: build_leaf(16) → leaves at PI[8 + s*4]

	#[test]
	fn test_full_tx_nonzero_values_match() {
		// Full TX batch (both slots real) with non-trivial matching values across
		// all four fields (note_nullifier, note_commitment, account_nullifier,
		// account_commitment).  Verifies that is_real=1 enforcement actually
		// propagates non-zero tree values into TX constraints.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		// Slot 0 tree values (word 0 of each field only; rest stay zero).
		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		// Slot 0, note 0, word 0:
		nn_vals[LEAF_OFFSET] = 101; // NN: LEAF_OFFSET + (0*8+0)*4 + 0
		nc_vals[LEAF_OFFSET] = 201; // NC: LEAF_OFFSET + (0*8+0)*4 + 0
		// Slot 0, account, word 0:
		an_vals[LEAF_OFFSET] = 301; // AN: LEAF_OFFSET + 0*4 + 0
		ac_vals[LEAF_OFFSET] = 401; // AC: LEAF_OFFSET + 0*4 + 0
		// Slot 1, note 0, word 0:
		nn_vals[LEAF_OFFSET + 8 * 4] = 102; // NN: 8 + (1*8+0)*4 = 40
		nc_vals[LEAF_OFFSET + 8 * 4] = 202; // NC: 8 + (1*8+0)*4 = 40
		// Slot 1, account, word 0:
		an_vals[LEAF_OFFSET + 1 * 4] = 302; // AN: 8 + 1*4 = 12
		ac_vals[LEAF_OFFSET + 1 * 4] = 402; // AC: 8 + 1*4 = 12

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		// TX: both slots real with data matching the tree leaves above.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Slot 0 (tx_base = 0):
		tx_vals[2] = 1; // is_real
		tx_vals[3] = 301; // account_nullifier[0]
		tx_vals[7] = 401; // account_commitment[0]
		tx_vals[11] = 101; // note_nullifier[0][0]
		tx_vals[43] = 201; // note_commitment[0][0]
		// Slot 1 (tx_base = 77):
		tx_vals[77 + 2] = 1; // is_real
		tx_vals[77 + 3] = 302; // account_nullifier[0]
		tx_vals[77 + 7] = 402; // account_commitment[0]
		tx_vals[77 + 11] = 102; // note_nullifier[0][0]
		tx_vals[77 + 43] = 202; // note_commitment[0][0]

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("full-tx nonzero prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_partial_tx_with_dummy_slot_aligned_to_tree() {
		// Slot 0 is_real=1 with matching non-zero values; slot 1 is_real=0
		// (dummy) with TX PIs aligned to tree padding (non-zero NC leaf).
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		// Slot 0 (active): matching values in all four fields.
		nn_vals[LEAF_OFFSET] = 101;
		nc_vals[LEAF_OFFSET] = 201;
		an_vals[LEAF_OFFSET] = 301;
		ac_vals[LEAF_OFFSET] = 401;
		// Slot 1 (padding): non-zero NC leaf (e.g. consume request).
		nc_vals[LEAF_OFFSET + 8 * 4] = 999;

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Slot 0 (tx_base=0): is_real=1, data matches tree.
		tx_vals[2] = 1;
		tx_vals[3] = 301;
		tx_vals[7] = 401;
		tx_vals[11] = 101;
		tx_vals[43] = 201;
		// Slot 1 (tx_base=77): is_real=0, dummy TX PIs aligned to tree padding.
		// NC slot 1 note 0 word 0 = 999 (matches tree).
		tx_vals[77 + 43] = 999;

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("partial-tx with aligned dummy prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	// -----------------------------------------------------------------------
	// Additional soundness tests
	// -----------------------------------------------------------------------

	#[test]
	fn test_soundness_non_boolean_is_real_should_fail() {
		// TX slot 0: is_real=2 (not 0 or 1) → assert_bool constraint fails.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 2; // is_real=2: not boolean
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (non-boolean is_real)"
		);
	}

	#[test]
	fn test_soundness_nn_mismatch_should_fail() {
		// TX NN[0][0] ≠ tree NN[0][0] → multi-set check fails.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NN leaf slot 0, note 0, word 0 = 55.
		let mut nn_vals = vec![0u64; nn_t.len()];
		nn_vals[8] = 55;
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: NN[0][0] = 0 ≠ tree's 55 → multi-set mismatch.
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (NN multi-set mismatch)"
		);
	}

	#[test]
	fn test_soundness_ac_mismatch_is_real_should_fail() {
		// TX AC[0] ≠ tree AC[0] with is_real=1 → conditional connect fails.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let mut ac_vals = vec![0u64; ac_t.len()];
		ac_vals[8] = 77;
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1, AC[0] = 0 ≠ tree's 77 → connect fails.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (AC positional mismatch with is_real=1)"
		);
	}

	// -----------------------------------------------------------------------
	// Conditional connect (AC/NC gated by is_real) tests
	// -----------------------------------------------------------------------

	#[test]
	fn test_nc_mismatch_is_real_false_should_pass() {
		// TX NC ≠ tree NC but is_real=0 → conditional connect is skipped → passes.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let mut nc_vals = vec![0u64; nc_t.len()];
		nc_vals[8] = 7; // NC leaf 0 word 0 = 7
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, NC[0][0] = 999 ≠ tree's 7 → skipped.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[43] = 999; // note_commitment[0][0] mismatches tree
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("NC mismatch with is_real=0 should pass");
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_ac_mismatch_is_real_false_should_pass() {
		// TX AC ≠ tree AC but is_real=0 → conditional connect is skipped → passes.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let mut ac_vals = vec![0u64; ac_t.len()];
		ac_vals[8] = 77; // AC leaf 0 word 0 = 77
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, AC[0] = 0 ≠ tree's 77 → skipped.
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("AC mismatch with is_real=0 should pass");
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_dummy_slot_unaligned_nc_ac_passes() {
		// Slot 0 is_real=1 with matching values; slot 1 is_real=0 with
		// completely different NC/AC values from tree → passes because
		// conditional connect is skipped for dummy slots.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		// Slot 0 (active): matching values.
		nn_vals[LEAF_OFFSET] = 101;
		nc_vals[LEAF_OFFSET] = 201;
		an_vals[LEAF_OFFSET] = 301;
		ac_vals[LEAF_OFFSET] = 401;
		// Slot 1 (dummy): tree has non-zero NC and AC values.
		nc_vals[LEAF_OFFSET + 8 * 4] = 999;
		ac_vals[LEAF_OFFSET + 1 * 4] = 888;

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Slot 0 (tx_base=0): is_real=1, data matches tree.
		tx_vals[2] = 1;
		tx_vals[3] = 301; // AN
		tx_vals[7] = 401; // AC
		tx_vals[11] = 101; // NN
		tx_vals[43] = 201; // NC
		// Slot 1 (tx_base=77): is_real=0, TX NC/AC are zeros (unaligned with tree's 999/888).
		// AN/NN are also zero (matching tree zeros → multi-set OK).

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("dummy slot unaligned NC/AC should pass");
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_soundness_an_mismatch_is_real_false_still_fails() {
		// AN uses ungated multi-set equality → mismatch fails even with is_real=0.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, AN[0] = 99 ≠ tree's 0 → multi-set fails.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[3] = 99; // account_nullifier[0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"AN mismatch should fail even with is_real=0 (ungated multi-set)"
		);
	}

	#[test]
	fn test_soundness_nn_mismatch_is_real_false_still_fails() {
		// NN uses ungated multi-set equality → mismatch fails even with is_real=0.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let mut nn_vals = vec![0u64; nn_t.len()];
		nn_vals[8] = 55; // NN leaf slot 0, note 0, word 0 = 55
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, NN[0][0] = 0 ≠ tree's 55 → multi-set fails.
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"NN mismatch should fail even with is_real=0 (ungated multi-set)"
		);
	}

	// -----------------------------------------------------------------------
	// Standalone multi-set equality gadget tests
	// -----------------------------------------------------------------------

	/// Build a tiny circuit that only runs `assert_multiset_eq` on two sets of
	/// 4-field hashes with deterministic Fiat-Shamir inputs.
	fn multiset_eq_circuit(set_a_vals: &[[u64; 4]], set_b_vals: &[[u64; 4]]) -> Result<(), String> {
		let n = set_a_vals.len();
		assert_eq!(n, set_b_vals.len());
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

		let mut a_targets = Vec::with_capacity(n);
		let mut b_targets = Vec::with_capacity(n);
		let mut fs_targets = Vec::new();

		for _ in 0..n {
			let a = HashOutTarget {
				elements: core::array::from_fn(|_| builder.add_virtual_target()),
			};
			let b = HashOutTarget {
				elements: core::array::from_fn(|_| builder.add_virtual_target()),
			};
			// Use set_b values as Fiat-Shamir inputs (simulates tree PIs).
			fs_targets.extend_from_slice(&b.elements);
			a_targets.push(a);
			b_targets.push(b);
		}

		assert_multiset_eq(&mut builder, &a_targets, &b_targets, &fs_targets);
		let data = builder.build::<ConfigNative>();

		let mut pw = PartialWitness::new();
		for (i, (a, b)) in a_targets.iter().zip(b_targets.iter()).enumerate() {
			for k in 0..4 {
				pw.set_target(a.elements[k], F::from_canonical_u64(set_a_vals[i][k]))
					.unwrap();
				pw.set_target(b.elements[k], F::from_canonical_u64(set_b_vals[i][k]))
					.unwrap();
			}
		}

		data.prove(pw)
			.map(|proof| {
				data.verify(proof).expect("verify failed");
			})
			.map_err(|e| format!("{e}"))
	}

	#[test]
	fn test_multiset_eq_identical_sets() {
		// Same elements in same order → trivially passes.
		let set = [[1, 2, 3, 4], [5, 6, 7, 8], [0, 0, 0, 0]];
		multiset_eq_circuit(&set, &set).expect("identical sets should pass");
	}

	#[test]
	fn test_multiset_eq_permuted_sets() {
		// Same elements in different order → multi-set equality passes.
		let a = [[10, 20, 30, 40], [50, 60, 70, 80], [1, 1, 1, 1]];
		let b = [[1, 1, 1, 1], [10, 20, 30, 40], [50, 60, 70, 80]];
		multiset_eq_circuit(&a, &b).expect("permuted sets should pass");
	}

	#[test]
	fn test_multiset_eq_all_zeros_pass() {
		// All-zero sets → products are β^n on both sides → passes.
		let set = [[0, 0, 0, 0], [0, 0, 0, 0]];
		multiset_eq_circuit(&set, &set).expect("all-zero identical sets should pass");
	}

	#[test]
	fn test_multiset_eq_mismatch_should_fail() {
		// Different sets → products differ → fails.
		let a = [[1, 0, 0, 0], [0, 0, 0, 0]];
		let b = [[2, 0, 0, 0], [0, 0, 0, 0]];
		assert!(
			multiset_eq_circuit(&a, &b).is_err(),
			"mismatched sets should fail"
		);
	}

	#[test]
	fn test_multiset_eq_zero_vs_nonzero_should_fail() {
		// One set all-zero, other has a non-zero element → fails.
		let a = [[99, 0, 0, 0], [0, 0, 0, 0]];
		let b = [[0, 0, 0, 0], [0, 0, 0, 0]];
		assert!(
			multiset_eq_circuit(&a, &b).is_err(),
			"zero vs non-zero should fail"
		);
	}

	// -----------------------------------------------------------------------
	// Multi-set equality in SuperAggregator context (permuted AN/NN)
	// -----------------------------------------------------------------------

	#[test]
	fn test_permuted_an_should_pass() {
		// AN values are swapped between TX slots and tree positions → multi-set
		// equality passes because {[5,0,0,0],[3,0,0,0]} == {[3,0,0,0],[5,0,0,0]}.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		// Tree AN: slot 0 = [3,0,0,0], slot 1 = [5,0,0,0] (sorted order).
		let mut an_vals = vec![0u64; an_t.len()];
		an_vals[LEAF_OFFSET] = 3;
		an_vals[LEAF_OFFSET + 4] = 5;
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);

		// TX: slot 0 AN = [5,0,0,0], slot 1 AN = [3,0,0,0] (reversed order).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[3] = 5; // slot 0 AN[0]
		tx_vals[77 + 3] = 3; // slot 1 AN[0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("permuted AN should pass (multi-set equality)");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_permuted_nn_should_pass() {
		// NN values permuted between TX and tree → multi-set equality passes.
		// TX slot 0 NN[0] = [7,0,0,0], slot 1 NN[0] = [3,0,0,0]
		// Tree NN:  leaf 0 = [3,0,0,0], leaf 8 = [7,0,0,0] (sorted)
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		const LEAF_OFFSET: usize = 8;

		// Tree NN: leaf 0 (slot 0 note 0) = [3,...], leaf 8 (slot 1 note 0) = [7,...]
		let mut nn_vals = vec![0u64; nn_t.len()];
		nn_vals[LEAF_OFFSET] = 3; // leaf 0, word 0
		nn_vals[LEAF_OFFSET + 8 * 4] = 7; // leaf 8, word 0
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX: slot 0 NN[0] = [7,...], slot 1 NN[0] = [3,...] (swapped vs tree).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[11] = 7; // slot 0, note_nullifier[0][0]
		tx_vals[77 + 11] = 3; // slot 1, note_nullifier[0][0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("permuted NN should pass (multi-set equality)");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	// -----------------------------------------------------------------------
	// Minimal reproduction: connect_extension on two mul_extension chains
	// -----------------------------------------------------------------------

	/// Two independent mul_extension chains with identical inputs.
	/// Products are mathematically equal. Uses connect_extension (the old
	/// buggy pattern) to assert equality.
	///
	/// If this test passes, connect_extension is NOT the root cause of the
	/// SuperAggregator "set twice" panic.
	#[test]
	fn test_repro_connect_extension_same_inputs() {
		use plonky2::field::extension::{Extendable, FieldExtension};

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		// N fingerprints — use enough elements to match the SA scale.
		const N: usize = 16;

		// Shared inputs: N extension targets.
		let inputs: Vec<_> = (0..N)
			.map(|_| builder.add_virtual_extension_target())
			.collect();

		// Two chains multiplying the SAME inputs in the SAME order.
		let one = builder.one_extension();
		let mut prod_a = one;
		let mut prod_b = one;
		for i in 0..N {
			prod_a = builder.mul_extension(prod_a, inputs[i]);
			prod_b = builder.mul_extension(prod_b, inputs[i]);
		}

		// Old pattern: connect the two chain outputs directly.
		builder.connect_extension(prod_a, prod_b);

		// Register one product as PI so the circuit isn't trivially empty.
		for i in 0..D {
			builder.register_public_input(prod_a.0[i]);
		}

		let data = builder.build::<ConfigNative>();

		// Witness: set all inputs to small nonzero values.
		let mut pw = PartialWitness::new();
		for (idx, &ext) in inputs.iter().enumerate() {
			let v0 = F::from_canonical_u64(idx as u64 + 2);
			let v1 = F::from_canonical_u64(idx as u64 + 100);
			pw.set_extension_target(
				ext,
				<F as Extendable<D>>::Extension::from_basefield_array([v0, v1]),
			)
			.unwrap();
		}

		let proof = data
			.prove(pw)
			.expect("connect_extension same-input chains should pass");
		data.verify(proof).expect("verify failed");
	}

	/// Same as above but the two chains multiply DIFFERENT inputs.
	/// Products differ → connect_extension should reject.
	#[test]
	fn test_repro_connect_extension_different_inputs_should_fail() {
		use plonky2::field::extension::{Extendable, FieldExtension};

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		const N: usize = 4;

		let inputs_a: Vec<_> = (0..N)
			.map(|_| builder.add_virtual_extension_target())
			.collect();
		let inputs_b: Vec<_> = (0..N)
			.map(|_| builder.add_virtual_extension_target())
			.collect();

		let one = builder.one_extension();
		let mut prod_a = one;
		let mut prod_b = one;
		for i in 0..N {
			prod_a = builder.mul_extension(prod_a, inputs_a[i]);
			prod_b = builder.mul_extension(prod_b, inputs_b[i]);
		}

		builder.connect_extension(prod_a, prod_b);

		for i in 0..D {
			builder.register_public_input(prod_a.0[i]);
		}

		let data = builder.build::<ConfigNative>();

		// Set different values for the two input sets.
		let mut pw = PartialWitness::new();
		for (idx, &ext) in inputs_a.iter().enumerate() {
			let v0 = F::from_canonical_u64(idx as u64 + 2);
			let v1 = F::from_canonical_u64(idx as u64 + 100);
			pw.set_extension_target(
				ext,
				<F as Extendable<D>>::Extension::from_basefield_array([v0, v1]),
			)
			.unwrap();
		}
		for (idx, &ext) in inputs_b.iter().enumerate() {
			let v0 = F::from_canonical_u64(idx as u64 + 999);
			let v1 = F::from_canonical_u64(idx as u64 + 5000);
			pw.set_extension_target(
				ext,
				<F as Extendable<D>>::Extension::from_basefield_array([v0, v1]),
			)
			.unwrap();
		}

		let result = data.prove(pw);
		assert!(
			result.is_err(),
			"connect_extension with different products should fail"
		);
	}

	/// Same chain structure as the SA's assert_multiset_eq: Poseidon-derived
	/// challenges, fingerprint computation, product accumulation.
	/// Uses connect_extension on the final products.
	#[test]
	fn test_repro_multiset_connect_extension() {
		use plonky2::hash::hash_types::HashOutTarget;

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		const N: usize = 16;

		// Two identical sets of 4-field hashes.
		let set: Vec<HashOutTarget> = (0..N)
			.map(|_| HashOutTarget {
				elements: core::array::from_fn(|_| builder.add_virtual_target()),
			})
			.collect();

		// Fiat-Shamir inputs (just use the first hash).
		let fs_inputs: Vec<Target> = set[0].elements.to_vec();

		// Derive challenges.
		let gamma_hash =
			builder.hash_n_to_hash_no_pad::<plonky2::hash::poseidon::PoseidonHash>(fs_inputs);
		let gamma = ExtensionTarget::<D>([gamma_hash.elements[0], gamma_hash.elements[1]]);
		let beta = ExtensionTarget::<D>([gamma_hash.elements[2], gamma_hash.elements[3]]);

		// Compute product of fingerprints TWICE (same set).
		let one = builder.one_extension();
		let mut prod_a = one;
		let mut prod_b = one;
		for h in &set {
			let fp = hash_fingerprint(&mut builder, h, gamma, beta);
			prod_a = builder.mul_extension(prod_a, fp);
			prod_b = builder.mul_extension(prod_b, fp);
		}

		// Old pattern: connect_extension on the two products.
		builder.connect_extension(prod_a, prod_b);

		for i in 0..D {
			builder.register_public_input(prod_a.0[i]);
		}

		let data = builder.build::<ConfigNative>();

		let mut pw = PartialWitness::new();
		for h in &set {
			for (k, &t) in h.elements.iter().enumerate() {
				pw.set_target(t, F::from_canonical_u64(k as u64 + 7))
					.unwrap();
			}
		}

		let proof = data
			.prove(pw)
			.expect("multiset connect_extension same set should pass");
		data.verify(proof).expect("verify failed");
	}

	// -----------------------------------------------------------------------
	// Off-circuit PI mapping validation
	// -----------------------------------------------------------------------

	/// Validate AC mapping off-circuit: for each real slot, TX AC fields must
	/// match tree AC leaves at the expected PI indices.
	fn validate_ac_offcircuit(ac_pis: &[F], tx_pis: &[F], n_tx_slots: usize) {
		for s in 0..n_tx_slots {
			let tx_base = s * TX_LEAF_PI_SIZE;
			let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
			if is_real == F::ONE {
				for k in 0..4 {
					let tx_v = tx_pis[tx_base + TX_DATA_OFFSET + 4 + k];
					let ac_v = ac_pis[LEAF_OFFSET + s * 4 + k];
					assert_eq!(tx_v, ac_v, "AC off-circuit mismatch: slot {s} field {k}");
				}
			}
		}
	}

	/// Validate NC mapping off-circuit: for each real slot, TX NC fields must
	/// match tree NC leaves at the expected PI indices.
	fn validate_nc_offcircuit(
		nc_pis: &[F],
		tx_pis: &[F],
		n_tx_slots: usize,
		notes_per_slot: usize,
	) {
		for s in 0..n_tx_slots {
			let tx_base = s * TX_LEAF_PI_SIZE;
			let is_real = tx_pis[tx_base + IS_REAL_OFFSET];
			if is_real == F::ONE {
				for j in 0..notes_per_slot {
					for k in 0..4 {
						let tx_v =
							tx_pis[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
						let leaf_idx = s * notes_per_slot + j;
						let nc_v = nc_pis[LEAF_OFFSET + leaf_idx * 4 + k];
						assert_eq!(
							tx_v, nc_v,
							"NC off-circuit mismatch: slot {s} note {j} field {k}"
						);
					}
				}
			}
		}
	}

	/// Validate AN mapping off-circuit: TX AN hashes and tree AN leaves must
	/// form the same multi-set (order-independent).
	fn validate_an_offcircuit(an_pis: &[F], tx_pis: &[F], n_tx_slots: usize) {
		use plonky2::field::types::PrimeField64;
		let mut tx_hashes: Vec<[u64; 4]> = Vec::new();
		let mut tree_hashes: Vec<[u64; 4]> = Vec::new();
		for s in 0..n_tx_slots {
			let tx_base = s * TX_LEAF_PI_SIZE;
			tx_hashes.push(core::array::from_fn(|k| {
				tx_pis[tx_base + TX_DATA_OFFSET + k].to_canonical_u64()
			}));
			tree_hashes.push(core::array::from_fn(|k| {
				an_pis[LEAF_OFFSET + s * 4 + k].to_canonical_u64()
			}));
		}
		tx_hashes.sort();
		tree_hashes.sort();
		assert_eq!(tx_hashes, tree_hashes, "AN off-circuit multiset mismatch");
	}

	/// Validate NN mapping off-circuit: TX NN hashes and tree NN leaves must
	/// form the same multi-set (order-independent).
	fn validate_nn_offcircuit(
		nn_pis: &[F],
		tx_pis: &[F],
		n_tx_slots: usize,
		notes_per_slot: usize,
	) {
		use plonky2::field::types::PrimeField64;
		let mut tx_hashes: Vec<[u64; 4]> = Vec::new();
		let mut tree_hashes: Vec<[u64; 4]> = Vec::new();
		for s in 0..n_tx_slots {
			let tx_base = s * TX_LEAF_PI_SIZE;
			for j in 0..notes_per_slot {
				tx_hashes.push(core::array::from_fn(|k| {
					tx_pis[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k].to_canonical_u64()
				}));
				let leaf_idx = s * notes_per_slot + j;
				tree_hashes.push(core::array::from_fn(|k| {
					nn_pis[LEAF_OFFSET + leaf_idx * 4 + k].to_canonical_u64()
				}));
			}
		}
		tx_hashes.sort();
		tree_hashes.sort();
		assert_eq!(tx_hashes, tree_hashes, "NN off-circuit multiset mismatch");
	}

	// -----------------------------------------------------------------------
	// Off-circuit validation tests
	// -----------------------------------------------------------------------

	#[test]
	fn test_offcircuit_ac_mapping() {
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (ac_cd, ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		let mut ac_vals = vec![0u64; ac_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Slot 0: is_real=1, AC = [10,20,30,40]
		tx_vals[2] = 1;
		for k in 0..4 {
			let v = (k as u64 + 1) * 10;
			tx_vals[TX_DATA_OFFSET + 4 + k] = v;
			ac_vals[LEAF_OFFSET + k] = v;
		}
		// Slot 1: is_real=0 (dummy, mismatch OK)
		tx_vals[TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 4] = 999;
		// Slot 2: is_real=1, AC = [50,60,70,80]
		tx_vals[2 * TX_LEAF_PI_SIZE + IS_REAL_OFFSET] = 1;
		for k in 0..4 {
			let v = (k as u64 + 5) * 10;
			tx_vals[2 * TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 4 + k] = v;
			ac_vals[LEAF_OFFSET + 2 * 4 + k] = v;
		}
		// Slot 3: is_real=0

		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
		validate_ac_offcircuit(&ac_proof.public_inputs, &tx_proof.public_inputs, n);
	}

	#[test]
	fn test_offcircuit_nc_mapping() {
		let n = 2;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Slot 0: is_real=1, NC note 0 = [1,2,3,4]
		tx_vals[2] = 1;
		for k in 0..4 {
			let v = k as u64 + 1;
			tx_vals[TX_DATA_OFFSET + 8 + nps * 4 + k] = v;
			nc_vals[LEAF_OFFSET + k] = v;
		}

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
		validate_nc_offcircuit(&nc_proof.public_inputs, &tx_proof.public_inputs, n, nps);
	}

	#[test]
	fn test_offcircuit_an_mapping() {
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		let mut an_vals = vec![0u64; an_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Tree AN: slots [0..3] = [10,0,0,0], [20,0,0,0], [30,0,0,0], [40,0,0,0]
		// TX AN:   slots [0..3] = [30,0,0,0], [10,0,0,0], [40,0,0,0], [20,0,0,0] (permuted)
		let tree_order = [10u64, 20, 30, 40];
		let tx_order = [30u64, 10, 40, 20];
		for s in 0..n {
			an_vals[LEAF_OFFSET + s * 4] = tree_order[s];
			tx_vals[s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET] = tx_order[s];
		}

		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
		validate_an_offcircuit(&an_proof.public_inputs, &tx_proof.public_inputs, n);
	}

	#[test]
	fn test_offcircuit_nn_mapping() {
		let n = 2;
		let nps = NOTES_PER_SLOT;
		let ((_nc_cd, _nc_t), (nn_cd, nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Tree NN leaf 0 (slot 0 note 0) = [5,0,0,0]
		// TX NN slot 0 note 0 = [5,0,0,0]
		nn_vals[LEAF_OFFSET] = 5;
		tx_vals[TX_DATA_OFFSET + 8] = 5;
		// Tree NN leaf 8 (slot 1 note 0) = [9,0,0,0]
		// TX NN slot 1 note 0 = [9,0,0,0]
		nn_vals[LEAF_OFFSET + nps * 4] = 9;
		tx_vals[TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 8] = 9;

		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
		validate_nn_offcircuit(&nn_proof.public_inputs, &tx_proof.public_inputs, n, nps);
	}

	// -----------------------------------------------------------------------
	// Standalone in-circuit gadget tests (with verify_proof)
	// -----------------------------------------------------------------------
	//
	// Each test builds a circuit that:
	//   1. verify_proof(tree_proof) + verify_proof(tx_proof)
	//   2. assert_bool(is_real) for each TX slot
	//   3. Applies ONE gadget
	//   4. Proves and verifies
	//
	// This isolates each gadget in an environment similar to the SA (recursive
	// proof verification) but without the other gadgets, decompose, or Keccak.

	/// Helper: build a standalone circuit that verifies tree + TX proofs and
	/// applies the given gadget.
	/// Build, prove and verify a circuit that replicates the real SA environment
	/// for a single gadget: verify_proof(tree) + verify_proof(tx) + gadget +
	/// decompose_field_to_u32_pair on ALL tree PIs (the interaction with
	/// decompose is what triggers wire-partition conflicts in the full SA).
	fn standalone_gadget_test<G>(
		tree_cd: &CircuitDataNative,
		tree_proof: &ProofNative,
		tx_cd: &CircuitDataNative,
		tx_proof: &ProofNative,
		n_tx_slots: usize,
		gadget: G,
	) where
		G: FnOnce(&mut CircuitBuilder<F, D>, &[Target], &[Target]),
	{
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

		let tree_pt = builder.add_virtual_proof_with_pis(&tree_cd.common);
		let tree_vd = builder.constant_verifier_data(&tree_cd.verifier_only);
		builder.verify_proof::<ConfigNative>(&tree_pt, &tree_vd, &tree_cd.common);

		let tx_pt = builder.add_virtual_proof_with_pis(&tx_cd.common);
		let tx_vd = builder.constant_verifier_data(&tx_cd.verifier_only);
		builder.verify_proof::<ConfigNative>(&tx_pt, &tx_vd, &tx_cd.common);

		// Assert is_real is boolean.
		for s in 0..n_tx_slots {
			let is_real =
				BoolTarget::new_unsafe(tx_pt.public_inputs[s * TX_LEAF_PI_SIZE + IS_REAL_OFFSET]);
			builder.assert_bool(is_real);
		}

		gadget(&mut builder, &tree_pt.public_inputs, &tx_pt.public_inputs);

		// --- Replicate the real SA: decompose ALL tree PIs to u32 pairs ---
		// This is the operation that causes wire-partition conflicts because
		// decompose_field_to_u32_pair calls connect(recomposed, pi_target),
		// merging ArithmeticGate outputs into tree PI target partitions.
		let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);
		for &pi in &tree_pt.public_inputs {
			let [hi, lo] = decompose_field_to_u32_pair(&mut builder, pi, byte_range_lut);
			// Register u32 outputs as PIs so the decompose isn't optimised away.
			builder.register_public_input(hi.0);
			builder.register_public_input(lo.0);
		}

		let data = builder.build::<ConfigNative>();

		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&tree_vd, &tree_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&tree_pt, tree_proof).unwrap();
		pw.set_verifier_data_target(&tx_vd, &tx_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&tx_pt, tx_proof).unwrap();

		let proof = data.prove(pw).expect("standalone gadget prove failed");
		data.verify(proof).expect("standalone gadget verify failed");
	}

	#[test]
	fn test_wire_ac_standalone_all_dummy() {
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (ac_cd, ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		// All dummy: is_real=0 for all slots, all zeros.
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		// Off-circuit validation first.
		validate_ac_offcircuit(&ac_proof.public_inputs, &tx_proof.public_inputs, n);

		standalone_gadget_test(&ac_cd, &ac_proof, &tx_cd, &tx_proof, n, |b, ac, tx| {
			wire_ac_to_tx(b, ac, tx, n);
		});
	}

	#[test]
	fn test_wire_ac_standalone_mixed() {
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (ac_cd, ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		let mut ac_vals = vec![0u64; ac_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Slot 0: is_real=1, matching AC = [10,20,30,40]
		tx_vals[2] = 1;
		for k in 0..4 {
			let v = (k as u64 + 1) * 10;
			tx_vals[TX_DATA_OFFSET + 4 + k] = v;
			ac_vals[LEAF_OFFSET + k] = v;
		}
		// Slots 1-3: is_real=0 (dummy)

		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_ac_offcircuit(&ac_proof.public_inputs, &tx_proof.public_inputs, n);

		standalone_gadget_test(&ac_cd, &ac_proof, &tx_cd, &tx_proof, n, |b, ac, tx| {
			wire_ac_to_tx(b, ac, tx, n);
		});
	}

	#[test]
	fn test_wire_nc_standalone_all_dummy() {
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		validate_nc_offcircuit(&nc_proof.public_inputs, &tx_proof.public_inputs, n, nps);

		standalone_gadget_test(&nc_cd, &nc_proof, &tx_cd, &tx_proof, n, |b, nc, tx| {
			wire_nc_to_tx(b, nc, tx, n, nps);
		});
	}

	#[test]
	fn test_wire_nc_standalone_mixed() {
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];

		// Slot 0: is_real=1, NC note 0 = [1,2,3,4]
		tx_vals[2] = 1;
		for j in 0..nps {
			for k in 0..4 {
				let v = (j * 4 + k) as u64 + 1;
				tx_vals[TX_DATA_OFFSET + 8 + nps * 4 + j * 4 + k] = v;
				nc_vals[LEAF_OFFSET + j * 4 + k] = v;
			}
		}
		// Slots 1-3: is_real=0

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_nc_offcircuit(&nc_proof.public_inputs, &tx_proof.public_inputs, n, nps);

		standalone_gadget_test(&nc_cd, &nc_proof, &tx_cd, &tx_proof, n, |b, nc, tx| {
			wire_nc_to_tx(b, nc, tx, n, nps);
		});
	}

	/// Helper: build a full 4-field AN hash from a seed. All 4 fields are
	/// non-zero and distinct so the multiset check exercises all components.
	fn an_hash(seed: u64) -> [u64; 4] {
		[seed, seed + 1000, seed + 2000, seed + 3000]
	}

	/// Helper: build a full 4-field NN hash from a seed.
	fn nn_hash(seed: u64) -> [u64; 4] {
		[seed, seed + 100, seed + 200, seed + 300]
	}

	/// Write a 4-field hash into an AN/NN tree PI vector at the given slot.
	fn set_tree_hash(vals: &mut [u64], slot: usize, hash: [u64; 4]) {
		for k in 0..4 {
			vals[LEAF_OFFSET + slot * 4 + k] = hash[k];
		}
	}

	/// Write a 4-field AN hash into the TX PI vector at the given slot.
	fn set_tx_an_hash(vals: &mut [u64], slot: usize, hash: [u64; 4]) {
		let tx_base = slot * TX_LEAF_PI_SIZE;
		for k in 0..4 {
			vals[tx_base + TX_DATA_OFFSET + k] = hash[k];
		}
	}

	/// Write a 4-field NN hash into the TX PI vector at the given slot and note.
	fn set_tx_nn_hash(vals: &mut [u64], slot: usize, note: usize, hash: [u64; 4]) {
		let tx_base = slot * TX_LEAF_PI_SIZE;
		for k in 0..4 {
			vals[tx_base + TX_DATA_OFFSET + 8 + note * 4 + k] = hash[k];
		}
	}

	/// Write a 4-field NN hash into an NN tree PI vector at the given flat leaf index.
	fn set_tree_nn_hash(vals: &mut [u64], leaf_idx: usize, hash: [u64; 4]) {
		for k in 0..4 {
			vals[LEAF_OFFSET + leaf_idx * 4 + k] = hash[k];
		}
	}

	#[test]
	fn test_wire_an_standalone_sorted_tree() {
		// Simulates real AN behaviour:
		// - Tree: 4 account-nullifier hashes in sorted order (batch insertion output)
		// - TX: same 4 hashes in unsorted transaction order
		// All 4 fields of each hash are non-zero.
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		// 4 distinct hashes, sorted by field-0 (simulating tree sorted order).
		let hashes = [an_hash(10), an_hash(20), an_hash(50), an_hash(90)];

		// Tree: sorted order [10, 20, 50, 90]
		let mut an_vals = vec![0u64; an_t.len()];
		for (s, &h) in hashes.iter().enumerate() {
			set_tree_hash(&mut an_vals, s, h);
		}

		// TX: unsorted transaction order [50, 10, 90, 20]
		let tx_perm = [2usize, 0, 3, 1];
		let mut tx_vals = vec![0u64; tx_t.len()];
		for (s, &src) in tx_perm.iter().enumerate() {
			set_tx_an_hash(&mut tx_vals, s, hashes[src]);
		}

		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_an_offcircuit(&an_proof.public_inputs, &tx_proof.public_inputs, n);

		standalone_gadget_test(&an_cd, &an_proof, &tx_cd, &tx_proof, n, |b, an, tx| {
			wire_an_to_tx(b, an, tx, n);
		});
	}

	#[test]
	fn test_wire_an_standalone_all_same_hash() {
		// Edge case: all 4 slots have the same hash (duplicate nullifiers).
		// Multiset should accept {A,A,A,A} == {A,A,A,A}.
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		let h = an_hash(42);
		let mut an_vals = vec![0u64; an_t.len()];
		let mut tx_vals = vec![0u64; tx_t.len()];
		for s in 0..n {
			set_tree_hash(&mut an_vals, s, h);
			set_tx_an_hash(&mut tx_vals, s, h);
		}

		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_an_offcircuit(&an_proof.public_inputs, &tx_proof.public_inputs, n);

		standalone_gadget_test(&an_cd, &an_proof, &tx_cd, &tx_proof, n, |b, an, tx| {
			wire_an_to_tx(b, an, tx, n);
		});
	}

	#[test]
	fn test_wire_nn_standalone_sorted_tree() {
		// Simulates real NN behaviour:
		// - Tree: 4 slots × 8 notes = 32 note-nullifier hashes in sorted order
		// - TX: same 32 hashes in unsorted transaction order
		// (Uses n=4 slots, 8 notes/slot. Only a few non-zero to keep it tractable.)
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let total_notes = n * nps; // 32
		let ((_nc_cd, _nc_t), (nn_cd, nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		// Generate 32 distinct hashes, sorted by seed (tree order).
		let sorted_hashes: Vec<[u64; 4]> = (0..total_notes)
			.map(|i| nn_hash((i as u64 + 1) * 5))
			.collect();

		// Tree: flat sorted order (leaf 0 = smallest, leaf 31 = largest).
		let mut nn_vals = vec![0u64; nn_t.len()];
		for (leaf_idx, &h) in sorted_hashes.iter().enumerate() {
			set_tree_nn_hash(&mut nn_vals, leaf_idx, h);
		}

		// TX: unsorted. Reverse within each slot to simulate transaction order
		// differing from sorted tree order.
		// Slot s gets tree leaves [s*8+7, s*8+6, ..., s*8+0] (reversed).
		let mut tx_vals = vec![0u64; tx_t.len()];
		for s in 0..n {
			for j in 0..nps {
				let tree_leaf_idx = s * nps + (nps - 1 - j); // reversed
				set_tx_nn_hash(&mut tx_vals, s, j, sorted_hashes[tree_leaf_idx]);
			}
		}

		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_nn_offcircuit(&nn_proof.public_inputs, &tx_proof.public_inputs, n, nps);

		standalone_gadget_test(&nn_cd, &nn_proof, &tx_cd, &tx_proof, n, |b, nn, tx| {
			wire_nn_to_tx(b, nn, tx, n, nps);
		});
	}

	#[test]
	fn test_wire_nn_standalone_cross_slot_permutation() {
		// Notes are shuffled ACROSS slots (not just within), simulating the
		// tree sorting notes from different TXs into a global sorted order.
		let n = 2;
		let nps = NOTES_PER_SLOT;
		let total_notes = n * nps; // 16
		let ((_nc_cd, _nc_t), (nn_cd, nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		// 16 distinct hashes.
		let hashes: Vec<[u64; 4]> = (0..total_notes)
			.map(|i| nn_hash((i as u64 + 1) * 7))
			.collect();

		// Tree: sorted order (ascending by seed).
		let mut nn_vals = vec![0u64; nn_t.len()];
		for (leaf_idx, &h) in hashes.iter().enumerate() {
			set_tree_nn_hash(&mut nn_vals, leaf_idx, h);
		}

		// TX: interleave — slot 0 gets even-indexed hashes, slot 1 gets odd-indexed.
		// This simulates two TXs whose notes interleave in the sorted tree.
		let mut tx_vals = vec![0u64; tx_t.len()];
		for j in 0..nps {
			set_tx_nn_hash(&mut tx_vals, 0, j, hashes[j * 2]); // even
			set_tx_nn_hash(&mut tx_vals, 1, j, hashes[j * 2 + 1]); // odd
		}

		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		validate_nn_offcircuit(&nn_proof.public_inputs, &tx_proof.public_inputs, n, nps);

		standalone_gadget_test(&nn_cd, &nn_proof, &tx_cd, &tx_proof, n, |b, nn, tx| {
			wire_nn_to_tx(b, nn, tx, n, nps);
		});
	}

	// -----------------------------------------------------------------------
	// Standalone gadget tests with random real/dummy patterns
	// -----------------------------------------------------------------------

	/// Helper: populate AC tree and TX values for a given real/dummy pattern.
	/// Real slots get matching non-zero AC values; dummy slots get mismatched
	/// values (to confirm the conditional gate actually skips them).
	fn populate_ac_random_pattern(ac_vals: &mut [u64], tx_vals: &mut [u64], is_real: &[bool]) {
		for (s, &real) in is_real.iter().enumerate() {
			let tx_base = s * TX_LEAF_PI_SIZE;
			if real {
				tx_vals[tx_base + IS_REAL_OFFSET] = 1;
				for k in 0..4 {
					let v = (s as u64 * 100) + k as u64 + 1;
					tx_vals[tx_base + TX_DATA_OFFSET + 4 + k] = v;
					ac_vals[LEAF_OFFSET + s * 4 + k] = v;
				}
			} else {
				// is_real=0, deliberately mismatch TX vs tree.
				tx_vals[tx_base + IS_REAL_OFFSET] = 0;
				tx_vals[tx_base + TX_DATA_OFFSET + 4] = 9999;
				ac_vals[LEAF_OFFSET + s * 4] = 1111;
			}
		}
	}

	/// Helper: populate NC tree and TX values for a given real/dummy pattern.
	fn populate_nc_random_pattern(
		nc_vals: &mut [u64],
		tx_vals: &mut [u64],
		is_real: &[bool],
		notes_per_slot: usize,
	) {
		for (s, &real) in is_real.iter().enumerate() {
			let tx_base = s * TX_LEAF_PI_SIZE;
			if real {
				tx_vals[tx_base + IS_REAL_OFFSET] = 1;
				for j in 0..notes_per_slot {
					for k in 0..4 {
						let v = (s as u64 * 1000) + (j as u64 * 10) + k as u64 + 1;
						tx_vals[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k] = v;
						let leaf_idx = s * notes_per_slot + j;
						nc_vals[LEAF_OFFSET + leaf_idx * 4 + k] = v;
					}
				}
			} else {
				tx_vals[tx_base + IS_REAL_OFFSET] = 0;
				// Mismatch on purpose (skipped by is_real=0).
				tx_vals[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4] = 7777;
				let leaf_idx = s * notes_per_slot;
				nc_vals[LEAF_OFFSET + leaf_idx * 4] = 3333;
			}
		}
	}

	#[test]
	fn test_wire_ac_standalone_random_patterns() {
		let n = 4;
		let ((_nc_cd, _nc_t), (_nn_cd, _nn_t), (ac_cd, ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, NOTES_PER_SLOT);

		// Test several patterns: all-real, alternating, only-last, only-middle.
		let patterns: &[&[bool]] = &[
			&[true, true, true, true],
			&[true, false, true, false],
			&[false, true, false, true],
			&[false, false, false, true],
			&[false, true, true, false],
		];

		for pattern in patterns {
			let mut ac_vals = vec![0u64; ac_t.len()];
			let mut tx_vals = vec![0u64; tx_t.len()];
			populate_ac_random_pattern(&mut ac_vals, &mut tx_vals, pattern);

			let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
			let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
			validate_ac_offcircuit(&ac_proof.public_inputs, &tx_proof.public_inputs, n);

			standalone_gadget_test(&ac_cd, &ac_proof, &tx_cd, &tx_proof, n, |b, ac, tx| {
				wire_ac_to_tx(b, ac, tx, n);
			});
		}
	}

	#[test]
	fn test_wire_nc_standalone_random_patterns() {
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (_nn_cd, _nn_t), (_ac_cd, _ac_t), (_an_cd, _an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let patterns: &[&[bool]] = &[
			&[true, true, true, true],
			&[true, false, true, false],
			&[false, true, false, true],
			&[false, false, false, true],
			&[false, true, true, false],
		];

		for pattern in patterns {
			let mut nc_vals = vec![0u64; nc_t.len()];
			let mut tx_vals = vec![0u64; tx_t.len()];
			populate_nc_random_pattern(&mut nc_vals, &mut tx_vals, pattern, nps);

			let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
			let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
			validate_nc_offcircuit(&nc_proof.public_inputs, &tx_proof.public_inputs, n, nps);

			standalone_gadget_test(&nc_cd, &nc_proof, &tx_cd, &tx_proof, n, |b, nc, tx| {
				wire_nc_to_tx(b, nc, tx, n, nps);
			});
		}
	}

	// -----------------------------------------------------------------------
	// Combined gadget tests — all 4 gadgets together (replicates full SA env)
	// -----------------------------------------------------------------------

	/// Build a circuit with all 5 inner proof verifications, all 4 cross-check
	/// gadgets, and decompose_field_to_u32_pair on all 4 tree PI vectors.
	/// This replicates the full SuperAggregator environment EXCEPT Keccak.
	#[test]
	fn test_combined_all_gadgets_no_keccak() {
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		// All dummy (zeros) — matches test_pipeline_4tx_all_dummy.
		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

		// 1. Add proof targets + verifier data for all 5 proofs.
		let nc_pt = builder.add_virtual_proof_with_pis(&nc_cd.common);
		let nc_vd = builder.constant_verifier_data(&nc_cd.verifier_only);
		let nn_pt = builder.add_virtual_proof_with_pis(&nn_cd.common);
		let nn_vd = builder.constant_verifier_data(&nn_cd.verifier_only);
		let ac_pt = builder.add_virtual_proof_with_pis(&ac_cd.common);
		let ac_vd = builder.constant_verifier_data(&ac_cd.verifier_only);
		let an_pt = builder.add_virtual_proof_with_pis(&an_cd.common);
		let an_vd = builder.constant_verifier_data(&an_cd.verifier_only);
		let tx_pt = builder.add_virtual_proof_with_pis(&tx_cd.common);
		let tx_vd = builder.constant_verifier_data(&tx_cd.verifier_only);

		// 2. Verify all 5 proofs.
		builder.verify_proof::<ConfigNative>(&nc_pt, &nc_vd, &nc_cd.common);
		builder.verify_proof::<ConfigNative>(&nn_pt, &nn_vd, &nn_cd.common);
		builder.verify_proof::<ConfigNative>(&ac_pt, &ac_vd, &ac_cd.common);
		builder.verify_proof::<ConfigNative>(&an_pt, &an_vd, &an_cd.common);
		builder.verify_proof::<ConfigNative>(&tx_pt, &tx_vd, &tx_cd.common);

		// 3. Assert is_real is boolean.
		for s in 0..n {
			let is_real =
				BoolTarget::new_unsafe(tx_pt.public_inputs[s * TX_LEAF_PI_SIZE + IS_REAL_OFFSET]);
			builder.assert_bool(is_real);
		}

		// 4. All 4 cross-check gadgets.
		wire_ac_to_tx(&mut builder, &ac_pt.public_inputs, &tx_pt.public_inputs, n);
		wire_nc_to_tx(
			&mut builder,
			&nc_pt.public_inputs,
			&tx_pt.public_inputs,
			n,
			nps,
		);
		wire_an_to_tx(&mut builder, &an_pt.public_inputs, &tx_pt.public_inputs, n);
		wire_nn_to_tx(
			&mut builder,
			&nn_pt.public_inputs,
			&tx_pt.public_inputs,
			n,
			nps,
		);

		// 5. Decompose ALL 4 tree PI vectors to u32 pairs (same as real SA).
		let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);
		let all_tree_pis: Vec<Target> = nc_pt
			.public_inputs
			.iter()
			.chain(nn_pt.public_inputs.iter())
			.chain(ac_pt.public_inputs.iter())
			.chain(an_pt.public_inputs.iter())
			.copied()
			.collect();

		for &pi in &all_tree_pis {
			let [hi, lo] = decompose_field_to_u32_pair(&mut builder, pi, byte_range_lut);
			builder.register_public_input(hi.0);
			builder.register_public_input(lo.0);
		}

		let data = builder.build::<ConfigNative>();

		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&nc_vd, &nc_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&nc_pt, &nc_proof).unwrap();
		pw.set_verifier_data_target(&nn_vd, &nn_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&nn_pt, &nn_proof).unwrap();
		pw.set_verifier_data_target(&ac_vd, &ac_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&ac_pt, &ac_proof).unwrap();
		pw.set_verifier_data_target(&an_vd, &an_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&an_pt, &an_proof).unwrap();
		pw.set_verifier_data_target(&tx_vd, &tx_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&tx_pt, &tx_proof).unwrap();

		let proof = data
			.prove(pw)
			.expect("combined all-gadgets (no keccak) prove failed");
		data.verify(proof)
			.expect("combined all-gadgets (no keccak) verify failed");
	}

	/// Same as above but WITH Keccak-256 — matches the real SuperAggregator exactly.
	#[test]
	fn test_combined_all_gadgets_with_keccak() {
		let n = 4;
		let nps = NOTES_PER_SLOT;
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(n, nps);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

		let nc_pt = builder.add_virtual_proof_with_pis(&nc_cd.common);
		let nc_vd = builder.constant_verifier_data(&nc_cd.verifier_only);
		let nn_pt = builder.add_virtual_proof_with_pis(&nn_cd.common);
		let nn_vd = builder.constant_verifier_data(&nn_cd.verifier_only);
		let ac_pt = builder.add_virtual_proof_with_pis(&ac_cd.common);
		let ac_vd = builder.constant_verifier_data(&ac_cd.verifier_only);
		let an_pt = builder.add_virtual_proof_with_pis(&an_cd.common);
		let an_vd = builder.constant_verifier_data(&an_cd.verifier_only);
		let tx_pt = builder.add_virtual_proof_with_pis(&tx_cd.common);
		let tx_vd = builder.constant_verifier_data(&tx_cd.verifier_only);

		builder.verify_proof::<ConfigNative>(&nc_pt, &nc_vd, &nc_cd.common);
		builder.verify_proof::<ConfigNative>(&nn_pt, &nn_vd, &nn_cd.common);
		builder.verify_proof::<ConfigNative>(&ac_pt, &ac_vd, &ac_cd.common);
		builder.verify_proof::<ConfigNative>(&an_pt, &an_vd, &an_cd.common);
		builder.verify_proof::<ConfigNative>(&tx_pt, &tx_vd, &tx_cd.common);

		for s in 0..n {
			let is_real =
				BoolTarget::new_unsafe(tx_pt.public_inputs[s * TX_LEAF_PI_SIZE + IS_REAL_OFFSET]);
			builder.assert_bool(is_real);
		}

		wire_ac_to_tx(&mut builder, &ac_pt.public_inputs, &tx_pt.public_inputs, n);
		wire_nc_to_tx(
			&mut builder,
			&nc_pt.public_inputs,
			&tx_pt.public_inputs,
			n,
			nps,
		);
		wire_an_to_tx(&mut builder, &an_pt.public_inputs, &tx_pt.public_inputs, n);
		wire_nn_to_tx(
			&mut builder,
			&nn_pt.public_inputs,
			&tx_pt.public_inputs,
			n,
			nps,
		);

		// Decompose + Keccak (same as real SA).
		let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);
		let all_tree_pis: Vec<Target> = nc_pt
			.public_inputs
			.iter()
			.chain(nn_pt.public_inputs.iter())
			.chain(ac_pt.public_inputs.iter())
			.chain(an_pt.public_inputs.iter())
			.copied()
			.collect();

		let mut u32_targets = Vec::with_capacity(all_tree_pis.len() * 2);
		for &pi in &all_tree_pis {
			let [hi, lo] = decompose_field_to_u32_pair(&mut builder, pi, byte_range_lut);
			u32_targets.push(hi.0);
			u32_targets.push(lo.0);
		}

		let hash = builder.keccak256::<ConfigNative>(&u32_targets);
		for &word in &hash {
			builder.register_public_input(word);
		}

		let data = builder.build::<ConfigNative>();

		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&nc_vd, &nc_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&nc_pt, &nc_proof).unwrap();
		pw.set_verifier_data_target(&nn_vd, &nn_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&nn_pt, &nn_proof).unwrap();
		pw.set_verifier_data_target(&ac_vd, &ac_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&ac_pt, &ac_proof).unwrap();
		pw.set_verifier_data_target(&an_vd, &an_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&an_pt, &an_proof).unwrap();
		pw.set_verifier_data_target(&tx_vd, &tx_cd.verifier_only)
			.unwrap();
		pw.set_proof_with_pis_target(&tx_pt, &tx_proof).unwrap();

		let proof = data
			.prove(pw)
			.expect("combined all-gadgets WITH keccak prove failed");
		data.verify(proof)
			.expect("combined all-gadgets WITH keccak verify failed");
	}
}
