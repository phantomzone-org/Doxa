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
		pw.set_verifier_data_target(&self.targets.nc_vd, &self.inner.nc_verifier)?;
		pw.set_proof_with_pis_target(&self.targets.nc_proof, &nc)?;
		pw.set_verifier_data_target(&self.targets.nn_vd, &self.inner.nn_verifier)?;
		pw.set_proof_with_pis_target(&self.targets.nn_proof, &nn)?;
		pw.set_verifier_data_target(&self.targets.ac_vd, &self.inner.ac_verifier)?;
		pw.set_proof_with_pis_target(&self.targets.ac_proof, &ac)?;
		pw.set_verifier_data_target(&self.targets.an_vd, &self.inner.an_verifier)?;
		pw.set_proof_with_pis_target(&self.targets.an_proof, &an)?;
		pw.set_verifier_data_target(&self.targets.tx_vd, &self.inner.tx_verifier)?;
		pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("SuperAggregator::prove failed: {e}"))
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
	// n_tx_slots = TX root PI count / 77  (77 fields per TX leaf slot)
	// 75 explicit + 2 plonky2 lookup-table metadata PIs.
	const TX_LEAF_PI_SIZE: usize = 77;
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
	const LEAF_OFFSET: usize = 8;
	const TX_DATA_OFFSET: usize = 3;

	let mut tx_an_hashes = Vec::with_capacity(n_tx_slots);
	let mut tree_an_hashes = Vec::with_capacity(n_tx_slots);
	let mut tx_nn_hashes = Vec::with_capacity(n_tx_slots * notes_per_slot);
	let mut tree_nn_hashes = Vec::with_capacity(n_tx_slots * notes_per_slot);

	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;

		let is_real = BoolTarget::new_unsafe(tx_proof.public_inputs[tx_base + 2]);
		builder.assert_bool(is_real);

		// AN: collect 4-field hash from TX and tree for multi-set check.
		tx_an_hashes.push(HashOutTarget {
			elements: core::array::from_fn(|k| {
				tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + k]
			}),
		});
		tree_an_hashes.push(HashOutTarget {
			elements: core::array::from_fn(|k| an_proof.public_inputs[LEAF_OFFSET + s * 4 + k]),
		});

		// AC: conditional positional connect gated by is_real.
		// When is_real=1: val = tx_t → enforces tx_t == ac_t.
		// When is_real=0: val = ac_t → trivially ac_t == ac_t.
		for k in 0..4 {
			let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 4 + k];
			let ac_t = ac_proof.public_inputs[LEAF_OFFSET + s * 4 + k];
			let val = builder.select(is_real, tx_t, ac_t);
			builder.connect(val, ac_t);
		}

		// NN: collect 4-field hashes from TX and tree for multi-set check.
		for j in 0..notes_per_slot {
			tx_nn_hashes.push(HashOutTarget {
				elements: core::array::from_fn(|k| {
					tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k]
				}),
			});
			let leaf_idx = s * notes_per_slot + j;
			tree_nn_hashes.push(HashOutTarget {
				elements: core::array::from_fn(|k| {
					nn_proof.public_inputs[LEAF_OFFSET + leaf_idx * 4 + k]
				}),
			});
		}

		// NC: conditional positional connect gated by is_real (same select pattern as AC).
		for j in 0..notes_per_slot {
			for k in 0..4 {
				let tx_nc = tx_proof.public_inputs
					[tx_base + TX_DATA_OFFSET + 8 + notes_per_slot * 4 + j * 4 + k];
				let leaf_idx = s * notes_per_slot + j;
				let tree_nc = nc_proof.public_inputs[LEAF_OFFSET + leaf_idx * 4 + k];
				let val = builder.select(is_real, tx_nc, tree_nc);
				builder.connect(val, tree_nc);
			}
		}
	}

	// AN multi-set equality: TX account nullifiers must match tree AN leaves (order-independent).
	{
		let fiat_shamir_inputs: Vec<Target> = an_proof.public_inputs[..8]
			.iter()
			.chain(tx_proof.public_inputs[..8].iter())
			.copied()
			.collect();
		assert_multiset_eq(
			&mut builder,
			&tx_an_hashes,
			&tree_an_hashes,
			&fiat_shamir_inputs,
		);
	}

	// NN multi-set equality: TX note nullifiers must match tree NN leaves (order-independent).
	{
		let fiat_shamir_inputs: Vec<Target> = nn_proof.public_inputs[..8]
			.iter()
			.chain(tx_proof.public_inputs[..8].iter())
			.copied()
			.collect();
		assert_multiset_eq(
			&mut builder,
			&tx_nn_hashes,
			&tree_nn_hashes,
			&fiat_shamir_inputs,
		);
	}

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
	//   PI[tx_base + 0]              = subpool_id_in
	//   PI[tx_base + 1]              = subpool_id_out
	//   PI[tx_base + 2]              = is_real
	//   PI[tx_base + 3 + k]          = account_nullifier[k]   (AN)
	//   PI[tx_base + 7 + k]          = account_commitment[k]  (AC)
	//   PI[tx_base + 11 + j*4 + k]   = note_nullifier[j][k]   (NN)
	//   PI[tx_base + 43 + j*4 + k]   = note_commitment[j][k]  (NC)
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
	// Scale test: 128-TX slots (production size)
	// -----------------------------------------------------------------------

	/// 128-TX all-dummy: builds and proves the full production-size SA circuit.
	/// Prints timings for build and prove phases.
	#[test]
	#[ignore] // slow (~minutes); run explicitly with: cargo test -p tessera-trees --release test_scale_128tx -- --ignored --nocapture
	fn test_scale_128tx_all_dummy() {
		use std::time::Instant;

		const N_TX: usize = 128;
		const NOTES: usize = 8;

		println!("=== 128-TX scale test (all-dummy) ===");

		// 1. Build leaf circuits.
		let t0 = Instant::now();
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX, NOTES);
		println!("leaf circuits built in {:.2?}", t0.elapsed());

		// 2. Build SA circuit.
		let t1 = Instant::now();
		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		println!("SA circuit built in {:.2?}", t1.elapsed());
		println!(
			"  SA degree_bits = {:?}",
			super_agg.circuit_data.common.degree_bits()
		);

		// 3. Prove leaf proofs (all zeros = all-dummy).
		let t2 = Instant::now();
		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);
		let tx_proof = prove_zeros(&tx_cd, &tx_t);
		println!("leaf proofs generated in {:.2?}", t2.elapsed());

		// 4. Prove SA.
		let t3 = Instant::now();
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("128-TX all-dummy SA prove failed");
		println!("SA proof generated in {:.2?}", t3.elapsed());

		// 5. Verify.
		let t4 = Instant::now();
		assert_eq!(root.public_inputs.len(), 8);
		super_agg
			.circuit_data
			.verify(root)
			.expect("128-TX SA verify failed");
		println!("SA proof verified in {:.2?}", t4.elapsed());
		println!("=== total: {:.2?} ===", t0.elapsed());
	}

	/// 128-TX mixed: 64 real slots with non-zero matching data + 64 dummy slots.
	/// Exercises all cross-checks (AC, NC positional; AN, NN multi-set) at
	/// production scale with a realistic mix.
	#[test]
	#[ignore] // slow; run with: cargo test -p tessera-trees --release test_scale_128tx_mixed -- --ignored --nocapture
	fn test_scale_128tx_mixed_real_and_dummy() {
		use std::time::Instant;

		const N_TX: usize = 128;
		const NOTES: usize = 8;
		const LEAF_OFFSET: usize = 8;
		const N_REAL: usize = 64; // first 64 slots are real, rest are dummy

		println!(
			"=== 128-TX mixed test ({N_REAL} real + {} dummy) ===",
			N_TX - N_REAL
		);

		let t0 = Instant::now();
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX, NOTES);
		println!("leaf circuits built in {:.2?}", t0.elapsed());

		let t1 = Instant::now();
		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		println!("SA circuit built in {:.2?}", t1.elapsed());

		// --- Build tree leaf values ---
		// Each real slot s gets distinct non-zero values:
		//   AN[s] word 0 = 1000 + s
		//   AC[s] word 0 = 2000 + s
		//   NN[s][j] word 0 = 3000 + s*8 + j
		//   NC[s][j] word 0 = 4000 + s*8 + j
		// Dummy slots (s >= N_REAL) stay zero in all trees.
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];

		for s in 0..N_REAL {
			an_vals[LEAF_OFFSET + s * 4] = 1000 + s as u64;
			ac_vals[LEAF_OFFSET + s * 4] = 2000 + s as u64;
			for j in 0..NOTES {
				let leaf_idx = s * NOTES + j;
				nn_vals[LEAF_OFFSET + leaf_idx * 4] = 3000 + leaf_idx as u64;
				nc_vals[LEAF_OFFSET + leaf_idx * 4] = 4000 + leaf_idx as u64;
			}
		}

		let t2 = Instant::now();
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);

		// --- Build TX values ---
		// Real slots: is_real=1, data matches tree leaves.
		// Dummy slots: is_real=0, all zeros (matching zero tree leaves).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];

		for s in 0..N_REAL {
			let tx_base = s * 77;
			tx_vals[tx_base + 2] = 1; // is_real
			tx_vals[tx_base + 3] = 1000 + s as u64; // AN word 0
			tx_vals[tx_base + 7] = 2000 + s as u64; // AC word 0
			for j in 0..NOTES {
				let leaf_idx = s * NOTES + j;
				tx_vals[tx_base + 11 + j * 4] = 3000 + leaf_idx as u64; // NN[j] word 0
				tx_vals[tx_base + 43 + j * 4] = 4000 + leaf_idx as u64; // NC[j] word 0
			}
		}
		// Dummy slots (s >= N_REAL): is_real=0, all zeros — already zeroed.

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);
		println!("leaf proofs generated in {:.2?}", t2.elapsed());

		let t3 = Instant::now();
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("128-TX mixed SA prove failed");
		println!("SA proof generated in {:.2?}", t3.elapsed());

		let t4 = Instant::now();
		assert_eq!(root.public_inputs.len(), 8);
		super_agg
			.circuit_data
			.verify(root)
			.expect("128-TX mixed SA verify failed");
		println!("SA proof verified in {:.2?}", t4.elapsed());
		println!("=== total: {:.2?} ===", t0.elapsed());
	}
}
