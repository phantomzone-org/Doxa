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
//! TX PIs are enforced in-circuit to equal the corresponding tree leaf PIs and
//! are therefore excluded from the Keccak preimage.
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
	iop::{
		target::BoolTarget,
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
	/// in the TX proof's own public inputs (`is_real` at `PI[s * 75 + 2]` for slot `s`).
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
	// n_tx_slots = TX root PI count / 75  (75 fields per TX leaf slot)
	const TX_LEAF_PI_SIZE: usize = 75; // subpool_id_in(1) + subpool_id_out(1) + is_real(1) + data(72)
	let tx_total_pi = inner.tx_common.num_public_inputs;
	assert_eq!(
		tx_total_pi % TX_LEAF_PI_SIZE,
		0,
		"TX root PI count must be a multiple of TX_LEAF_PI_SIZE (75)"
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
	//
	// All four trees (NC/NN/AC/AN) share the same PI layout:
	//   public_inputs[0..8]  = [old_root × 4, new_root × 4]
	//   public_inputs[8..]   = leaves (batch_size × 4 fields)
	// TX leaf PI layout (75 fields per slot):
	//   [0]      = subpool_id_in
	//   [1]      = subpool_id_out
	//   [2]      = is_real (bool: 1 = real private tx, 0 = padding)
	//   [3..7]   = account_nullifier        (1 × 4 fields, from AN)
	//   [7..11]  = account_commitment       (1 × 4 fields, from AC)
	//   [11..43] = note_nullifiers[0..8]   (8 × 4 fields, from NN)
	//   [43..75] = note_commitments[0..8]  (8 × 4 fields, from NC)
	//
	// The cross-check is conditional on is_real:
	//   is_real * (tx_data - tree_leaf) == 0
	// Real slots (is_real=1): tx_data must equal tree_leaf.
	// Padding slots (is_real=0): no constraint (dummy TX PIs are unchecked).
	const LEAF_OFFSET: usize = 8; // old_root[4] + new_root[4]
	const TX_DATA_OFFSET: usize = 3; // PI[0..2] are subpool_ids + is_real; data starts at PI[3]
	let zero = builder.zero();
	#[allow(clippy::needless_range_loop)]
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		// Read is_real from TX root proof PI[tx_base + 2]; wrap and assert boolean.
		let is_real = BoolTarget::new_unsafe(tx_proof.public_inputs[tx_base + 2]);
		builder.assert_bool(is_real);
		// account nullifier (TX PI[3..7]) — from AN tree
		let an_val_base = LEAF_OFFSET + s * 4;
		for k in 0..4 {
			let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + k];
			let an_t = an_proof.public_inputs[an_val_base + k];
			let diff = builder.sub(tx_t, an_t);
			let gated = builder.mul(is_real.target, diff);
			builder.connect(gated, zero);
		}
		// account commitment (TX PI[7..11]) — from AC tree
		for k in 0..4 {
			let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 4 + k];
			let ac_t = ac_proof.public_inputs[LEAF_OFFSET + s * 4 + k];
			let diff = builder.sub(tx_t, ac_t);
			let gated = builder.mul(is_real.target, diff);
			builder.connect(gated, zero);
		}
		// note nullifiers (TX PI[11..43]) — from NN tree
		for j in 0..notes_per_slot {
			let leaf_idx = s * notes_per_slot + j;
			let nn_val_base = LEAF_OFFSET + leaf_idx * 4;
			for k in 0..4 {
				let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 8 + j * 4 + k];
				let nn_t = nn_proof.public_inputs[nn_val_base + k];
				let diff = builder.sub(tx_t, nn_t);
				let gated = builder.mul(is_real.target, diff);
				builder.connect(gated, zero);
			}
		}
		// note commitments (TX PI[43..75]) — from NC tree
		for j in 0..notes_per_slot {
			for k in 0..4 {
				let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 40 + j * 4 + k];
				let nc_t = nc_proof.public_inputs[LEAF_OFFSET + (s * notes_per_slot + j) * 4 + k];
				let diff = builder.sub(tx_t, nc_t);
				let gated = builder.mul(is_real.target, diff);
				builder.connect(gated, zero);
			}
		}
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
		(CircuitDataNative, Vec<Target>), /* tx (75 PIs per slot: subpool_ids(2) + is_real + 72
		                                   * data) */
	) {
		let note_batch_size = notes_per_slot * n_tx_slots;
		let account_batch_size = n_tx_slots;
		let nc = build_leaf((2 + note_batch_size) * 4);
		let nn = build_leaf((2 + note_batch_size) * 4);
		let ac = build_leaf((2 + account_batch_size) * 4);
		let an = build_leaf((2 + account_batch_size) * 4);
		let tx = build_leaf(n_tx_slots * 75);
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
	fn test_consume_only_is_real_all_false() {
		// Consume-only batch: all slots are padding (is_real=0).
		// Cross-check is conditional on is_real, so TX data is unconstrained.
		// Here TX data happens to be all-zero (doesn't match NC leaves) → still passes.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NC leaf PIs: roots zero, leaves non-zero (42). Leaves start at NC_LEAF_OFFSET=8.
		let nc_n_pi = nc_t.len();
		let mut nc_vals = vec![0u64; nc_n_pi];
		for i in 8..nc_n_pi {
			nc_vals[i] = 42;
		}
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);
		// TX: is_real=0 for all slots, data all-zero (doesn't match NC leaves=42).
		// Conditional cross-check: is_real=0 → no constraint → passes.
		let tx_proof = prove_zeros(&tx_cd, &tx_t);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("consume-only prove failed");

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

		// TX: is_real=1 for all slots (PI[s*75+2]=1), all data zero.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		for s in 0..N_TX_SLOTS {
			tx_vals[s * 75 + 2] = 1; // is_real=true for slot s
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
	fn test_soundness_tx_data_mismatch_tree_data_is_real_true_should_fail() {
		// TX data for slot 0 differs from tree data AND is_real=1 → conditional check fails.
		// Tree AN leaf[0][0]=0, TX account_nullifier[0]=99 → mismatch.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1, data[0] = 99 ≠ tree's 0 → conditional check enforced → fails.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		tx_vals[3] = 99; // slot 0, TX_DATA_OFFSET=3, account_nullifier[0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(result.is_err(), "expected prove to fail (data mismatch)");
	}

	#[test]
	fn test_is_real_false_mismatched_data_should_pass() {
		// is_real=0 for slot 0, TX data differs from tree data → conditional check
		// is not enforced → should pass.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0, data[0] = 99 ≠ tree's 0 → no constraint → passes.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[3] = 99; // slot 0, account_nullifier[0] = 99
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("is_real=false mismatch should pass");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
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
	fn test_soundness_is_real_true_mismatched_commitment_should_fail() {
		// is_real=1 for slot 0, but TX note_commitment[0][0] ≠ NC leaf[0][0] → fail.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NC leaf 0 word 0 = 7. NC_LEAF_OFFSET=8.
		let nc_n_pi = nc_t.len();
		let mut nc_vals = vec![0u64; nc_n_pi];
		nc_vals[8] = 7;
		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);

		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1 (PI[2]=1), note_commitment[0][0] (PI[43]) = 999.
		// TX_DATA_OFFSET=3; note_commitments start at data offset 40 → PI[3+40]=PI[43].
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		tx_vals[43] = 999; // note_commitment[0][0] (mismatch with NC leaf = 7)
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (mismatch soundness)"
		);
	}

	// -----------------------------------------------------------------------
	// Non-trivial (non-zero value) pass tests
	// -----------------------------------------------------------------------
	//
	// TX leaf PI layout per slot (tx_base = s × 75):
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
		// Slot 1 (tx_base = 75):
		tx_vals[75 + 2] = 1; // is_real
		tx_vals[75 + 3] = 302; // account_nullifier[0]
		tx_vals[75 + 7] = 402; // account_commitment[0]
		tx_vals[75 + 11] = 102; // note_nullifier[0][0]
		tx_vals[75 + 43] = 202; // note_commitment[0][0]

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("full-tx nonzero prove failed");

		assert_eq!(root.public_inputs.len(), 8);
		super_agg.circuit_data.verify(root).expect("verify failed");
	}

	#[test]
	fn test_partial_tx_nonzero_active_slot_and_nonzero_nc_padding() {
		// Partial TX: slot 0 is_real=1 with matching non-zero values; slot 1 is
		// padding (is_real=0) with non-zero NC leaf — TX data for slot 1 is
		// unconstrained (conditional cross-check skips is_real=0 slots).
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
		// Slot 1 (padding): non-zero NC leaf.
		nc_vals[LEAF_OFFSET + 8 * 4] = 999; // NC slot 1, note 0, word 0 = non-zero

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
		// Slot 1 (tx_base=75): is_real=0 → TX data unconstrained (no match required).
		// tx_vals[75 + 2] = 0; // is_real=false
		// TX slot 1 data left as zero even though NC leaf=999 → no constraint → ok.

		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let root = super_agg
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof)
			.expect("partial-tx nonzero prove failed");

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
	fn test_soundness_is_real_true_mismatched_nullifier_should_fail() {
		// is_real=1 for slot 0, but TX note_nullifier[0][0] ≠ NN leaf[0][0] → fail.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// NN leaf slot 0, note 0, word 0 = 55.
		let mut nn_vals = vec![0u64; nn_t.len()];
		nn_vals[8] = 55; // LEAF_OFFSET + 0
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1, note_nullifier[0][0] = 0 (should be 55).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		// tx_vals[11] = 0 ≠ 55 → mismatch
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (nullifier mismatch)"
		);
	}

	#[test]
	fn test_soundness_is_real_true_mismatched_account_should_fail() {
		// is_real=1 for slot 0, but TX account_nullifier[0] ≠ AN leaf[0] → fail.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// AN leaf slot 0, word 0 = 77.
		let mut an_vals = vec![0u64; an_t.len()];
		an_vals[8] = 77; // LEAF_OFFSET + 0*4 + 0
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);

		// TX slot 0: is_real=1, account_nullifier[0] = 0 (should be 77).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[2] = 1; // is_real=1
		// tx_vals[3] = 0 ≠ 77 → mismatch
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (account nullifier mismatch)"
		);
	}
}
