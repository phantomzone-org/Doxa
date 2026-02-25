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
//! Keccak preimage: **1184 Goldilocks fields** (9472 bytes)
//!
//! Nullifier trees (NN, AN) have a non-obvious raw PI layout: `NullifierInsertProofTargets::new`
//! with `is_last=true` registers `new_root[4]` **before** its own `new_node_value[4]`, so for a
//! batch of N insertions the layout is:
//!   `[old_root[4], new_node_path[1], values[0..N-2][4 each], new_root[4], value[N-1][4]]`
//! Equivalently, `new_root` is at `PI[nn_len-8..nn_len-4]`, not at `PI[nn_len-4..]`.
//! The preimage reorders to `[old_root, new_root, all_values]` (skipping `new_node_path`)
//! to match the on-chain `registerTransactionBatchUpdate` Keccak formula exactly:
//!   `keccak(confirmedRoot || newRoot || fullBatch)` per tree.
//!
//! | Circuit | Raw PIs | Preimage contribution (fields) | Notes |
//! |---------|---------|-------------------------------|-------|
//! | NC tree | 520 | 520 | old_root[4] + new_root[4] + leaves[128×4] |
//! | NN tree | 521 | 520 | old_root[4] + new_root[4] + values[128×4] (new_node_path skipped) |
//! | AC tree |  72 |  72 | old_root[4] + new_root[4] + leaves[16×4] |
//! | AN tree |  73 |  72 | old_root[4] + new_root[4] + values[16×4] (new_node_path skipped) |
//! | TX (in-circuit, not in preimage) | 1168 | — | 16 × 73 |
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
	/// in the TX proof's own public inputs (`is_real` at `PI[s * 73]` for slot `s`).
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
	// n_tx_slots = TX root PI count / 73  (73 fields per TX leaf slot: is_real + 72 data)
	const TX_LEAF_PI_SIZE: usize = 73; // is_real(1) + data(72)
	let tx_total_pi = inner.tx_common.num_public_inputs;
	assert_eq!(
		tx_total_pi % TX_LEAF_PI_SIZE,
		0,
		"TX root PI count must be a multiple of TX_LEAF_PI_SIZE (73)"
	);
	let n_tx_slots = tx_total_pi / TX_LEAF_PI_SIZE;

	// note_batch_size = NC PI count / 4 - 2 (subtract 2 roots × 4 fields each)
	let note_batch_size = inner.nc_common.num_public_inputs / 4 - 2;
	let notes_per_slot = note_batch_size / n_tx_slots;
	assert_eq!(notes_per_slot, 8, "notes per TX slot must be 8");

	// account_batch_size = AC PI count / 4 - 2; must equal n_tx_slots
	let account_batch_size = inner.ac_common.num_public_inputs / 4 - 2;
	assert_eq!(
		account_batch_size, n_tx_slots,
		"account_batch_size must equal n_tx_slots"
	);

	// --- Verify all 5 inner proofs in-circuit ---
	builder.verify_proof::<ConfigNative>(&nc_proof, &nc_vd, &inner.nc_common);
	builder.verify_proof::<ConfigNative>(&nn_proof, &nn_vd, &inner.nn_common);
	builder.verify_proof::<ConfigNative>(&ac_proof, &ac_vd, &inner.ac_common);
	builder.verify_proof::<ConfigNative>(&an_proof, &an_vd, &inner.an_common);
	builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);

	// --- Cross-check: TX slot PIs must match the corresponding tree leaf PIs ---
	//
	// Commitment tree (NC/AC) PI layout:
	//   public_inputs[0..7]  = [old_root × 4, new_root × 4]
	//   public_inputs[8..]   = leaves (batch_size × 4 fields)
	// Nullifier tree (NN/AN) PI layout (from chained-insertion stark):
	//   public_inputs[0..4]              = old_root[4]
	//   public_inputs[4]                 = new_node_path (starting chain index)
	//   public_inputs[5..5+(N-1)*4]      = values[0..N-2]  (first N-1 insertions)
	//   public_inputs[5+(N-1)*4..nn_len-4] = new_root[4]   (from the last insertion)
	//   public_inputs[nn_len-4..nn_len]  = value[N-1][4]   (last insertion, after new_root)
	// TX leaf PI layout (73 fields per slot):
	//   [0]      = is_real (bool: 1 = real private tx, 0 = padding)
	//   [1..33]  = note_nullifiers[0..8]   (8 × 4 fields, from NN)
	//   [33..65] = note_commitments[0..8]  (8 × 4 fields, from NC)
	//   [65..69] = account_nullifier        (1 × 4 fields, from AN)
	//   [69..73] = account_commitment       (1 × 4 fields, from AC)
	//
	// is_real is read from the TX proof's own PIs (certified by the TX leaf circuit).
	// When is_real = 1: expected = tree_t → tx_data_t must equal the tree leaf.
	// When is_real = 0: expected = 0      → tx_data_t must be zero (canonical padding).
	// TX PIs are fully captured by the tree PIs; TX is excluded from the Keccak preimage.
	const NC_LEAF_OFFSET: usize = 8; // old_root[4] + new_root[4]
	const NN_LEAF_OFFSET: usize = 5; // old_root[4] + new_node_path[1]
	const TX_DATA_OFFSET: usize = 1; // PI[0] is is_real; data starts at PI[1]
	#[allow(clippy::needless_range_loop)]
	for s in 0..n_tx_slots {
		let tx_base = s * TX_LEAF_PI_SIZE;
		let zero = builder.zero();
		// Read is_real from TX root proof PI[tx_base]; wrap and assert boolean.
		let is_real = BoolTarget::new_unsafe(tx_proof.public_inputs[tx_base]);
		builder.assert_bool(is_real);
		// note nullifiers (TX data[0..32]) — from NN tree
		// values[0..N-2] at PI[5..nn_len-8]; value[N-1] at PI[nn_len-4] (after new_root).
		for j in 0..notes_per_slot {
			let leaf_idx = s * notes_per_slot + j;
			let nn_val_base = if leaf_idx < note_batch_size - 1 {
				NN_LEAF_OFFSET + leaf_idx * 4
			} else {
				nn_proof.public_inputs.len() - 4 // value[N-1] is after new_root
			};
			for k in 0..4 {
				let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + j * 4 + k];
				let nn_t = nn_proof.public_inputs[nn_val_base + k];
				let expected = builder.select(is_real, nn_t, zero);
				builder.connect(tx_t, expected);
			}
		}
		// note commitments (TX data[32..64]) — from NC tree
		for j in 0..notes_per_slot {
			for k in 0..4 {
				let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 32 + j * 4 + k];
				let nc_t =
					nc_proof.public_inputs[NC_LEAF_OFFSET + (s * notes_per_slot + j) * 4 + k];
				let expected = builder.select(is_real, nc_t, zero);
				builder.connect(tx_t, expected);
			}
		}
		// account nullifier (TX data[64..68]) — from AN tree
		// Same PI layout as NN: value[N-1] is at PI[an_len-4] (after new_root).
		let an_val_base = if s < account_batch_size - 1 {
			NN_LEAF_OFFSET + s * 4
		} else {
			an_proof.public_inputs.len() - 4 // value[N-1] is after new_root
		};
		for k in 0..4 {
			let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 64 + k];
			let an_t = an_proof.public_inputs[an_val_base + k];
			let expected = builder.select(is_real, an_t, zero);
			builder.connect(tx_t, expected);
		}
		// account commitment (TX data[68..72]) — from AC tree
		for k in 0..4 {
			let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 68 + k];
			let ac_t = ac_proof.public_inputs[NC_LEAF_OFFSET + s * 4 + k];
			let expected = builder.select(is_real, ac_t, zero);
			builder.connect(tx_t, expected);
		}
	}

	// --- Collect tree PI targets and decompose each to [hi_u32, lo_u32] ---
	//
	// TX PIs are enforced in-circuit above; only the 4 tree PI vectors are
	// included in the Keccak preimage (1184 fields total).
	// The decomposition matches `keccak256_field_elements_native`: each
	// Goldilocks field element is split big-endian into two u32 words so that
	// the on-chain Keccak input is identical to the in-circuit preimage.
	let byte_range_lut = add_u8_range_check_lookup_table(&mut builder);

	// Keccak preimage layout (must match on-chain registerTransactionBatchUpdate formula):
	//   per tree: old_root[4] || new_root[4] || full_batch[batch_size×4]
	//
	// Commitment trees (NC, AC): PIs already in this order — take sequentially.
	// Nullifier trees (NN, AN): raw PIs are [old_root[4], new_node_path[1], values[0..N-2][4],
	//   new_root[4], value[N-1][4]]. Reorder to [old_root, new_root, values[0..N-1]];
	//   skip new_node_path (PI[4]). new_root is at [nn_len-8..nn_len-4].
	let nn_len = nn_proof.public_inputs.len();
	let an_len = an_proof.public_inputs.len();
	let nn_new_root_start = nn_len - 8; // new_root: second-to-last group of 4
	let an_new_root_start = an_len - 8; // same for AN

	let all_pi: Vec<_> = nc_proof
		.public_inputs
		.iter()
		.copied()
		// NN: old_root || new_root || values[0..N-2] || value[N-1]  (skip new_node_path at PI[4])
		.chain(nn_proof.public_inputs[..4].iter().copied())
		.chain(nn_proof.public_inputs[nn_new_root_start..nn_new_root_start + 4].iter().copied())
		.chain(nn_proof.public_inputs[5..nn_new_root_start].iter().copied())
		.chain(nn_proof.public_inputs[nn_new_root_start + 4..].iter().copied())
		.chain(ac_proof.public_inputs.iter().copied())
		// AN: old_root || new_root || values[0..N-2] || value[N-1]  (skip new_node_path at PI[4])
		.chain(an_proof.public_inputs[..4].iter().copied())
		.chain(an_proof.public_inputs[an_new_root_start..an_new_root_start + 4].iter().copied())
		.chain(an_proof.public_inputs[5..an_new_root_start].iter().copied())
		.chain(an_proof.public_inputs[an_new_root_start + 4..].iter().copied())
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
		(CircuitDataNative, Vec<Target>), // tx (73 PIs per slot: is_real + 72 data)
	) {
		let note_batch_size = notes_per_slot * n_tx_slots;
		let account_batch_size = n_tx_slots;
		let nc = build_leaf((2 + note_batch_size) * 4);
		let nn = build_leaf((2 + note_batch_size) * 4);
		let ac = build_leaf((2 + account_batch_size) * 4);
		let an = build_leaf((2 + account_batch_size) * 4);
		let tx = build_leaf(n_tx_slots * 73);
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
		// Consume-only batch: NC leaves are non-zero, TX has is_real=0 and all data=0.
		// Circuit: is_real=0 → expected=0 → tx_data==0 ✓ (NC non-zero doesn't matter).
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
		// TX: is_real=0 for all slots (PI[s*73]=0), all data zero.
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

		// TX: is_real=1 for all slots (PI[s*73]=1), all data zero.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		for s in 0..N_TX_SLOTS {
			tx_vals[s * 73] = 1; // is_real=true for slot s
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

		// Slot 0: is_real=1 (PI[0]=1), slot 1: is_real=0 (PI[73]=0). Data all zero.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[0] = 1; // slot 0 is_real=1
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
	fn test_soundness_is_real_false_nonzero_tx_data_should_fail() {
		// is_real=0 for slot 0, but TX data[0] (note_nullifier word) is non-zero → fail.
		// Circuit: expected=0 but tx_t=99 → connect fails.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=0 (PI[0]=0), data[0] (PI[1]) = 99 — note_nullifier word.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[1] = 99; // slot 0, TX_DATA_OFFSET=1, note_nullifier[0][0]
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(result.is_err(), "expected prove to fail (soundness check)");
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

		// TX slot 0: is_real=1 (PI[0]=1), note_commitment[0][0] (PI[33]) = 999.
		// TX_DATA_OFFSET=1; note_commitments start at data offset 32 → PI[1+32]=PI[33].
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[0] = 1; // is_real=1
		tx_vals[33] = 999; // note_commitment[0][0] (mismatch with NC leaf = 7)
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
	// TX leaf PI layout per slot (tx_base = s × 73):
	//   PI[tx_base + 0]        = is_real
	//   PI[tx_base + 1 + j*4 + k]      = note_nullifier[j][k]   (NN)
	//   PI[tx_base + 1 + 32 + j*4 + k] = note_commitment[j][k]  (NC)
	//   PI[tx_base + 1 + 64 + k]       = account_nullifier[k]   (AN)
	//   PI[tx_base + 1 + 68 + k]       = account_commitment[k]  (AC)
	//
	// Tree offsets (N_TX_SLOTS=2, NOTES_PER_SLOT=8, note_batch_size=16, account_batch_size=2):
	//   NN (test): build_leaf(72) → values[0..14] at PI[5 + leaf_idx*4]; value[15] at PI[nn_len-4]=PI[68]
	//   NC: leaves at PI[8 + leaf_idx*4]  (simple sequential layout)
	//   AN (test): build_leaf(16) → value[0] at PI[5]; value[1] (last, s=1=N-1) at PI[an_len-4]=PI[12]
	//   AC: leaves at PI[8 + s*4]  (simple sequential layout)

	#[test]
	fn test_full_tx_nonzero_values_match() {
		// Full TX batch (both slots real) with non-trivial matching values across
		// all four fields (note_nullifier, note_commitment, account_nullifier,
		// account_commitment).  Verifies that is_real=1 enforcement actually
		// propagates non-zero tree values into TX constraints.
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		// Slot 0 tree values (word 0 of each field only; rest stay zero).
		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		// Slot 0, note 0, word 0:
		nn_vals[5] = 101; // NN: NN_LEAF_OFFSET + (0*8+0)*4 + 0
		nc_vals[8] = 201; // NC: NC_LEAF_OFFSET + (0*8+0)*4 + 0
		// Slot 0, account, word 0:
		an_vals[5] = 301; // AN: NN_LEAF_OFFSET + 0*4 + 0
		ac_vals[8] = 401; // AC: NC_LEAF_OFFSET + 0*4 + 0
		// Slot 1, note 0, word 0:
		nn_vals[5 + 8 * 4] = 102; // NN: 5 + (1*8+0)*4 = 37
		nc_vals[8 + 8 * 4] = 202; // NC: 8 + (1*8+0)*4 = 40
		// Slot 1, account, word 0 (last account, s=1=N-1 → value at an_len-4):
		// Test AN has build_leaf(16) → an_len=16, an_len-4=12.
		an_vals[12] = 302; // AN slot 1 (last): value[N-1] at an_len-4 = 16-4 = 12
		ac_vals[8 + 1 * 4] = 402; // AC: 8 + 1*4 = 12

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		// TX: both slots real with data matching the tree leaves above.
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Slot 0 (tx_base = 0):
		tx_vals[0] = 1; // is_real
		tx_vals[1] = 101; // note_nullifier[0][0]
		tx_vals[1 + 32] = 201; // note_commitment[0][0]
		tx_vals[1 + 64] = 301; // account_nullifier[0]
		tx_vals[1 + 68] = 401; // account_commitment[0]
		// Slot 1 (tx_base = 73):
		tx_vals[73] = 1; // is_real
		tx_vals[73 + 1] = 102; // note_nullifier[0][0]
		tx_vals[73 + 1 + 32] = 202; // note_commitment[0][0]
		tx_vals[73 + 1 + 64] = 302; // account_nullifier[0]
		tx_vals[73 + 1 + 68] = 402; // account_commitment[0]

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
		// padding (is_real=0) but its NC leaf is non-zero (demonstrating that
		// padding slots correctly ignore tree leaf values).
		let ((nc_cd, nc_t), (nn_cd, nn_t), (ac_cd, ac_t), (an_cd, an_t), (tx_cd, tx_t)) =
			build_all_leaves(N_TX_SLOTS, NOTES_PER_SLOT);

		let mut nn_vals = vec![0u64; nn_t.len()];
		let mut nc_vals = vec![0u64; nc_t.len()];
		let mut an_vals = vec![0u64; an_t.len()];
		let mut ac_vals = vec![0u64; ac_t.len()];
		// Slot 0 (active): matching values in all four fields.
		nn_vals[5] = 101;
		nc_vals[8] = 201;
		an_vals[5] = 301;
		ac_vals[8] = 401;
		// Slot 1 (padding): non-zero NC leaf — TX will still be all-zero because
		// is_real=0 forces expected=0 regardless of the tree value.
		nc_vals[8 + 8 * 4] = 999; // NC slot 1, note 0, word 0 = non-zero

		let nc_proof = prove_with_values(&nc_cd, &nc_t, &nc_vals);
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);
		let ac_proof = prove_with_values(&ac_cd, &ac_t, &ac_vals);
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		// Slot 0 (tx_base=0): is_real=1, data matches tree.
		tx_vals[0] = 1;
		tx_vals[1] = 101;
		tx_vals[1 + 32] = 201;
		tx_vals[1 + 64] = 301;
		tx_vals[1 + 68] = 401;
		// Slot 1 (tx_base=73): is_real=0, all TX data zero (NC leaf=999 is ignored).
		// tx_vals[73] = 0; already zero

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
		tx_vals[0] = 2; // is_real=2: not boolean
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
		nn_vals[5] = 55; // NN_LEAF_OFFSET + 0
		let nn_proof = prove_with_values(&nn_cd, &nn_t, &nn_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);
		let an_proof = prove_zeros(&an_cd, &an_t);

		// TX slot 0: is_real=1, note_nullifier[0][0] = 0 (should be 55).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[0] = 1; // is_real=1
		// tx_vals[1] = 0 ≠ 55 → mismatch
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
		an_vals[5] = 77; // NN_LEAF_OFFSET + 0*4 + 0
		let an_proof = prove_with_values(&an_cd, &an_t, &an_vals);

		let nc_proof = prove_zeros(&nc_cd, &nc_t);
		let nn_proof = prove_zeros(&nn_cd, &nn_t);
		let ac_proof = prove_zeros(&ac_cd, &ac_t);

		// TX slot 0: is_real=1, account_nullifier[0] = 0 (should be 77).
		let tx_n_pi = tx_t.len();
		let mut tx_vals = vec![0u64; tx_n_pi];
		tx_vals[0] = 1; // is_real=1
		// tx_vals[65] = 0 ≠ 77 → mismatch
		let tx_proof = prove_with_values(&tx_cd, &tx_t, &tx_vals);

		let super_agg = make_super_agg(&nc_cd, &nn_cd, &ac_cd, &an_cd, &tx_cd);
		let result = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_proof);
		assert!(
			result.is_err(),
			"expected prove to fail (account nullifier mismatch)"
		);
	}
}
