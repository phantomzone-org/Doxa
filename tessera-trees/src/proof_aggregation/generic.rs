//! Generic recursive proof aggregator.
//!
//! Combines `arity^depth` independent leaf proofs (sharing the same circuit)
//! into a single root proof whose public inputs are the reducer-derived digest
//! of all leaf public inputs.
//!
//! # Aggregation strategy
//!
//! Intermediate levels (0 to depth-2) verify `arity` child proofs and pass
//! all child public inputs through unchanged (concatenated).  The reducer is
//! applied **only at the root level** (level `depth-1`), receiving the full
//! `arity^depth × leaf_pi_len` field-element preimage at once.
//!
//! This keeps every intermediate circuit free of expensive hash gadgets.
//!
//! # PI contract
//!
//! Only the root proof has a fixed-length PI:
//!
//! - **`Keccak256`**: 8 Goldilocks field elements (256-bit big-endian digest). Each of the
//!   `arity^depth × leaf_pi_len` leaf field elements is first decomposed into a `[hi_u32, lo_u32]`
//!   pair (matching `keccak256_field_elements_native`), and all resulting words are hashed in one
//!   Keccak-256 invocation.
//! - **`Poseidon`**: 4 Goldilocks field elements (one `HashOut`).  All leaf field elements are
//!   concatenated and hashed with `hash_n_to_hash_no_pad`.
//! - **`None`**: `arity^depth × leaf_pi_len` Goldilocks field elements — the raw concatenation of
//!   all leaf public inputs, identical to what intermediate levels expose.  No hash gadget is added
//!   to the root circuit, so the default generator serializer suffices.
//!
//! Intermediate-level proofs carry `arity^(level+1) × leaf_pi_len` field
//! elements as their public inputs.
//!
//! # Serializer requirement
//!
//! Only the root-level circuit uses the `Keccak256` reducer; intermediate
//! circuits contain no hash gadgets.  `CircuitData::to_bytes` / `from_bytes`
//! for the root circuit **must** use [`TesseraGeneratorSerializer`].

use std::{fs, path::Path, time::Instant};

use anyhow::{Result, anyhow, bail};
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{
			CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
			VerifierOnlyCircuitData,
		},
		config::{AlgebraicHasher, GenericConfig},
		proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
	},
	util::serialization::{DefaultGateSerializer, GateSerializer},
};
use serde::{Deserialize, Serialize};

use super::artifacts::{
	LEAF_COMMON_PATH, LEAF_VERIFIER_PATH, MANIFEST_PATH, MANIFEST_VERSION, level_circuit_path,
};
use crate::{
	groth::serializer::TesseraGeneratorSerializer,
	plonky2_gadgets::{
		keccak256::builder::BuilderKeccak256, sha256::circuit::decompose_field_to_u32_pair,
		u32::add_u8_range_check_lookup_table,
	},
};

// ---------------------------------------------------------------------------
// Public manifest version cap
// ---------------------------------------------------------------------------

/// Maximum total leaf count supported in v1 (`arity^depth <= MAX_AGGREGATION_LEAVES`).
pub const MAX_AGGREGATION_LEAVES: usize = 1024;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration for a [`GenericAggregator`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericAggregatorConfig {
	/// Fan-in at each level.  Must be a power of two and `>= 2`.
	pub arity: usize,
	/// Number of aggregation levels.  Must be `>= 1`.
	/// Total leaf count `= arity^depth`.
	pub depth: usize,
	/// How child public inputs are collapsed into a single parent digest.
	pub reducer: ReducerKind,
}

impl GenericAggregatorConfig {
	/// Returns an error for any invalid combination of fields.
	pub fn validate(&self) -> Result<()> {
		if self.arity < 2 {
			bail!("arity must be >= 2, got {}", self.arity);
		}
		if !self.arity.is_power_of_two() {
			bail!("arity must be a power of two, got {}", self.arity);
		}
		if self.depth < 1 {
			bail!("depth must be >= 1, got {}", self.depth);
		}
		let total_leaves = self
			.arity
			.checked_pow(self.depth as u32)
			.ok_or_else(|| anyhow!("arity^depth overflows usize"))?;
		if total_leaves > MAX_AGGREGATION_LEAVES {
			bail!(
				"arity^depth = {} exceeds MAX_AGGREGATION_LEAVES = {} (v1 cap)",
				total_leaves,
				MAX_AGGREGATION_LEAVES
			);
		}
		Ok(())
	}
}

/// Strategy for deriving a single parent digest from concatenated child PIs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReducerKind {
	/// Keccak-256 applied once at the root over all `arity^depth × leaf_pi_len`
	/// leaf field elements.
	///
	/// Output: 8 Goldilocks field elements (256-bit big-endian digest).
	/// Each leaf field element is decomposed into `[hi_u32, lo_u32]` before
	/// hashing, matching `keccak256_field_elements_native`.
	Keccak256,
	/// Poseidon applied once at the root over all `arity^depth × leaf_pi_len`
	/// leaf field elements (using `C::Hasher`).
	///
	/// Output: 4 Goldilocks field elements (one `HashOut`).
	Poseidon,
	/// No reduction: all leaf public inputs are concatenated and registered
	/// directly as the root circuit's public inputs (same behaviour as
	/// intermediate levels).
	///
	/// Root PI count = `arity^depth × leaf_pi_len`.
	///
	/// No hash gadget is added to the root circuit, so the default generator
	/// serializer suffices for all levels.
	None,
}

/// A root proof produced by [`GenericAggregator::aggregate`].
///
/// The PI shape depends on the reducer:
/// - `Keccak256` → 8 Goldilocks field elements, each a u32 word (big-endian).
/// - `Poseidon`  → 4 Goldilocks field elements (one `HashOut`).
/// - `None`      → `arity^depth × leaf_pi_len` Goldilocks field elements (raw pass-through).
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
	/// The root aggregation proof.
	pub proof: ProofWithPublicInputs<F, C, D>,
	/// The configuration that produced this proof.
	pub config: GenericAggregatorConfig,
}

// ---------------------------------------------------------------------------
// Internal per-level circuit state
// ---------------------------------------------------------------------------

pub struct LevelCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	pub circuit_data: CircuitData<F, C, D>,
	pub proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
	pub verifier_target: VerifierCircuitTarget,
}

// Internal manifest used for artifact persistence.
#[derive(Debug, Serialize, Deserialize)]
struct AggregatorManifest {
	version: u32,
	arity: usize,
	depth: usize,
	reducer: ReducerKind,
	leaf_pi_len: usize,
	levels: usize,
}

// ---------------------------------------------------------------------------
// GenericAggregator
// ---------------------------------------------------------------------------

/// Generic recursive proof aggregator.
///
/// Combines `arity^depth` independent leaf proofs (all sharing the same
/// `CommonCircuitData` and `VerifierOnlyCircuitData`) into a single root proof.
///
/// # Artifact lifecycle
///
/// ```ignore
/// // Fresh build (compiles all level circuits — may be slow).
/// let agg = GenericAggregator::new(config, leaf_common, leaf_verifier)?;
/// agg.store_artifacts(Path::new("artifacts/aggregator"), &gate_ser)?;
///
/// // Fast reload from disk (no recompilation).
/// let agg = GenericAggregator::<F, ConfigNative, D>::from_artifacts(
///     Path::new("artifacts/aggregator"), &gate_ser,
/// )?;
/// let root = agg.aggregate(leaf_proofs)?;
/// ```
pub struct GenericAggregator<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
> {
	config: GenericAggregatorConfig,
	leaf_common: CommonCircuitData<F, D>,
	leaf_verifier: VerifierOnlyCircuitData<C, D>,
	levels: Vec<LevelCircuit<F, C, D>>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
	GenericAggregator<F, C, D>
where
	C::Hasher: AlgebraicHasher<F>,
{
	/// Build all aggregation-level circuits from scratch.
	///
	/// Only the circuit schema (`leaf_common` + `leaf_verifier`) is required —
	/// no concrete proof values.
	pub fn new(
		config: GenericAggregatorConfig,
		leaf_common: CommonCircuitData<F, D>,
		leaf_verifier: VerifierOnlyCircuitData<C, D>,
	) -> Result<Self> {
		config.validate()?;

		let mut levels: Vec<LevelCircuit<F, C, D>> = Vec::with_capacity(config.depth);

		// Level 0: verifies leaf proofs.
		// The reducer is only applied at the root (last) level.
		{
			let is_root = config.depth == 1;
			let (builder, proof_targets, verifier_target) = setup_level_builder::<F, C, D>(
				&leaf_common,
				&leaf_verifier,
				config.arity,
				&config.reducer,
				is_root,
			);
			let circuit_data = builder.build::<C>();
			levels.push(LevelCircuit {
				circuit_data,
				proof_targets,
				verifier_target,
			});
		}

		// Levels 1..depth-1: each verifies the previous level's proofs.
		for i in 1..config.depth {
			let is_root = i == config.depth - 1;
			let inner_common = levels[i - 1].circuit_data.common.clone();
			let inner_verifier = levels[i - 1].circuit_data.verifier_only.clone();
			let (builder, proof_targets, verifier_target) = setup_level_builder::<F, C, D>(
				&inner_common,
				&inner_verifier,
				config.arity,
				&config.reducer,
				is_root,
			);
			let circuit_data = builder.build::<C>();
			levels.push(LevelCircuit {
				circuit_data,
				proof_targets,
				verifier_target,
			});
		}

		Ok(Self {
			config,
			leaf_common,
			leaf_verifier,
			levels,
		})
	}

	pub fn get_circuit(&self, level: usize) -> Result<&LevelCircuit<F, C, D>> {
		self.levels
			.get(level)
			.ok_or_else(|| anyhow::anyhow!("level index > {}", self.levels.len()))
	}

	/// Returns the aggregator configuration (arity, depth, reducer).
	pub fn config(&self) -> &GenericAggregatorConfig {
		&self.config
	}

	/// Returns the [`LevelCircuit`] at `level`, or `Err` if `level >= depth`.
	pub fn level_circuit(&self, level: usize) -> Result<&LevelCircuit<F, C, D>> {
		self.levels
			.get(level)
			.ok_or_else(|| anyhow!("level {} out of range (depth={})", level, self.levels.len()))
	}

	/// Returns the inner verifier used by level `level`.
	///
	/// - Level 0 → `&self.leaf_verifier` (verifies leaf proofs).
	/// - Level l > 0 → `&self.levels[l-1].circuit_data.verifier_only`.
	///
	/// # Panics
	///
	/// Panics if `level >= self.levels.len()`.  Call [`level_circuit`] first to
	/// range-check.
	pub fn inner_verifier_for_level(&self, level: usize) -> &VerifierOnlyCircuitData<C, D> {
		if level == 0 {
			&self.leaf_verifier
		} else {
			&self.levels[level - 1].circuit_data.verifier_only
		}
	}

	/// Aggregate exactly `config.arity^config.depth` leaf proofs into one root proof.
	pub fn aggregate(
		&self,
		proofs: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<AggregatedProof<F, C, D>> {
		let expected = self.config.arity.pow(self.config.depth as u32);
		if proofs.len() != expected {
			bail!(
				"expected {} proofs (arity {} ^ depth {}), got {}",
				expected,
				self.config.arity,
				self.config.depth,
				proofs.len()
			);
		}

		// Level 0: group leaf proofs into arity-sized batches and prove each.
		let mut current: Vec<ProofWithPublicInputs<F, C, D>> = {
			let level = &self.levels[0];
			proofs
				.chunks(self.config.arity)
				.map(|group| {
					let mut pw = PartialWitness::new();
					pw.set_verifier_data_target(&level.verifier_target, &self.leaf_verifier)?;
					for (i, proof) in group.iter().enumerate() {
						pw.set_proof_with_pis_target(&level.proof_targets[i], proof)?;
					}
					let now = Instant::now();
					let proof = level.circuit_data.prove(pw);
					println!("level: {} -> {:?}", 0, now.elapsed());
					proof
				})
				.collect::<Result<Vec<_>>>()?
		};

		// Levels 1..depth-1.
		for level_idx in 1..self.config.depth {
			let level = &self.levels[level_idx];
			let inner_verifier = self.levels[level_idx - 1]
				.circuit_data
				.verifier_only
				.clone();
			current = current
				.chunks(self.config.arity)
				.map(|group| {
					let mut pw = PartialWitness::new();
					pw.set_verifier_data_target(&level.verifier_target, &inner_verifier)?;
					for (i, proof) in group.iter().enumerate() {
						pw.set_proof_with_pis_target(&level.proof_targets[i], proof)?;
					}
					let now = Instant::now();
					let proof = level.circuit_data.prove(pw);
					println!("level: {} -> {:?}", level_idx, now.elapsed());
					proof
				})
				.collect::<Result<Vec<_>>>()?;
		}

		debug_assert_eq!(
			current.len(),
			1,
			"aggregation must produce exactly one root proof"
		);
		let root = current.into_iter().next().unwrap();
		Ok(AggregatedProof {
			proof: root,
			config: self.config.clone(),
		})
	}

	/// Verify the root proof against the top-level aggregation circuit.
	pub fn verify_root(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
		self.levels
			.last()
			.expect("aggregator has at least one level")
			.circuit_data
			.verify(proof.clone())
			.map_err(|e| anyhow!("root proof verification failed: {e}"))
	}

	/// Returns the leaf circuit's `CommonCircuitData`.
	///
	/// Required to deserialize leaf proof bytes via
	/// `ProofWithPublicInputs::from_bytes(bytes, leaf_common)`.
	pub fn leaf_common(&self) -> &CommonCircuitData<F, D> {
		&self.leaf_common
	}
}

// ---------------------------------------------------------------------------
// Artifact persistence — concrete types only
// ---------------------------------------------------------------------------
//
// `TesseraGeneratorSerializer` implements `WitnessGeneratorSerializer` only for
// `(GoldilocksField, 2)`, so these methods must live on a monomorphised impl
// block rather than the generic one above.

impl GenericAggregator<crate::F, crate::ConfigNative, 2> {
	/// Persist all circuit artifacts to `path`.
	///
	/// Creates the directory if it does not exist.  Overwrites any existing
	/// artifacts.  Delete `path` before calling if you need a clean rebuild.
	///
	/// `leaf_gate_ser` is the gate serializer used for `leaf_common.bin`.
	/// Pass `&DefaultGateSerializer` when the leaf circuit uses only standard
	/// plonky2 gates, or a custom serializer (e.g. `TesseraGateSerializer`)
	/// when the leaf circuit contains custom gates.
	pub fn store_artifacts(
		&self,
		path: &Path,
		leaf_gate_ser: &dyn GateSerializer<crate::F, 2>,
	) -> Result<()> {
		fs::create_dir_all(path)?;

		let manifest = AggregatorManifest {
			version: MANIFEST_VERSION,
			arity: self.config.arity,
			depth: self.config.depth,
			reducer: self.config.reducer.clone(),
			leaf_pi_len: self.leaf_common.num_public_inputs,
			levels: self.config.depth,
		};
		fs::write(
			path.join(MANIFEST_PATH),
			serde_json::to_string_pretty(&manifest)?,
		)?;

		let gate_ser = DefaultGateSerializer;

		let common_bytes = self
			.leaf_common
			.to_bytes(leaf_gate_ser)
			.map_err(|_| anyhow!("serialize leaf_common failed"))?;
		fs::write(path.join(LEAF_COMMON_PATH), common_bytes)?;

		let verifier_bytes = self
			.leaf_verifier
			.to_bytes()
			.map_err(|_| anyhow!("serialize leaf_verifier failed"))?;
		fs::write(path.join(LEAF_VERIFIER_PATH), verifier_bytes)?;
		for (i, level) in self.levels.iter().enumerate() {
			let bytes = level
				.circuit_data
				.to_bytes(&gate_ser, &TesseraGeneratorSerializer)
				.map_err(|_| {
					anyhow!(
						"serialize level {i} circuit failed (plonky2 IoError). \
                         If a new custom generator was added, register it in \
                         tessera-trees/src/groth/serializer.rs."
					)
				})?;
			fs::write(path.join(level_circuit_path(i)), bytes)?;
		}

		Ok(())
	}

	/// Reconstruct a [`GenericAggregator`] from pre-generated artifacts without
	/// recompiling any circuits.
	///
	/// Follows the required bottom-up loading order: level-N's circuit was built
	/// against level-(N-1)'s `CommonCircuitData`, so targets are rebuilt in the
	/// same order to obtain correct wire indices.
	///
	/// `leaf_gate_ser` is the gate serializer used for `leaf_common.bin`.
	/// Must match the serializer used in [`store_artifacts`].
	pub fn from_artifacts(
		path: &Path,
		leaf_gate_ser: &dyn GateSerializer<crate::F, 2>,
	) -> Result<Self> {
		let manifest_path = path.join(MANIFEST_PATH);
		let manifest: AggregatorManifest = serde_json::from_str(
			&fs::read_to_string(&manifest_path)
				.map_err(|e| anyhow!("failed to read '{}': {e}", manifest_path.display()))?,
		)?;

		if manifest.version != MANIFEST_VERSION {
			bail!(
				"manifest version mismatch in '{}': expected {}, got {}",
				path.display(),
				MANIFEST_VERSION,
				manifest.version
			);
		}

		let config = GenericAggregatorConfig {
			arity: manifest.arity,
			depth: manifest.depth,
			reducer: manifest.reducer,
		};
		config.validate()?;

		let gate_ser = DefaultGateSerializer;

		let leaf_common_path = path.join(LEAF_COMMON_PATH);
		let leaf_common_bytes = fs::read(&leaf_common_path)
			.map_err(|e| anyhow!("failed to read '{}': {e}", leaf_common_path.display()))?;
		let leaf_common: CommonCircuitData<crate::F, 2> =
			CommonCircuitData::from_bytes(&leaf_common_bytes, leaf_gate_ser).map_err(|_| {
				anyhow!(
					"deserialize leaf_common from '{}' failed",
					leaf_common_path.display()
				)
			})?;

		let leaf_verifier_path = path.join(LEAF_VERIFIER_PATH);
		let leaf_verifier_bytes = fs::read(&leaf_verifier_path)
			.map_err(|e| anyhow!("failed to read '{}': {e}", leaf_verifier_path.display()))?;
		let leaf_verifier: VerifierOnlyCircuitData<crate::ConfigNative, 2> =
			VerifierOnlyCircuitData::from_bytes(&leaf_verifier_bytes).map_err(|_| {
				anyhow!(
					"deserialize leaf_verifier from '{}' failed",
					leaf_verifier_path.display()
				)
			})?;

		// Bottom-up loading.  Level 0 uses leaf_common/leaf_verifier; each
		// subsequent level uses the previous level's circuit data.
		let mut inner_common = leaf_common.clone();
		let mut inner_verifier = leaf_verifier.clone();
		let mut levels: Vec<LevelCircuit<crate::F, crate::ConfigNative, 2>> =
			Vec::with_capacity(config.depth);

		for i in 0..config.depth {
			let is_root_level = i == config.depth - 1;

			// Replay the exact same deterministic builder operations used in `new`
			// to recover the target wire indices.  No `build()` or `prove()` call
			// is needed; the builder is discarded after extracting targets.
			let (_, proof_targets, verifier_target) =
				setup_level_builder::<crate::F, crate::ConfigNative, 2>(
					&inner_common,
					&inner_verifier,
					config.arity,
					&config.reducer,
					is_root_level,
				);

			let level_path = path.join(level_circuit_path(i));
			let bytes = fs::read(&level_path)
				.map_err(|e| anyhow!("failed to read '{}': {e}", level_path.display()))?;
			let circuit_data = CircuitData::<crate::F, crate::ConfigNative, 2>::from_bytes(
				&bytes,
				&gate_ser,
				&TesseraGeneratorSerializer,
			)
			.map_err(|_| {
				anyhow!(
					"deserialize level {i} circuit from '{}' failed (plonky2 IoError). \
                             Possible causes: (1) artifacts from a different plonky2 revision; \
                             (2) file truncated or corrupt; (3) a generator present at \
                             serialization time is missing from TesseraGeneratorSerializer. \
                             Delete the artifacts directory and regenerate.",
					level_path.display()
				)
			})?;

			// Advance inner circuit data for the next level.
			if i + 1 < config.depth {
				inner_common = circuit_data.common.clone();
				inner_verifier = circuit_data.verifier_only.clone();
			}

			levels.push(LevelCircuit {
				circuit_data,
				proof_targets,
				verifier_target,
			});
		}

		Ok(Self {
			config,
			leaf_common,
			leaf_verifier,
			levels,
		})
	}

	/// Returns `Ok(true)` if the full artifact set required by
	/// [`from_artifacts`] is present under `path`.
	pub fn has_full_artifacts(path: &Path) -> Result<bool> {
		if !path.join(MANIFEST_PATH).is_file()
			|| !path.join(LEAF_COMMON_PATH).is_file()
			|| !path.join(LEAF_VERIFIER_PATH).is_file()
		{
			return Ok(false);
		}

		// Parse the manifest to discover how many level files to expect.
		let manifest: AggregatorManifest = match fs::read_to_string(path.join(MANIFEST_PATH)) {
			Ok(s) => match serde_json::from_str(&s) {
				Ok(m) => m,
				Err(_) => return Ok(false),
			},
			Err(_) => return Ok(false),
		};

		for i in 0..manifest.levels {
			if !path.join(level_circuit_path(i)).is_file() {
				return Ok(false);
			}
		}

		Ok(true)
	}
}

// ---------------------------------------------------------------------------
// Internal builder helpers
// ---------------------------------------------------------------------------

/// Creates a [`CircuitBuilder`] populated with all wires and constraints for
/// one aggregation level, and returns it together with the allocated targets.
///
/// The caller finishes the circuit by either:
/// - calling `builder.build::<C>()` (in [`GenericAggregator::new`]), or
/// - discarding the builder (in [`GenericAggregator::from_artifacts`], which loads pre-built
///   circuit data from disk).
///
/// Both paths perform identical wire-allocation operations in the same order,
/// so the target indices are always deterministic.
fn setup_level_builder<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	const D: usize,
>(
	inner_common: &CommonCircuitData<F, D>,
	inner_verifier: &VerifierOnlyCircuitData<C, D>,
	arity: usize,
	reducer: &ReducerKind,
	is_root_level: bool,
) -> (
	CircuitBuilder<F, D>,
	Vec<ProofWithPublicInputsTarget<D>>,
	VerifierCircuitTarget,
)
where
	C::Hasher: AlgebraicHasher<F>,
{
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// One proof-with-PIs target per child.
	let proof_targets: Vec<ProofWithPublicInputsTarget<D>> = (0..arity)
		.map(|_| builder.add_virtual_proof_with_pis(inner_common))
		.collect();

	// All children verify against the same circuit, so constant-fold the
	// verifier data into the circuit constants.
	let verifier_target = builder.constant_verifier_data(inner_verifier);

	// Verify each child proof in-circuit.
	for pt in &proof_targets {
		builder.verify_proof::<C>(pt, &verifier_target, inner_common);
	}

	// At intermediate levels just pass child PIs through; at the root apply
	// the reducer over the full leaf preimage.
	apply_reducer::<F, C, D>(
		&mut builder,
		&proof_targets,
		reducer,
		is_root_level,
		inner_common.num_public_inputs,
	);

	(builder, proof_targets, verifier_target)
}

/// Registers public inputs for one aggregation level.
///
/// - **Intermediate levels** (`is_root_level = false`): concatenate all child PI targets and
///   register them directly — no hash, no constraint overhead.
/// - **Root level** (`is_root_level = true`): apply the reducer over the full preimage (all
///   `arity^depth × leaf_pi_len` leaf field elements that have been passed through from the
///   bottom).
fn apply_reducer<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	proof_targets: &[ProofWithPublicInputsTarget<D>],
	reducer: &ReducerKind,
	is_root_level: bool,
	child_pi_len: usize,
) where
	C::Hasher: AlgebraicHasher<F>,
{
	if !is_root_level {
		// Pass all child public inputs through unchanged.
		for pt in proof_targets {
			for &pi in &pt.public_inputs {
				builder.register_public_input(pi);
			}
		}
		return;
	}

	// Root level: apply the chosen reducer over all leaf field elements
	// that have propagated up through intermediate pass-through levels.
	match reducer {
		ReducerKind::Keccak256 => {
			// All inputs are original leaf Goldilocks field elements.
			// Decompose each into [hi_u32, lo_u32] (big-endian) to match
			// keccak256_field_elements_native's encoding.
			let byte_range_lut = add_u8_range_check_lookup_table(builder);
			let mut u32_targets = Vec::with_capacity(proof_targets.len() * child_pi_len * 2);
			for pt in proof_targets {
				for &pi in &pt.public_inputs {
					let [hi, lo] = decompose_field_to_u32_pair(builder, pi, byte_range_lut);
					u32_targets.push(hi.0);
					u32_targets.push(lo.0);
				}
			}
			let hash = builder.keccak256::<C>(&u32_targets);
			for &word in &hash {
				builder.register_public_input(word);
			}
		},
		ReducerKind::Poseidon => {
			// All inputs are original leaf field elements — hash them directly.
			let inputs: Vec<Target> = proof_targets
				.iter()
				.flat_map(|pt| pt.public_inputs.iter().copied())
				.collect();
			let hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(inputs);
			for &elem in &hash.elements {
				builder.register_public_input(elem);
			}
		},
		ReducerKind::None => {
			// No reduction: pass all child public inputs through unchanged,
			// identical to the intermediate-level pass-through.
			for pt in proof_targets {
				for &pi in &pt.public_inputs {
					builder.register_public_input(pi);
				}
			}
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use std::time::Instant;

	use anyhow::Result;
	use num::pow;
	use plonky2::{
		field::types::{Field, PrimeField64},
		hash::poseidon::PoseidonHash,
		iop::{
			target::Target,
			witness::{PartialWitness, WitnessWrite},
		},
		plonk::{
			circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
			config::Hasher as PlonkyHasher,
		},
	};

	use super::*;
	use crate::{
		ConfigNative, D, F, plonky2_gadgets::keccak256::utils::keccak256_field_elements_native,
	};

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/// Builds a minimal leaf circuit with `n_pi` virtual field-element public inputs.
	fn build_leaf_circuit(n_pi: usize) -> (CircuitData<F, ConfigNative, D>, Vec<Target>) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

	/// Proves the leaf circuit with specific `u64` witness values.
	fn prove_leaf(
		circuit: &CircuitData<F, ConfigNative, D>,
		targets: &[Target],
		values: &[u64],
	) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(values.iter()) {
			pw.set_target(t, F::from_canonical_u64(v))?;
		}
		circuit.prove(pw)
	}

	/// Creates a temporary directory under the system temp dir.
	fn make_temp_dir(tag: &str) -> std::path::PathBuf {
		let nanos = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.subsec_nanos();
		let dir = std::env::temp_dir().join(format!("tessera_{tag}_{nanos}"));
		std::fs::create_dir_all(&dir).expect("create temp dir");
		dir
	}

	// -----------------------------------------------------------------------
	// Public accessor tests (Step 1)
	// -----------------------------------------------------------------------

	#[test]
	fn test_config_accessor() -> Result<()> {
		let (leaf_circuit, _) = build_leaf_circuit(4);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 3,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			cfg.clone(),
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		assert_eq!(agg.config().arity, cfg.arity);
		assert_eq!(agg.config().depth, cfg.depth);
		Ok(())
	}

	#[test]
	fn test_level_circuit_valid() -> Result<()> {
		let (leaf_circuit, _) = build_leaf_circuit(4);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 3,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		assert!(agg.level_circuit(0).is_ok(), "level 0 must be valid");
		assert!(agg.level_circuit(2).is_ok(), "level depth-1 must be valid");
		Ok(())
	}

	#[test]
	fn test_level_circuit_oob() -> Result<()> {
		let (leaf_circuit, _) = build_leaf_circuit(4);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		assert!(
			agg.level_circuit(2).is_err(),
			"level == depth must be out of range"
		);
		Ok(())
	}

	#[test]
	fn test_inner_verifier_level0() -> Result<()> {
		let (leaf_circuit, _) = build_leaf_circuit(4);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		// Level 0 inner verifier must be the leaf verifier (same address).
		assert!(std::ptr::eq(
			agg.inner_verifier_for_level(0),
			&agg.leaf_verifier
		));
		Ok(())
	}

	#[test]
	fn test_inner_verifier_level1() -> Result<()> {
		let (leaf_circuit, _) = build_leaf_circuit(4);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		// Level 1 inner verifier must be level 0's verifier_only (same address).
		assert!(std::ptr::eq(
			agg.inner_verifier_for_level(1),
			&agg.levels[0].circuit_data.verifier_only
		));
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Config validation
	// -----------------------------------------------------------------------

	#[test]
	fn test_invalid_config_arity_one() {
		let cfg = GenericAggregatorConfig {
			arity: 1,
			depth: 1,
			reducer: ReducerKind::Keccak256,
		};
		assert!(cfg.validate().is_err(), "arity=1 should be rejected");
	}

	#[test]
	fn test_invalid_config_arity_non_power_of_two() {
		let cfg = GenericAggregatorConfig {
			arity: 3,
			depth: 1,
			reducer: ReducerKind::Keccak256,
		};
		assert!(cfg.validate().is_err(), "arity=3 should be rejected");
	}

	#[test]
	fn test_invalid_config_depth_zero() {
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 0,
			reducer: ReducerKind::Keccak256,
		};
		assert!(cfg.validate().is_err(), "depth=0 should be rejected");
	}

	#[test]
	fn test_valid_config() {
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::Keccak256,
		};
		assert!(cfg.validate().is_ok());
	}

	// -----------------------------------------------------------------------
	// Wrong proof count
	// -----------------------------------------------------------------------

	#[test]
	fn test_wrong_proof_count_rejected() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(4);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		// Provide only 1 proof when 2 are needed.
		let proof = prove_leaf(&leaf_circuit, &targets, &[1, 2, 3, 4])?;
		assert!(
			agg.aggregate(vec![proof]).is_err(),
			"wrong proof count must be rejected"
		);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Keccak256 circuit / native agreement  (arity=2, depth=1)
	// -----------------------------------------------------------------------

	#[test]
	fn test_keccak256_circuit_native_agreement() -> Result<()> {
		const N_PI: usize = 4;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		// Known leaf PI values.
		let leaf0_values: [u64; N_PI] = [1, 2, 3, 4];
		let leaf1_values: [u64; N_PI] = [5, 6, 7, 8];

		let proof0 = prove_leaf(&leaf_circuit, &targets, &leaf0_values)?;
		let proof1 = prove_leaf(&leaf_circuit, &targets, &leaf1_values)?;

		let root = agg.aggregate(vec![proof0, proof1])?;

		// Sanity: root proof must verify.
		agg.verify_root(&root.proof)?;

		// Expected digest: keccak256_field_elements_native over all child PI field
		// elements in order (left child then right child).
		let all_fields: Vec<F> = leaf0_values
			.iter()
			.chain(leaf1_values.iter())
			.map(|&v| F::from_canonical_u64(v))
			.collect();
		let expected = keccak256_field_elements_native(&all_fields);

		assert_eq!(
			root.proof.public_inputs.len(),
			8,
			"Keccak256 root must have exactly 8 public inputs"
		);
		for (i, &expected_word) in expected.iter().enumerate() {
			assert_eq!(
				root.proof.public_inputs[i],
				F::from_canonical_u64(expected_word as u64),
				"public input word {i} mismatch: circuit output 0x{:08X}, expected 0x{expected_word:08X}",
				root.proof.public_inputs[i].to_canonical_u64(),
			);
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Multi-level aggregation  (arity=2, depth=2)
	// -----------------------------------------------------------------------

	#[test]
	fn test_aggregate_keccak256_arity2_depth2() -> Result<()> {
		const N_PI: usize = 2;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		// 4 leaf proofs (arity^depth = 2^2 = 4).
		let proofs: Vec<_> = (0u64..4)
			.map(|i| prove_leaf(&leaf_circuit, &targets, &[i * 10, i * 10 + 1]))
			.collect::<Result<_>>()?;

		let root = agg.aggregate(proofs)?;

		agg.verify_root(&root.proof)?;
		assert_eq!(root.proof.public_inputs.len(), 8);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Artifact roundtrip  (arity=2, depth=1)
	// -----------------------------------------------------------------------

	#[test]
	fn test_artifact_roundtrip() -> Result<()> {
		let dir = make_temp_dir("aggr");

		const N_PI: usize = 3;
		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
			reducer: ReducerKind::Keccak256,
		};

		// Build a fresh aggregator and write artifacts.
		let agg_fresh = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		agg_fresh.store_artifacts(&dir, &DefaultGateSerializer)?;

		assert!(
			GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(&dir)?,
			"artifacts must be complete after store_artifacts"
		);

		// Reload from artifacts.
		let agg_loaded =
			GenericAggregator::<F, ConfigNative, D>::from_artifacts(&dir, &DefaultGateSerializer)?;

		// Both aggregators must produce identical public inputs for the same inputs.
		let proof0 = prove_leaf(&leaf_circuit, &targets, &[10, 20, 30])?;
		let proof1 = prove_leaf(&leaf_circuit, &targets, &[40, 50, 60])?;

		let root_fresh = agg_fresh.aggregate(vec![proof0.clone(), proof1.clone()])?;
		let root_loaded = agg_loaded.aggregate(vec![proof0, proof1])?;

		agg_fresh.verify_root(&root_fresh.proof)?;
		agg_loaded.verify_root(&root_loaded.proof)?;

		assert_eq!(
			root_fresh.proof.public_inputs, root_loaded.proof.public_inputs,
			"fresh and artifact-loaded aggregators must produce identical public inputs"
		);

		let _ = std::fs::remove_dir_all(&dir);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Arity=4, depth=2: 16 leaf proofs → 4 level-0 proofs → 1 root proof
	// with native cross-verification of the two-level Keccak256 preimage.
	// -----------------------------------------------------------------------

	#[test]
	fn test_aggregate_keccak256_arity4_depth2() -> Result<()> {
		const N_PI: usize = 4;
		const ARITY: usize = 4;
		const DEPTH: usize = 4;
		let n_leaves: usize = pow(ARITY, DEPTH);

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: ARITY,
			depth: DEPTH,
			reducer: ReducerKind::Keccak256,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		// 16 leaf proofs with distinct PI values.
		let leaf_values: Vec<[u64; N_PI]> = (0..n_leaves as u64)
			.map(|i| [i * 100, i * 100 + 1, i * 100 + 2, i * 100 + 3])
			.collect();
		let proofs: Vec<_> = leaf_values
			.iter()
			.map(|vals| prove_leaf(&leaf_circuit, &targets, vals))
			.collect::<Result<_>>()?;

		let now = Instant::now();
		let root = agg.aggregate(proofs)?;
		println!("proof took: {:?}", now.elapsed());
		agg.verify_root(&root.proof)?;

		assert_eq!(
			root.proof.public_inputs.len(),
			8,
			"Keccak256 root must have exactly 8 public inputs"
		);

		// --- Native cross-check ---
		//
		// The reducer is applied once at the root over ALL arity^depth × N_PI
		// leaf field elements concatenated — matches keccak256_field_elements_native.
		let all_fields: Vec<F> = leaf_values
			.iter()
			.flat_map(|vals| vals.iter().map(|&v| F::from_canonical_u64(v)))
			.collect();
		let expected = keccak256_field_elements_native(&all_fields);

		for (i, &expected_word) in expected.iter().enumerate() {
			assert_eq!(
				root.proof.public_inputs[i],
				F::from_canonical_u64(expected_word as u64),
				"public input word {i} mismatch: circuit 0x{:08X}, expected 0x{expected_word:08X}",
				root.proof.public_inputs[i].to_canonical_u64(),
			);
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// None reducer — raw PI pass-through  (arity=2, depth=1)
	// -----------------------------------------------------------------------

	#[test]
	fn test_none_reducer_passthrough() -> Result<()> {
		const N_PI: usize = 4;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
			reducer: ReducerKind::None,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		let leaf0_values: [u64; N_PI] = [1, 2, 3, 4];
		let leaf1_values: [u64; N_PI] = [5, 6, 7, 8];

		let proof0 = prove_leaf(&leaf_circuit, &targets, &leaf0_values)?;
		let proof1 = prove_leaf(&leaf_circuit, &targets, &leaf1_values)?;

		let root = agg.aggregate(vec![proof0, proof1])?;
		agg.verify_root(&root.proof)?;

		// Root PI count = arity^depth × leaf_pi_len = 2 × 4 = 8.
		assert_eq!(
			root.proof.public_inputs.len(),
			8,
			"None root must expose all leaf field elements"
		);

		// Verify exact values: leaf0 then leaf1, in order.
		let expected: Vec<F> = leaf0_values
			.iter()
			.chain(leaf1_values.iter())
			.map(|&v| F::from_canonical_u64(v))
			.collect();
		assert_eq!(
			root.proof.public_inputs, expected,
			"None root PIs must be raw concatenation of leaf PIs"
		);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// None reducer — multi-level  (arity=2, depth=2)
	// -----------------------------------------------------------------------

	#[test]
	fn test_none_reducer_arity2_depth2() -> Result<()> {
		const N_PI: usize = 3;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: 2,
			depth: 2,
			reducer: ReducerKind::None,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		// 4 leaf proofs.
		let leaf_values: Vec<[u64; N_PI]> = (0u64..4)
			.map(|i| [i * 10, i * 10 + 1, i * 10 + 2])
			.collect();
		let proofs: Vec<_> = leaf_values
			.iter()
			.map(|vals| prove_leaf(&leaf_circuit, &targets, vals))
			.collect::<Result<_>>()?;

		let root = agg.aggregate(proofs)?;
		agg.verify_root(&root.proof)?;

		// Root PI count = 2^2 × 3 = 12.
		assert_eq!(root.proof.public_inputs.len(), 12);

		let expected: Vec<F> = leaf_values
			.iter()
			.flat_map(|vals| vals.iter().map(|&v| F::from_canonical_u64(v)))
			.collect();
		assert_eq!(root.proof.public_inputs, expected);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Artifact roundtrip  (arity=4, depth=2)
	// -----------------------------------------------------------------------

	#[test]
	fn test_artifact_roundtrip_arity4_depth2() -> Result<()> {
		let dir = make_temp_dir("aggr_4x2");

		const N_PI: usize = 4;
		const ARITY: usize = 4;
		const DEPTH: usize = 2;
		const N_LEAVES: usize = ARITY * ARITY; // 16

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: ARITY,
			depth: DEPTH,
			reducer: ReducerKind::Keccak256,
		};

		// Build a fresh aggregator and write artifacts.
		let agg_fresh = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		agg_fresh.store_artifacts(&dir, &DefaultGateSerializer)?;

		assert!(
			GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(&dir)?,
			"artifacts must be complete after store_artifacts"
		);

		// Reload from artifacts — no circuit recompilation.
		let agg_loaded =
			GenericAggregator::<F, ConfigNative, D>::from_artifacts(&dir, &DefaultGateSerializer)?;

		// 16 leaf proofs.
		let proofs: Vec<_> = (0..N_LEAVES as u64)
			.map(|i| prove_leaf(&leaf_circuit, &targets, &[i, i + 1, i + 2, i + 3]))
			.collect::<Result<_>>()?;

		let root_fresh = agg_fresh.aggregate(proofs.clone())?;
		let root_loaded = agg_loaded.aggregate(proofs)?;

		agg_fresh.verify_root(&root_fresh.proof)?;
		agg_loaded.verify_root(&root_loaded.proof)?;

		assert_eq!(
			root_fresh.proof.public_inputs, root_loaded.proof.public_inputs,
			"fresh and artifact-loaded aggregators must produce identical public inputs"
		);

		let _ = std::fs::remove_dir_all(&dir);
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Poseidon reducer  (arity=4, depth=3)
	// -----------------------------------------------------------------------

	#[test]
	fn test_aggregate_poseidon_arity4_depth3() -> Result<()> {
		const N_PI: usize = 4;
		const ARITY: usize = 2;
		const DEPTH: usize = 7;
		let n_leaves: usize = pow(ARITY, DEPTH);

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let config = GenericAggregatorConfig {
			arity: ARITY,
			depth: DEPTH,
			reducer: ReducerKind::Poseidon,
		};
		let agg = GenericAggregator::new(
			config,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;

		let leaf_values: Vec<[u64; N_PI]> = (0..n_leaves as u64)
			.map(|i| [i * 100, i * 100 + 1, i * 100 + 2, i * 100 + 3])
			.collect();
		let proofs: Vec<_> = leaf_values
			.iter()
			.map(|vals| prove_leaf(&leaf_circuit, &targets, vals))
			.collect::<Result<_>>()?;

		let now = Instant::now();
		let root = agg.aggregate(proofs)?;
		println!("proof took: {:?}", now.elapsed());
		agg.verify_root(&root.proof)?;

		assert_eq!(
			root.proof.public_inputs.len(),
			4,
			"Poseidon root must have exactly 4 public inputs"
		);

		// --- Native cross-check ---
		//
		// The reducer is applied once at the root over ALL arity^depth × N_PI
		// leaf field elements concatenated.
		let all_fields: Vec<F> = leaf_values
			.iter()
			.flat_map(|vals| vals.iter().map(|&v| F::from_canonical_u64(v)))
			.collect();
		let expected = PoseidonHash::hash_no_pad(&all_fields);

		for (i, &expected_elem) in expected.elements.iter().enumerate() {
			assert_eq!(
				root.proof.public_inputs[i],
				expected_elem,
				"public input element {i} mismatch: circuit {:?}, expected {:?}",
				root.proof.public_inputs[i].to_canonical_u64(),
				expected_elem.to_canonical_u64(),
			);
		}
		Ok(())
	}
}
