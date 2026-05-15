//! Generic recursive proof aggregator.
//!
//! Combines `arity^depth` independent leaf proofs (sharing the same circuit)
//! into a single root proof whose public inputs are the concatenation of all
//! leaf public inputs, passed through unchanged at every level.

use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{
			CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
			VerifierOnlyCircuitData,
		},
		config::{AlgebraicHasher, GenericConfig},
		proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
	},
};
use serde::{Deserialize, Serialize};

use crate::aggregator_service::generic_aggregator::MAX_AGGREGATION_LEAVES;

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

/// The root aggregation proof.
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
	/// The root aggregation proof.
	pub proof: ProofWithPublicInputs<F, C, D>,
}

// ---------------------------------------------------------------------------
// Internal per-level circuit state
// ---------------------------------------------------------------------------

pub struct LevelCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	pub circuit_data: CircuitData<F, C, D>,
	pub proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
	pub verifier_target: VerifierCircuitTarget,
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
/// ```text
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
	pub(crate) config: GenericAggregatorConfig,
	pub(crate) leaf_common: CommonCircuitData<F, D>,
	pub(crate) leaf_verifier: VerifierOnlyCircuitData<C, D>,
	pub(crate) levels: Vec<LevelCircuit<F, C, D>>,
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
		{
			let (builder, proof_targets, verifier_target) =
				setup_level_builder::<F, C, D>(&leaf_common, &leaf_verifier, config.arity);
			let circuit_data = builder.build::<C>();
			levels.push(LevelCircuit {
				circuit_data,
				proof_targets,
				verifier_target,
			});
		}

		// Levels 1..depth-1: each verifies the previous level's proofs.
		for i in 1..config.depth {
			let inner_common = levels[i - 1].circuit_data.common.clone();
			let inner_verifier = levels[i - 1].circuit_data.verifier_only.clone();
			let (builder, proof_targets, verifier_target) =
				setup_level_builder::<F, C, D>(&inner_common, &inner_verifier, config.arity);
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

	#[allow(dead_code)]
	pub fn get_circuit(&self, level: usize) -> Result<&LevelCircuit<F, C, D>> {
		self.levels
			.get(level)
			.ok_or_else(|| anyhow::anyhow!("level index > {}", self.levels.len()))
	}

	#[allow(dead_code)]
	/// Returns the aggregator configuration (arity, depth).
	pub fn config(&self) -> &GenericAggregatorConfig {
		&self.config
	}

	#[allow(dead_code)]
	/// Returns the [`LevelCircuit`] at `level`, or `Err` if `level >= depth`.
	pub fn level_circuit(&self, level: usize) -> Result<&LevelCircuit<F, C, D>> {
		self.levels
			.get(level)
			.ok_or_else(|| anyhow!("level {} out of range (depth={})", level, self.levels.len()))
	}

	#[allow(dead_code)]
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
		Ok(AggregatedProof { proof: root })
	}

	/// Aggregate a single leaf proof into a root proof by cloning it at every
	/// level of the tree (`[p, p, ..., p]` at each level).
	///
	/// Costs `depth` proof generations instead of `arity^depth`, making it
	/// suitable for generating dummy proofs during artifact setup.
	pub fn aggregate_dummy(
		&self,
		leaf: ProofWithPublicInputs<F, C, D>,
	) -> Result<AggregatedProof<F, C, D>> {
		let mut current = leaf;

		// Level 0: clone leaf `arity` times.
		{
			let level = &self.levels[0];
			let mut pw = PartialWitness::new();
			pw.set_verifier_data_target(&level.verifier_target, &self.leaf_verifier)?;
			for i in 0..self.config.arity {
				pw.set_proof_with_pis_target(&level.proof_targets[i], &current)?;
			}
			let now = Instant::now();
			current = level.circuit_data.prove(pw)?;
			println!("aggregate_dummy level: 0 -> {:?}", now.elapsed());
		}

		// Levels 1..depth: clone previous-level proof `arity` times.
		for level_idx in 1..self.config.depth {
			let level = &self.levels[level_idx];
			let inner_verifier = self.levels[level_idx - 1].circuit_data.verifier_only.clone();
			let mut pw = PartialWitness::new();
			pw.set_verifier_data_target(&level.verifier_target, &inner_verifier)?;
			for i in 0..self.config.arity {
				pw.set_proof_with_pis_target(&level.proof_targets[i], &current)?;
			}
			let now = Instant::now();
			current = level.circuit_data.prove(pw)?;
			println!("aggregate_dummy level: {} -> {:?}", level_idx, now.elapsed());
		}

		Ok(AggregatedProof { proof: current })
	}

	#[allow(dead_code)]
	/// Verify the root proof against the top-level aggregation circuit.
	pub fn verify_root(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
		self.levels
			.last()
			.expect("aggregator has at least one level")
			.circuit_data
			.verify(proof.clone())
			.map_err(|e| anyhow!("root proof verification failed: {e}"))
	}

	#[allow(dead_code)]
	/// Returns the leaf circuit's `CommonCircuitData`.
	///
	/// Required to deserialize leaf proof bytes via
	/// `ProofWithPublicInputs::from_bytes(bytes, leaf_common)`.
	pub fn leaf_common(&self) -> &CommonCircuitData<F, D> {
		&self.leaf_common
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
pub(crate) fn setup_level_builder<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	const D: usize,
>(
	inner_common: &CommonCircuitData<F, D>,
	inner_verifier: &VerifierOnlyCircuitData<C, D>,
	arity: usize,
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

	// Pass all child public inputs through unchanged at every level.
	for pt in &proof_targets {
		for &pi in &pt.public_inputs {
			builder.register_public_input(pi);
		}
	}

	(builder, proof_targets, verifier_target)
}
