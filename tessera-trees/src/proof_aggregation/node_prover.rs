//! Synchronous node-proving abstraction for the streaming aggregation pipeline.
//!
//! [`NodeProver`] is a blocking trait, intended to be called from
//! `tokio::task::spawn_blocking` in `tessera-server`.  No async runtime is
//! required here; `tessera-trees` stays sync/CPU-only.

use std::sync::Arc;

use anyhow::Result;
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_data::VerifierOnlyCircuitData,
		config::{AlgebraicHasher, GenericConfig},
		proof::ProofWithPublicInputs,
	},
};

use super::GenericAggregator;

// ---------------------------------------------------------------------------
// NodeProver trait
// ---------------------------------------------------------------------------

/// Synchronous (blocking) trait for proving one internal aggregation node.
///
/// Implementors receive `arity` child proofs and return the parent proof.
/// This trait is `Send + Sync` so it can be wrapped in an `Arc` and shared
/// across threads.
pub trait NodeProver<F, C, const D: usize>: Send + Sync
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	/// Prove an internal tree node at `level` whose children are `children`.
	///
	/// - `level` selects which `LevelCircuit` to use (0 = bottom level, `depth-1` = root level).
	/// - `node_idx` is used only for logging / tracing.
	/// - `children` must have exactly `arity` elements; passing a different count will cause a
	///   plonky2 target-count error.
	fn prove_node_blocking(
		&self,
		level: usize,
		node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>>;
}

// ---------------------------------------------------------------------------
// LocalNodeProver
// ---------------------------------------------------------------------------

/// Proves aggregation nodes locally using a shared [`GenericAggregator`].
///
/// The aggregator is wrapped in an `Arc` so many `LocalNodeProver` instances
/// (or threads) can share the same pre-built circuit data without cloning it.
pub struct LocalNodeProver<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
	aggregator: Arc<GenericAggregator<F, C, D>>,
}

impl<F, C, const D: usize> LocalNodeProver<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	C::Hasher: AlgebraicHasher<F>,
{
	/// Create a new `LocalNodeProver` backed by the given aggregator.
	pub fn new(aggregator: Arc<GenericAggregator<F, C, D>>) -> Self {
		Self {
			aggregator,
		}
	}
}

impl<F, C, const D: usize> NodeProver<F, C, D> for LocalNodeProver<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	C::Hasher: AlgebraicHasher<F>,
{
	fn prove_node_blocking(
		&self,
		level: usize,
		_node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>> {
		let level_circuit = self.aggregator.level_circuit(level)?;
		let inner_verifier: &VerifierOnlyCircuitData<C, D> =
			self.aggregator.inner_verifier_for_level(level);

		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&level_circuit.verifier_target, inner_verifier)?;
		for (i, child) in children.iter().enumerate() {
			pw.set_proof_with_pis_target(&level_circuit.proof_targets[i], child)?;
		}
		level_circuit.circuit_data.prove(pw)
	}
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
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::{CircuitConfig, CircuitData},
		},
	};

	use super::*;
	use crate::{ConfigNative, D, F, proof_aggregation::GenericAggregatorConfig};

	fn build_leaf_circuit(n_pi: usize) -> (CircuitData<F, ConfigNative, D>, Vec<Target>) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

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

	/// Build a `LocalNodeProver` and prove one level-0 node for arity=2.
	#[test]
	fn test_local_prover_level0_arity2() -> Result<()> {
		const N_PI: usize = 4;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
		};
		let agg = Arc::new(GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?);

		let proof0 = prove_leaf(&leaf_circuit, &targets, &[1, 2, 3, 4])?;
		let proof1 = prove_leaf(&leaf_circuit, &targets, &[5, 6, 7, 8])?;

		let prover = LocalNodeProver::new(agg.clone());
		let node_proof = prover.prove_node_blocking(0, 0, vec![proof0, proof1])?;

		// The result must verify against level 0's circuit data.
		agg.level_circuit(0)?.circuit_data.verify(node_proof)?;
		Ok(())
	}

	/// Passing the wrong number of children must produce an error (plonky2
	/// target-count mismatch).
	#[test]
	fn test_local_prover_wrong_child_count() -> Result<()> {
		const N_PI: usize = 4;

		let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
		let cfg = GenericAggregatorConfig {
			arity: 2,
			depth: 1,
		};
		let agg = Arc::new(GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?);

		// Only 1 child for arity=2 — must fail.
		let proof0 = prove_leaf(&leaf_circuit, &targets, &[1, 2, 3, 4])?;
		let prover = LocalNodeProver::new(agg);
		let result = prover.prove_node_blocking(0, 0, vec![proof0]);
		assert!(result.is_err(), "wrong child count must produce Err");
		Ok(())
	}
}
