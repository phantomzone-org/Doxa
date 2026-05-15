use std::time::Instant;

use anyhow::Result;
use num::pow;
use plonky2::{
	field::types::Field,
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData},
		proof::ProofWithPublicInputs,
	},
	util::serialization::DefaultGateSerializer,
};
use doxa_utils::{ConfigNative, D, F};

use super::*;

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
	let dir = std::env::temp_dir().join(format!("doxa_{tag}_{nanos}"));
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
	};
	assert!(cfg.validate().is_err(), "arity=1 should be rejected");
}

#[test]
fn test_invalid_config_arity_non_power_of_two() {
	let cfg = GenericAggregatorConfig {
		arity: 3,
		depth: 1,
	};
	assert!(cfg.validate().is_err(), "arity=3 should be rejected");
}

#[test]
fn test_invalid_config_depth_zero() {
	let cfg = GenericAggregatorConfig {
		arity: 2,
		depth: 0,
	};
	assert!(cfg.validate().is_err(), "depth=0 should be rejected");
}

#[test]
fn test_valid_config() {
	let cfg = GenericAggregatorConfig {
		arity: 2,
		depth: 2,
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
// Raw PI pass-through  (arity=2, depth=1)
// -----------------------------------------------------------------------

#[test]
fn test_aggregate_passthrough_arity2_depth1() -> Result<()> {
	const N_PI: usize = 4;

	let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
	let config = GenericAggregatorConfig {
		arity: 2,
		depth: 1,
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
		"root must expose all leaf field elements"
	);

	// Verify exact values: leaf0 then leaf1, in order.
	let expected: Vec<F> = leaf0_values
		.iter()
		.chain(leaf1_values.iter())
		.map(|&v| F::from_canonical_u64(v))
		.collect();
	assert_eq!(
		root.proof.public_inputs, expected,
		"root PIs must be raw concatenation of leaf PIs"
	);
	Ok(())
}

// -----------------------------------------------------------------------
// Raw PI pass-through — multi-level  (arity=2, depth=2)
// -----------------------------------------------------------------------

#[test]
fn test_aggregate_passthrough_arity2_depth2() -> Result<()> {
	const N_PI: usize = 3;

	let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
	let config = GenericAggregatorConfig {
		arity: 2,
		depth: 2,
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
// Large aggregation  (arity=4, depth=4)
// -----------------------------------------------------------------------

#[test]
fn test_aggregate_large_arity4_depth4() -> Result<()> {
	const N_PI: usize = 4;
	const ARITY: usize = 4;
	const DEPTH: usize = 4;
	let n_leaves: usize = pow(ARITY, DEPTH);

	let (leaf_circuit, targets) = build_leaf_circuit(N_PI);
	let config = GenericAggregatorConfig {
		arity: ARITY,
		depth: DEPTH,
	};
	let agg = GenericAggregator::new(
		config,
		leaf_circuit.common.clone(),
		leaf_circuit.verifier_only.clone(),
	)?;

	// 256 leaf proofs with distinct PI values.
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

	// Root PI count = arity^depth × leaf_pi_len = 256 × 4 = 1024.
	assert_eq!(
		root.proof.public_inputs.len(),
		n_leaves * N_PI,
		"root must expose all leaf field elements"
	);

	// Verify the raw pass-through: all leaf PIs in order.
	let expected: Vec<F> = leaf_values
		.iter()
		.flat_map(|vals| vals.iter().map(|&v| F::from_canonical_u64(v)))
		.collect();
	assert_eq!(root.proof.public_inputs, expected);
	Ok(())
}
