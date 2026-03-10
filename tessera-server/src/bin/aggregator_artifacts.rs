//! Generate Aggregator artifacts for the [`PrivateTx`].
//!
//! Produces a native Plonky2 `GenericAggregator` (ARITY=2, DEPTH=7,
//! [`ReducerKind::None`]) that aggregates 128 leaf proofs and exposes their
//! 9600 raw public inputs (128×75) as the root proof's public inputs.
//!
//! Each TX leaf is a **recursive verifier** that verifies one inner PrivTx proof
//! (from `tessera-client`) and forwards its 75 public inputs:
//!   PI[0..2] = subpool_ids, PI[2] = is_real, PI[3..7] = AN, PI[7..11] = AC, PI[11..43] = NN,
//! PI[43..75] = NC.
//!
//! No BN128/Groth16 wrapping is done here — the SuperAggregator wraps all 5
//! inner proofs together.
//!
//! Usage:
//!   TESSERA_DEBUG=1 cargo run --bin aggregator_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget},
		proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
	},
};
use tessera_trees::{
	proof_aggregation::{GenericAggregator, GenericAggregatorConfig, ReducerKind},
	ConfigNative, D, F,
};

fn debug_enabled() -> bool {
	std::env::var("TESSERA_DEBUG")
		.map(|v| v == "1")
		.unwrap_or(false)
}

fn debug_log(msg: &str) {
	if debug_enabled() {
		println!("{msg}");
	}
}

const ARITY: usize = 2;
const DEPTH: usize = 7;
const TX_LEAF_PI: usize = 75; // subpool_id_in(1) + subpool_id_out(1) + is_real(1) + AN(4) + AC(4) + NN(32) + NC(32)

fn main() -> Result<()> {
	let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("artifacts")
		.join("associated-input-aggregator");

	fs::create_dir_all(&tmp_dir)?;

	println!("aggregator artifacts: {}", tmp_dir.display());

	// 1. Build the inner PrivTx circuit and generate a dummy proof for padding.
	debug_log("Building inner PrivTx circuit + dummy proof");
	let (inner_circuit, dummy_inner_proof) = tessera_client::build_circuit_and_dummy_proof();
	println!(
		"  inner PrivTx circuit: {} PIs, degree_bits={}",
		inner_circuit.common.num_public_inputs,
		inner_circuit.common.degree_bits()
	);
	assert_eq!(
		inner_circuit.common.num_public_inputs, TX_LEAF_PI,
		"inner PrivTx circuit must have exactly {TX_LEAF_PI} public inputs"
	);

	// Save dummy inner proof (used at runtime for padding slots).
	let dummy_proof_bytes = dummy_inner_proof.to_bytes();
	fs::write(tmp_dir.join("dummy_inner_proof.bin"), &dummy_proof_bytes)?;
	println!(
		"  wrote: dummy_inner_proof.bin ({} bytes)",
		dummy_proof_bytes.len()
	);

	// 2. Build the recursive leaf circuit (verifies inner proof, forwards PIs).
	debug_log("Building recursive leaf circuit");
	let (leaf_circuit, inner_proof_target, inner_verifier_target) =
		build_recursive_leaf_circuit(&inner_circuit);
	println!(
		"  recursive leaf circuit: {} PIs, degree_bits={}",
		leaf_circuit.common.num_public_inputs,
		leaf_circuit.common.degree_bits()
	);
	assert_eq!(
		leaf_circuit.common.num_public_inputs, TX_LEAF_PI,
		"recursive leaf circuit must forward exactly {TX_LEAF_PI} public inputs"
	);

	// 3. Build GenericAggregator with the recursive leaf circuit.
	debug_log("Instantiate GenericAggregator");
	let config = GenericAggregatorConfig {
		arity: ARITY,
		depth: DEPTH,
		reducer: ReducerKind::None,
	};

	let agg = GenericAggregator::new(
		config,
		leaf_circuit.common.clone(),
		leaf_circuit.verifier_only.clone(),
	)?;

	debug_log("Store GenericAggregator");
	agg.store_artifacts(&tmp_dir)?;

	// 4. Validate the pipeline by proving one sibling pair per aggregation level. This exercises
	//    every level circuit without the cost of a full 128-leaf aggregation.
	debug_log("Validate aggregation pipeline (one pair per level)");

	let single_leaf = prove_recursive_leaf(
		&leaf_circuit,
		&inner_proof_target,
		&inner_verifier_target,
		&inner_circuit,
		&dummy_inner_proof,
	)?;
	println!("  proved 1 recursive leaf");

	let now = Instant::now();
	// Walk up the tree: prove one sibling pair per level.
	let mut current_proof = single_leaf;
	for level_idx in 0..DEPTH {
		let level = agg.level_circuit(level_idx)?;
		let inner_verifier = agg.inner_verifier_for_level(level_idx);
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&level.verifier_target, inner_verifier)?;
		for i in 0..ARITY {
			pw.set_proof_with_pis_target(&level.proof_targets[i], &current_proof)?;
		}
		current_proof = level.circuit_data.prove(pw)?;
		println!("  level {level_idx}: ok");
	}
	println!("Validation took: {:?}", now.elapsed());

	// Verify the root proof.
	agg.verify_root(&current_proof)?;

	println!("aggregator artifacts generated successfully");

	Ok(())
}

/// Build a recursive leaf circuit that verifies one inner PrivTx proof and
/// forwards its public inputs as this circuit's public inputs.
fn build_recursive_leaf_circuit(
	inner_circuit: &CircuitData<F, ConfigNative, D>,
) -> (
	CircuitData<F, ConfigNative, D>,
	ProofWithPublicInputsTarget<D>,
	VerifierCircuitTarget,
) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);

	// Virtual proof target for the inner PrivTx proof.
	let inner_proof_target = builder.add_virtual_proof_with_pis(&inner_circuit.common);

	// Bake inner circuit verifier data into the circuit as constants.
	let inner_verifier_target = builder.constant_verifier_data(&inner_circuit.verifier_only);

	// Verify the inner proof in-circuit.
	builder.verify_proof::<ConfigNative>(
		&inner_proof_target,
		&inner_verifier_target,
		&inner_circuit.common,
	);

	// Forward all inner PIs as this circuit's PIs (preserves the 75-PI layout).
	for &pi in &inner_proof_target.public_inputs {
		builder.register_public_input(pi);
	}

	let circuit = builder.build::<ConfigNative>();
	(circuit, inner_proof_target, inner_verifier_target)
}

/// Prove a single recursive leaf by wrapping an inner PrivTx proof.
fn prove_recursive_leaf(
	circuit: &CircuitData<F, ConfigNative, D>,
	inner_proof_target: &ProofWithPublicInputsTarget<D>,
	inner_verifier_target: &VerifierCircuitTarget,
	inner_circuit: &CircuitData<F, ConfigNative, D>,
	inner_proof: &ProofWithPublicInputs<F, ConfigNative, D>,
) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
	let mut pw = PartialWitness::new();
	pw.set_verifier_data_target(inner_verifier_target, &inner_circuit.verifier_only)?;
	pw.set_proof_with_pis_target(inner_proof_target, inner_proof)?;
	let proof = circuit.prove(pw)?;
	Ok(proof)
}
