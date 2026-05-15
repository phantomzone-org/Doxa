//! Generate Aggregator artifacts for the [`PrivateTx`].
//!
//! Produces a native Plonky2 `GenericAggregator` (ARITY=2, DEPTH=7,
//! pass-through) that aggregates 128 inner PrivTx proofs and exposes
//! their 9856 raw public inputs (128×77) as the root proof's public inputs.
//!
//! The inner PrivTx circuit (from `tessera-client`) produces 75 public inputs:
//!   PI[0..2] = subpool_ids, PI[2] = is_real, PI[3..7] = AN, PI[7..11] = AC,
//!   PI[11..43] = NN, PI[43..75] = NC.
//!
//! No BN128/Groth16 wrapping is done here — the SuperAggregator wraps all 5
//! inner proofs together.
//!
//! Usage:
//!   TESSERA_DEBUG=1 cargo run --bin aggregator_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use tessera_client::TesseraGateSerializer;
use tessera_trees::proof_aggregation::{GenericAggregator, GenericAggregatorConfig};

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
// 75 explicit PIs + 2 plonky2 lookup-table metadata PIs.
const TX_LEAF_PI: usize = 77;

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

	// 2. Build GenericAggregator directly with the inner PrivTx circuit. TesseraGateSerializer
	//    handles the custom ECGFp5 gates (DoubleAdd4x, CompressionGate) used by the inner circuit.
	debug_log("Instantiate GenericAggregator");
	let config = GenericAggregatorConfig {
		arity: ARITY,
		depth: DEPTH,
	};

	let agg = GenericAggregator::new(
		config,
		inner_circuit.common.clone(),
		inner_circuit.verifier_only.clone(),
	)?;

	debug_log("Store GenericAggregator");
	agg.store_artifacts(&tmp_dir, &TesseraGateSerializer)?;

	// 3. Generate a dummy root proof by proving one node per level with duplicated sibling proofs.
	//    This requires only DEPTH proofs instead of arity^DEPTH - 1, giving an ~18× speedup for
	//    ARITY=2, DEPTH=7.
	println!("\nGenerating dummy root proof ({DEPTH} levels, 1 proof per level)...");
	let total_now = Instant::now();
	let mut current_proof = dummy_inner_proof;
	for level_idx in 0..DEPTH {
		let level = agg.get_circuit(level_idx)?;
		let inner_verifier = agg.inner_verifier_for_level(level_idx);
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&level.verifier_target, inner_verifier)?;
		for i in 0..ARITY {
			pw.set_proof_with_pis_target(&level.proof_targets[i], &current_proof)?;
		}
		let now = Instant::now();
		current_proof = level.circuit_data.prove(pw)?;
		println!("  level {level_idx}: {:?}", now.elapsed());
	}
	println!("  total: {:?}", total_now.elapsed());

	agg.verify_root(&current_proof)?;
	println!("  root proof verified ok");

	let root_proof_bytes = current_proof.to_bytes();
	fs::write(tmp_dir.join("dummy_root_proof.bin"), &root_proof_bytes)?;
	println!(
		"  wrote: dummy_root_proof.bin ({} bytes)",
		root_proof_bytes.len()
	);

	println!("aggregator artifacts generated successfully");

	Ok(())
}
