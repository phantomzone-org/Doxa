//! Generate Aggregator artifacts for the [`PrivateTx`].
//!
//! Produces a native Plonky2 `GenericAggregator` (ARITY=2, DEPTH=7,
//! [`ReducerKind::None`]) that aggregates 128 inner PrivTx proofs and exposes
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
use tessera_client::TesseraGateSerializer;
use tessera_trees::proof_aggregation::{GenericAggregator, GenericAggregatorConfig, ReducerKind};

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
		reducer: ReducerKind::None,
	};

	let agg = GenericAggregator::new(
		config,
		inner_circuit.common.clone(),
		inner_circuit.verifier_only.clone(),
	)?;

	debug_log("Store GenericAggregator");
	agg.store_artifacts(&tmp_dir, &TesseraGateSerializer)?;

	// 3. Full aggregation of 128 dummy leaves and serialize the root proof. This proof is reused by
	//    super_aggregator_artifacts (avoids re-proving).
	let n_leaves = ARITY.pow(DEPTH as u32);
	println!("\nAggregating {n_leaves} dummy leaves...");
	let now = Instant::now();
	let leaf_proofs = vec![dummy_inner_proof; n_leaves];
	let result = agg.aggregate(leaf_proofs)?;
	println!("  aggregation took: {:?}", now.elapsed());

	agg.verify_root(&result.proof)?;
	println!("  root proof verified ok");

	let root_proof_bytes = result.proof.to_bytes();
	fs::write(tmp_dir.join("dummy_root_proof.bin"), &root_proof_bytes)?;
	println!(
		"  wrote: dummy_root_proof.bin ({} bytes)",
		root_proof_bytes.len()
	);

	println!("aggregator artifacts generated successfully");

	Ok(())
}
