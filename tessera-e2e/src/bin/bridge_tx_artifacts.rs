use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use tessera_client::{
	TesseraGateSerializer, build_deposit_tx_circuit, build_withdraw_tx_circuit,
};
use tessera_server::aggregator_service::BridgeTxAggregator;
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
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

/// Resolve artifact output directory.
///
/// Priority:
///   1. `$TESSERA_ARTIFACTS_DIR` environment variable
///   2. `<workspace-root>/artifacts/`  (sibling of this crate's manifest dir)
fn artifacts_root() -> PathBuf {
	std::env::var("TESSERA_ARTIFACTS_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|_| {
			PathBuf::from(env!("CARGO_MANIFEST_DIR"))
				.parent()
				.expect("tessera-e2e has a workspace parent")
				.join("artifacts")
		})
}

fn main() -> Result<()> {
	let artifacts_root = artifacts_root();
	let agg_path = artifacts_root.join("bridge-tx");
	let plonky2_path = agg_path.join("plonky2-proof");
	let groth_path = agg_path.join("groth-artifacts");

	println!("=== Bridge TX Artifact Builder ===");
	println!("artifacts root  : {}", artifacts_root.display());
	println!("aggregator dir  : {}", agg_path.display());
	println!("plonky2 dir     : {}", plonky2_path.display());
	println!("groth dir       : {}", groth_path.display());

	// =======================================================================
	// 1. Build inner W/D circuits
	// =======================================================================
	println!("\n[1] Building inner Withdraw circuit...");
	let now = Instant::now();
	let w_circuit = build_withdraw_tx_circuit();
	println!(
		"  Withdraw circuit: {} PIs, degree_bits={} [{:?}]",
		w_circuit.circuit_data.common.num_public_inputs,
		w_circuit.circuit_data.common.degree_bits(),
		now.elapsed()
	);

	println!("  Building inner Deposit circuit...");
	let now = Instant::now();
	let d_circuit = build_deposit_tx_circuit();
	println!(
		"  Deposit circuit:  {} PIs, degree_bits={} [{:?}]",
		d_circuit.circuit_data.common.num_public_inputs,
		d_circuit.circuit_data.common.degree_bits(),
		now.elapsed()
	);

	// =======================================================================
	// 2. Build BridgeTxAggregator (or load from artifacts if already built)
	// =======================================================================
	let agg = if BridgeTxAggregator::has_full_artifacts(&agg_path).unwrap_or(false) {
		println!("\n[2] BridgeTxAggregator artifacts already exist — loading...");
		let now = Instant::now();
		let agg = BridgeTxAggregator::from_artifacts(
			&agg_path,
			&TesseraGateSerializer,
			&TesseraGateSerializer,
		)?;
		println!("  loaded [{:?}]", now.elapsed());
		agg
	} else {
		println!("\n[2] Building BridgeTxAggregator (pair-based, arity=4, depth=4)...");
		let now = Instant::now();
		let agg = BridgeTxAggregator::build(
			w_circuit.circuit_data.common.clone(),
			w_circuit.circuit_data.verifier_only.clone(),
			d_circuit.circuit_data.common.clone(),
			d_circuit.circuit_data.verifier_only.clone(),
		)?;
		println!("  built [{:?}]", now.elapsed());

		println!("  Storing BridgeTxAggregator artifacts → {}", agg_path.display());
		fs::create_dir_all(&agg_path)?;
		agg.store_artifacts(&agg_path, &TesseraGateSerializer, &TesseraGateSerializer)?;
		println!("  stored.");
		agg
	};

	// =======================================================================
	// 3. Generate dummy super proof
	// =======================================================================
	println!("\n[3] Generating dummy super proof...");
	let now = Instant::now();
	let dummy_proof = agg.prove_dummy()?;
	agg.super_circuit_data().verify(dummy_proof.clone())?;
	println!("  dummy super proof verified [{:?}]", now.elapsed());
	assert_eq!(
		dummy_proof.public_inputs.len(),
		8,
		"super proof must have exactly 8 public inputs"
	);
	println!(
		"  piCommitment words: {:?}",
		&dummy_proof.public_inputs[..8]
	);

	// =======================================================================
	// 4. BN128 wrap
	// =======================================================================
	debug_log("Instantiating BN128Wrapper...");
	let bn128_wrapper = BN128Wrapper::new(agg.super_circuit_data().clone(), dummy_proof.clone())?;

	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		println!("\n[4] Writing BN128 wrapper artifacts...");
		fs::create_dir_all(&plonky2_path)?;
		bn128_wrapper.store_full_circuit_data(&plonky2_path)?;
		println!("  stored → {}", plonky2_path.display());
	} else {
		println!("\n[4] BN128 artifacts already exist, skipping.");
	}

	// =======================================================================
	// 5. Groth16 trusted setup
	// =======================================================================
	if !groth_path.is_dir() {
		println!("[5] Generating Groth16 trusted setup...");
		let result = Groth16Wrapper::trusted_setup(&plonky2_path, &groth_path);
		debug_log(&format!("  trusted_setup result: {result}"));
		println!("  stored → {}", groth_path.display());
	} else {
		println!("[5] Groth16 artifacts already exist, skipping.");
	}

	let result: String = Groth16Wrapper::init(&plonky2_path, &groth_path)?;
	debug_log(&format!("init result: {result}"));
	let result: String = Groth16Wrapper::check_init();
	debug_log(&format!("check_init result: {result}"));

	// =======================================================================
	// 6. Groth16 round-trip test
	// =======================================================================
	println!("\n[6] Groth16 round-trip test...");
	let now = Instant::now();
	let proof_bn128 = bn128_wrapper.wrap_proof_to_bn128(dummy_proof)?;
	debug_log(&format!("  BN128 wrap: {:?}", now.elapsed()));

	let now = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_bn128)?;
	debug_log(&format!("  Groth16 prove: {:?}", now.elapsed()));

	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;
	println!("  Groth16 verify ok");

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = groth_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("  wrote proof: {}", json_path.display());

	println!("\n=== Bridge TX artifacts generated successfully ===");
	Ok(())
}
