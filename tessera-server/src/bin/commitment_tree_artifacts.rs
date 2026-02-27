//! Generate Groth16 artifacts for the CommitmentTree.
//!
//! Outputs (in artifacts/commitment-tree/):
//!   - plonky2-proof/    (plonky2 circuit data for R1CS)
//!   - groth-artifacts/  (Groth16 proving/verifying keys)
//!
//! Usage:
//!   cargo run --bin commitment_tree_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use tessera_server::sample_batch_commitment_tree_proof;
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	tree::{hasher::HashOutput, BatchCommitmentProof},
	CircuitDataNative, ProofBN128, ProofNative,
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

fn main() -> Result<()> {
	let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("artifacts")
		.join("commitment-tree");

	fs::create_dir_all(&tmp_dir)?;

	let input_path: PathBuf = tmp_dir.join("plonky2-proof");
	let output_path: PathBuf = tmp_dir.join("groth-artifacts");

	println!("commitment-tree artifacts: {}", tmp_dir.display());
	println!("plonky2 data: {}", input_path.display());
	println!("groth16 artifacts: {}", output_path.display());

	debug_log("Instantiate BN128Wrapper");
	let (circuit_data, proof_with_pis, _, _): (
		CircuitDataNative,
		ProofNative,
		BatchCommitmentProof<HashOutput>,
		Vec<HashOutput>,
	) = sample_batch_commitment_tree_proof([0u8; 32])?;
	let bn128_wrapper: BN128Wrapper = BN128Wrapper::new(circuit_data, proof_with_pis)?;

	if !BN128Wrapper::has_full_artifacts(&input_path) {
		println!("writing plonky2 circuit data");
		fs::create_dir_all(&input_path)?;
		bn128_wrapper.store_full_circuit_data(&input_path)?;
	}

	if !output_path.is_dir() {
		println!("generating groth16 trusted setup");
		let result = Groth16Wrapper::trusted_setup(&input_path, &output_path);
		debug_log(&format!("trusted_setup result: {result}"));
	}

	let result: String = Groth16Wrapper::init(&input_path, &output_path)?;
	debug_log(&format!("init result: {result}"));

	let result: String = Groth16Wrapper::check_init();
	debug_log(&format!("check_init result: {result}"));

	let (_, proof_with_pis, _, _): (
		CircuitDataNative,
		ProofNative,
		BatchCommitmentProof<HashOutput>,
		Vec<HashOutput>,
	) = sample_batch_commitment_tree_proof([1u8; 32])?;

	println!("wrapping proof to bn128");
	let start = Instant::now();
	let proof_with_public_inputs_bn128: ProofBN128 =
		bn128_wrapper.wrap_proof_to_bn128(proof_with_pis)?;
	debug_log(&format!("[TIME] bn128 wrapper took: {:?}", start.elapsed()));

	println!("generating groth16 proof");
	let start = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_with_public_inputs_bn128.clone())?;
	debug_log(&format!("[TIME] groth16_prove took: {:?}", start.elapsed()));
	debug_log(&format!("{:?} {:?}", g16_proof, g16_pub_inp));

	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = output_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("wrote proof: {}", json_path.display());
	debug_log(&format!(
		"\n(rust) Solidity proof JSON written to {:?}\n{}",
		json_path, solidity_json
	));

	Ok(())
}
